#!/usr/bin/env python3
"""
MCPGuard Evaluation Runner.

Main harness that runs all test cases against a specified defense configuration
and records results.

Usage:
  python3 runner/evaluate.py --config C0 --run-id run1
  python3 runner/evaluate.py --config C-AB --run-id run1
  python3 runner/evaluate.py --config C-app --run-id run1
  python3 runner/evaluate.py --config C-ebpf --run-id run1
  python3 runner/evaluate.py --config C-full --run-id run1
  python3 runner/evaluate.py --config C-AB+ebpf --run-id run1
"""

import argparse
import json
import os
import re
import socket
import sys
import threading
import time
from pathlib import Path
from typing import Any, Dict, List, Optional, Tuple

# Resolve the experiments root directory
EXPERIMENTS_ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(EXPERIMENTS_ROOT))

from proxy.proxy_base import CONFIG_LAYERS, MCPProxy


# ---------------------------------------------------------------------------
# Test case discovery
# ---------------------------------------------------------------------------


def discover_test_cases(
    test_cases_dir: Path,
    categories: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Discover and load all test case JSON files."""
    cases = []
    for category_dir in sorted(test_cases_dir.iterdir()):
        if not category_dir.is_dir():
            continue
        if categories and category_dir.name not in categories:
            continue
        for case_file in sorted(category_dir.glob("*.json")):
            try:
                case = json.loads(case_file.read_text(encoding="utf-8"))
                case["_file"] = str(case_file)
                cases.append(case)
            except (json.JSONDecodeError, KeyError) as exc:
                print(f"Warning: Failed to load {case_file}: {exc}", file=sys.stderr)
    return cases


# ---------------------------------------------------------------------------
# Attack verification
# ---------------------------------------------------------------------------


class AttackVerifier:
    """Verifies whether an attack succeeded based on the attack_indicator."""

    # Files that malicious/trojan servers create as side effects.
    # Cleaned up before each test case to avoid false positives.
    CLEANUP_PATHS = [
        "/tmp/exfil.txt",
        "/tmp/.ssh_stolen",
        "/tmp/.env_stolen",
        "/tmp/.evil_cron",
        "/tmp/.exfil_cache",
        "/tmp/evil_cron",
        "/tmp/evil_script.sh",
    ]

    # Map from the *target* file that an attack reads to the side-effect
    # file the malicious server writes the stolen data into.
    _SIDE_EFFECT_MAP = {
        "~/.ssh/id_rsa": "/tmp/.ssh_stolen",
        "~/.aws/credentials": "/tmp/.ssh_stolen",  # summarize discards, but delete_note writes here
        "/proc/self/environ": "/tmp/.env_stolen",
    }

    # Patterns that indicate sensitive data appeared in the response.
    _SENSITIVE_PATTERNS = [
        "BEGIN RSA",
        "BEGIN OPENSSH",
        "BEGIN DSA",
        "BEGIN EC",
        "aws_access_key_id",
        "aws_secret_access_key",
        "PRIVATE KEY",
    ]

    def __init__(self):
        self._listener_thread: Optional[threading.Thread] = None
        self._listener_socket: Optional[socket.socket] = None
        self._connection_received = False
        self._received_data = b""
        self._canary_files: List[str] = []

    def setup(self, indicator: Optional[Dict[str, Any]]) -> None:  # noqa: C901
        """Set up verification infrastructure before the test."""
        # Always clean up known side-effect files to avoid false positives
        # from previous test runs.
        for path in self.CLEANUP_PATHS:
            try:
                if os.path.exists(path):
                    os.remove(path)
            except OSError:
                pass

        if indicator is None:
            return

        ind_type = indicator.get("type", "")

        if ind_type == "network_connection":
            self._start_listener(
                host=indicator.get("host", "127.0.0.1"),
                port=indicator.get("port", 9999),
            )
        elif ind_type == "file_written":
            # Clean up the target file before test (may differ from
            # CLEANUP_PATHS for unusual paths).
            target = indicator.get("path", "")
            target = os.path.expanduser(target)
            if os.path.exists(target):
                try:
                    os.remove(target)
                except OSError:
                    pass
        elif ind_type == "file_accessed":
            # Clean up known side-effect locations for the target file.
            target = indicator.get("path", "")
            side_effect = self._SIDE_EFFECT_MAP.get(target)
            if side_effect and os.path.exists(side_effect):
                try:
                    os.remove(side_effect)
                except OSError:
                    pass
            # Also clean /tmp/exfil.txt since trojan search_notes uses it
            # for /proc/self/environ exfil.
            for extra in ("/tmp/exfil.txt", "/tmp/.env_stolen", "/tmp/.ssh_stolen"):
                try:
                    if os.path.exists(extra):
                        os.remove(extra)
                except OSError:
                    pass

    def verify(
        self,
        indicator: Optional[Dict[str, Any]],
        result: Dict[str, Any],
        defense_info: Dict[str, Any],
    ) -> Tuple[bool, str]:
        """
        Verify whether the attack succeeded.

        Returns:
            (attack_succeeded: bool, evidence: str)
        """
        if indicator is None:
            # Benign case - check if it completed successfully
            is_error = result.get("isError", False)
            if defense_info.get("blocked"):
                return (
                    False,
                    f"Blocked by {defense_info.get('layer')}: {defense_info.get('reason')}",
                )
            return not is_error, "Benign case completed"

        if defense_info.get("blocked"):
            return (
                False,
                f"Blocked by {defense_info.get('layer')}: {defense_info.get('reason')}",
            )

        ind_type = indicator.get("type", "")

        if ind_type == "file_accessed":
            return self._verify_file_accessed(indicator, result)
        elif ind_type == "network_connection":
            return self._verify_network_connection(indicator)
        elif ind_type == "process_spawned":
            return self._verify_process_spawned(indicator, result)
        elif ind_type == "env_leaked":
            return self._verify_env_leaked(indicator, result)
        elif ind_type == "file_written":
            return self._verify_file_written(indicator)
        elif ind_type == "prompt_injection":
            return self._verify_prompt_injection(indicator, result)
        else:
            return False, f"Unknown indicator type: {ind_type}"

    def cleanup(self) -> None:
        """Clean up verification infrastructure after the test."""
        self._stop_listener()
        for canary in self._canary_files:
            try:
                os.remove(canary)
            except OSError:
                pass
        self._canary_files.clear()

    def _start_listener(self, host: str, port: int) -> None:
        """Start a TCP listener to detect network connections."""
        self._connection_received = False
        self._received_data = b""
        try:
            self._listener_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self._listener_socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
            self._listener_socket.settimeout(5)
            self._listener_socket.bind((host, port))
            self._listener_socket.listen(1)

            def accept_connection():
                try:
                    conn, addr = self._listener_socket.accept()
                    self._connection_received = True
                    self._received_data = conn.recv(4096)
                    # Send a minimal HTTP response
                    conn.sendall(b"HTTP/1.1 200 OK\r\nContent-Length: 2\r\n\r\nOK")
                    conn.close()
                except socket.timeout:
                    pass
                except OSError:
                    pass

            self._listener_thread = threading.Thread(
                target=accept_connection, daemon=True
            )
            self._listener_thread.start()
        except OSError as exc:
            print(
                f"Warning: Could not start listener on {host}:{port}: {exc}",
                file=sys.stderr,
            )

    def _stop_listener(self) -> None:
        """Stop the TCP listener."""
        if self._listener_socket:
            try:
                self._listener_socket.close()
            except OSError:
                pass
            self._listener_socket = None
        if self._listener_thread:
            self._listener_thread.join(timeout=2)
            self._listener_thread = None

    def _verify_file_accessed(
        self, indicator: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Check if a sensitive file was actually read by examining side effects.

        For implementation-hidden attacks the malicious server reads a
        sensitive file and either:
          1. Writes the stolen data to a side-effect file (e.g. /tmp/.ssh_stolen), or
          2. Includes the data in the tool response.

        If eBPF blocked the underlying open/read syscall, neither will be
        true, so we correctly report BLOCKED.
        """
        target_path = indicator.get("path", "")

        if result.get("isError"):
            return False, "Tool returned error"

        # 1. Check if any known side-effect file was created for this target.
        side_effect = self._SIDE_EFFECT_MAP.get(target_path)
        if side_effect and os.path.exists(side_effect):
            return (
                True,
                f"Side-effect file {side_effect} exists (stolen from {target_path})",
            )

        # Also check generic exfil locations that the trojan uses.
        for exfil_path in ("/tmp/exfil.txt", "/tmp/.env_stolen", "/tmp/.ssh_stolen"):
            if os.path.exists(exfil_path):
                return True, f"Exfil file {exfil_path} exists (data from {target_path})"

        # 2. Check if the response contains sensitive data patterns that
        #    would only appear if the file was successfully read.
        result_text = json.dumps(result)
        for pattern in self._SENSITIVE_PATTERNS:
            if pattern.lower() in result_text.lower():
                return (
                    True,
                    f"Response contains sensitive pattern '{pattern}' from {target_path}",
                )

        # 3. Neither side-effect file nor sensitive content found.
        #    The underlying syscall was likely blocked by eBPF.
        return (
            False,
            f"No evidence of successful file access to {target_path} (likely blocked by eBPF)",
        )

    def _verify_network_connection(self, indicator: Dict[str, Any]) -> Tuple[bool, str]:
        """Check if a network connection was received."""
        # Give the connection time to arrive
        if self._listener_thread:
            self._listener_thread.join(timeout=3)
        if self._connection_received:
            return (
                True,
                f"Network connection received, data: {self._received_data[:100]}",
            )
        return False, "No network connection received"

    def _verify_process_spawned(
        self, indicator: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Check if a process was actually spawned by looking for side effects.

        When eBPF blocks execve, os.system() returns non-zero and no child
        process runs.  We verify by checking for files the process would
        have created or network connections it would have made.
        """
        if result.get("isError"):
            return False, "Tool returned error"

        cmd = indicator.get("command", "")

        # Check known side-effect files that spawned processes create.
        # - analyze/word_count spawn curl; word_count also writes /tmp/.exfil_cache
        for side_effect in ("/tmp/.exfil_cache", "/tmp/.evil_cron", "/tmp/evil_cron"):
            if os.path.exists(side_effect):
                return True, f"Process '{cmd}' produced side-effect file {side_effect}"

        # If a network listener was active, check if data was received
        # (the spawned curl would connect to it).
        if self._connection_received:
            return True, f"Process '{cmd}' made network connection to listener"

        # No evidence the process actually ran.
        return (
            False,
            f"No evidence process '{cmd}' was spawned (likely blocked by eBPF)",
        )

    def _verify_env_leaked(
        self, indicator: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Check if environment variables were actually leaked.

        When eBPF blocks the read of /proc/self/environ or the write to
        the exfil file, neither the response nor the side-effect file will
        contain environment data.
        """
        if result.get("isError"):
            return False, "Tool returned error"

        result_text = json.dumps(result)
        pattern = indicator.get("pattern", "")

        # 1. Check if the response contains env data matching the pattern.
        if pattern and re.search(pattern, result_text, re.IGNORECASE):
            return True, f"Environment data matching '{pattern}' found in response"

        # 2. Check known env-variable patterns in the response.
        env_patterns = ["AWS_SECRET", "API_KEY", "SECRET_KEY", "ACCESS_KEY"]
        for ep in env_patterns:
            if ep.lower() in result_text.lower():
                return True, f"Environment variable pattern '{ep}' found in response"

        # 3. Check for exfil side-effect files.
        for exfil_path in ("/tmp/exfil.txt", "/tmp/.env_stolen"):
            if os.path.exists(exfil_path):
                return True, f"Environment data written to {exfil_path}"

        # 4. No evidence of env leak.
        return (
            False,
            "No evidence of environment variable leak (likely blocked by eBPF)",
        )

    def _verify_file_written(self, indicator: Dict[str, Any]) -> Tuple[bool, str]:
        """Check if a file was written to a disallowed location."""
        target = indicator.get("path", "")
        target = os.path.expanduser(target)
        if os.path.exists(target):
            return True, f"File written to {target}"
        return False, f"File not found at {target}"

    def _verify_prompt_injection(
        self, indicator: Dict[str, Any], result: Dict[str, Any]
    ) -> Tuple[bool, str]:
        """Check if prompt injection text appears in the response."""
        result_text = json.dumps(result)
        pattern = indicator.get("pattern", "")
        if pattern and pattern.lower() in result_text.lower():
            return True, f"Prompt injection pattern '{pattern}' found in response"
        return False, f"Prompt injection pattern '{pattern}' not found"


# ---------------------------------------------------------------------------
# Main evaluation loop
# ---------------------------------------------------------------------------


def run_single_case(
    case: Dict[str, Any],
    config: str,
    workspace_dir: str,
) -> Dict[str, Any]:
    """Run a single test case and return results."""
    case_id = case["case_id"]
    server = case["server"]
    tool = case["tool"]
    arguments = case["arguments"]
    indicator = case.get("attack_indicator")
    category = case["category"]
    # A case is benign if the category is "benign" or if the test case
    # explicitly declares ground_truth as benign (e.g. cross-language
    # benign cases that live in a non-benign category directory).
    is_benign = category == "benign" or case.get("ground_truth") == "benign"

    verifier = AttackVerifier()
    result_record = {
        "case_id": case_id,
        "category": "benign" if is_benign else category,
        "attack_name": case.get("attack_name"),
        "server": server,
        "tool": tool,
        "config": config,
        "attack_prevented": False,
        "attack_succeeded": False,
        "defense_action": None,
        "defense_layer": None,
        "latency_ms": 0.0,
        "error": None,
        "evidence": None,
    }

    try:
        # Set up attack verification
        verifier.setup(indicator)

        # Create and start proxy
        proxy = MCPProxy(
            server_name=server,
            config=config,
            workspace_dir=workspace_dir,
        )

        with proxy:
            # Send the tool call
            result, defense_info = proxy.call_tool(
                tool_name=tool,
                arguments=arguments,
            )

            result_record["latency_ms"] = defense_info["latency_ms"]
            result_record["defense_action"] = (
                "BLOCKED" if defense_info["blocked"] else "ALLOWED"
            )
            result_record["defense_layer"] = defense_info.get("layer")

            # Verify attack outcome
            attack_succeeded, evidence = verifier.verify(
                indicator=indicator,
                result=result,
                defense_info=defense_info,
            )

            if is_benign:
                # For benign cases, "attack_prevented" means false positive
                result_record["attack_prevented"] = defense_info["blocked"]
                result_record["attack_succeeded"] = not defense_info["blocked"]
                result_record["evidence"] = evidence
            else:
                result_record["attack_succeeded"] = attack_succeeded
                result_record["attack_prevented"] = not attack_succeeded
                result_record["evidence"] = evidence

    except Exception as exc:
        result_record["error"] = str(exc)
        result_record["attack_prevented"] = False
        result_record["attack_succeeded"] = False

    finally:
        verifier.cleanup()

    return result_record


def run_evaluation(
    config: str,
    run_id: str,
    categories: Optional[List[str]] = None,
    case_ids: Optional[List[str]] = None,
) -> List[Dict[str, Any]]:
    """Run the full evaluation for a given config."""
    test_cases_dir = EXPERIMENTS_ROOT / "test_cases"
    workspace_dir = str(EXPERIMENTS_ROOT / "workspace")
    results_dir = EXPERIMENTS_ROOT / "results" / config

    # Ensure workspace exists
    Path(workspace_dir).mkdir(parents=True, exist_ok=True)
    # Create a sample file for benign reads
    readme_file = Path(workspace_dir) / "readme.txt"
    if not readme_file.exists():
        readme_file.write_text("This is a sample workspace file.\n", encoding="utf-8")
    config_file = Path(workspace_dir) / "data" / "config.json"
    config_file.parent.mkdir(parents=True, exist_ok=True)
    if not config_file.exists():
        config_file.write_text('{"version": "1.0"}\n', encoding="utf-8")

    # Ensure notes_data exists with test notes
    notes_dir = EXPERIMENTS_ROOT / "notes_data"
    notes_dir.mkdir(parents=True, exist_ok=True)
    test_notes = {
        "test001.json": {
            "id": "test001",
            "title": "Test Note",
            "content": "This is a test note for evaluation.",
            "created_at": time.time(),
        },
        "note-1.json": {
            "id": "note-1",
            "title": "Project Planning",
            "content": "Review the project milestones and deliverables.",
            "created_at": time.time(),
        },
    }
    for filename, note_data in test_notes.items():
        note_file = notes_dir / filename
        if not note_file.exists():
            note_file.write_text(json.dumps(note_data, indent=2), encoding="utf-8")

    # Discover test cases
    cases = discover_test_cases(test_cases_dir, categories)
    if case_ids:
        cases = [c for c in cases if c["case_id"] in case_ids]

    print(f"Running {len(cases)} test cases with config '{config}', run_id '{run_id}'")
    print(f"Active layers: {CONFIG_LAYERS.get(config, [])}")
    print("-" * 70)

    results = []
    for i, case in enumerate(cases, 1):
        case_id = case["case_id"]
        print(
            f"[{i}/{len(cases)}] {case_id}: {case.get('attack_name') or case.get('description', '')}...",
            end=" ",
        )
        sys.stdout.flush()

        result = run_single_case(
            case=case,
            config=config,
            workspace_dir=workspace_dir,
        )
        results.append(result)

        status = (
            "BLOCKED"
            if result["attack_prevented"]
            else (
                "PASSED"
                if result["category"] == "benign" and result["attack_succeeded"]
                else "ATTACKED"
                if result["attack_succeeded"]
                else "ERROR"
            )
        )
        latency = result["latency_ms"]
        print(f"{status} ({latency:.1f}ms)")

    # Write results
    results_dir.mkdir(parents=True, exist_ok=True)
    output_file = results_dir / f"{run_id}.json"
    output = {
        "config": config,
        "run_id": run_id,
        "timestamp": time.time(),
        "total_cases": len(results),
        "layers": CONFIG_LAYERS.get(config, []),
        "results": results,
    }
    output_file.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"\nResults written to {output_file}")

    # Print summary
    _print_summary(results, config)

    return results


def _print_summary(results: List[Dict[str, Any]], config: str) -> None:
    """Print a summary of evaluation results."""
    print(f"\n{'=' * 70}")
    print(f"Summary for config: {config}")
    print(f"{'=' * 70}")

    categories = {}
    for r in results:
        cat = r["category"]
        if cat not in categories:
            categories[cat] = {"total": 0, "prevented": 0, "succeeded": 0, "errors": 0}
        categories[cat]["total"] += 1
        if r["error"]:
            categories[cat]["errors"] += 1
        elif r["attack_prevented"]:
            categories[cat]["prevented"] += 1
        elif r["attack_succeeded"]:
            categories[cat]["succeeded"] += 1

    print(
        f"{'Category':<20} {'Total':>6} {'Prevented':>10} {'Succeeded':>10} {'Errors':>7}"
    )
    print("-" * 55)
    for cat, stats in sorted(categories.items()):
        print(
            f"{cat:<20} {stats['total']:>6} "
            f"{stats['prevented']:>10} {stats['succeeded']:>10} "
            f"{stats['errors']:>7}"
        )

    # Overall stats for attack cases
    attack_cases = [r for r in results if r["category"] != "benign"]
    benign_cases = [r for r in results if r["category"] == "benign"]

    if attack_cases:
        prevented = sum(1 for r in attack_cases if r["attack_prevented"])
        total = len(attack_cases)
        print(
            f"\nAttack Prevention Rate: {prevented}/{total} ({100 * prevented / total:.1f}%)"
        )

    if benign_cases:
        false_positives = sum(1 for r in benign_cases if r["attack_prevented"])
        total = len(benign_cases)
        print(
            f"False Positive Rate: {false_positives}/{total} ({100 * false_positives / total:.1f}%)"
        )

    avg_latency = sum(r["latency_ms"] for r in results) / max(len(results), 1)
    print(f"Average Latency: {avg_latency:.2f}ms")


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="MCPGuard Evaluation Runner",
    )
    parser.add_argument(
        "--config",
        required=True,
        choices=list(CONFIG_LAYERS.keys()),
        help="Defense configuration to evaluate",
    )
    parser.add_argument(
        "--run-id",
        required=True,
        help="Unique identifier for this evaluation run",
    )
    parser.add_argument(
        "--categories",
        nargs="*",
        help="Filter to specific test categories",
    )
    parser.add_argument(
        "--cases",
        nargs="*",
        help="Filter to specific case IDs (e.g., FR-01 SE-02)",
    )

    args = parser.parse_args()

    run_evaluation(
        config=args.config,
        run_id=args.run_id,
        categories=args.categories,
        case_ids=args.cases,
    )


if __name__ == "__main__":
    main()
