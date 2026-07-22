# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
MCPGuard Layer 3: eBPF Sandbox.

Controller for the BPF LSM programs in experiments/ebpf. The proxy uses this
class to install per-server policies into pinned BPF maps before forwarding a
tool call. eBPF configurations fail closed when the kernel programs or maps are
not available.
"""

import ctypes
import ipaddress
import json
import logging
import os
import socket
import struct
import subprocess
import tempfile
from pathlib import Path
from typing import Any, Dict, List, Optional, Set

logger = logging.getLogger(__name__)

# Must match common.h definitions
MAX_PATH_LEN = 256
MAX_PATH_RULES = 32
MAX_NET_RULES = 16
MAX_EXEC_RULES = 16

# BPF pin base path
PIN_PATH = "/sys/fs/bpf/mcpguard"

# Subdirectories per program
FILE_MAP_DIR = f"{PIN_PATH}/file"
NET_MAP_DIR = f"{PIN_PATH}/net"
PROC_MAP_DIR = f"{PIN_PATH}/proc"
FORK_MAP_DIR = f"{PIN_PATH}/fork"

# Shared pid_policy_map used by all four programs (file, net, proc, fork).
# Created by `make install` before loading any BPF program.
SHARED_PID_MAP = f"{PIN_PATH}/pid_policy_map"


def _int_to_le_hex(val: int, nbytes: int) -> List[str]:
    """Convert an integer to little-endian hex byte list for bpftool."""
    return [f"0x{b:02x}" for b in val.to_bytes(nbytes, "little")]


def _str_to_hex(s: str, total_len: int) -> List[str]:
    """Convert a string to a fixed-length hex byte list (zero-padded)."""
    raw = s.encode("utf-8")[:total_len]
    padded = raw + b"\x00" * (total_len - len(raw))
    return [f"0x{b:02x}" for b in padded]


def _run_bpftool(args: List[str]) -> bool:
    """Run a bpftool command, returning True on success."""
    cmd = ["sudo", "bpftool"] + args
    result = subprocess.run(
        cmd,
        capture_output=True,
        text=True,
        timeout=10,
    )
    if result.returncode != 0:
        logger.warning("bpftool command failed: %s\nstderr: %s", cmd, result.stderr)
        return False
    return True


def _require_bpftool(args: List[str], description: str) -> None:
    """Run bpftool and fail closed if the policy update cannot be applied."""
    if not _run_bpftool(args):
        raise RuntimeError(f"Failed to apply eBPF policy update: {description}")


def _run_bpftool_map_update_binary(
    map_path: str, key_bytes: bytes, value_bytes: bytes
) -> bool:
    """Write a map entry using temp binary files (avoids command-line length limits)."""
    key_file = ""
    val_file = ""
    try:
        with tempfile.NamedTemporaryFile(delete=False, prefix="bpf_key_") as kf:
            kf.write(key_bytes)
            key_file = kf.name
        with tempfile.NamedTemporaryFile(delete=False, prefix="bpf_val_") as vf:
            vf.write(value_bytes)
            val_file = vf.name

        cmd = (
            [
                "sudo",
                "bpftool",
                "map",
                "update",
                "pinned",
                map_path,
                "key",
                "hex",
            ]
            + [f"0x{b:02x}" for b in key_bytes]
            + [
                "value",
                "hex",
            ]
        )

        if len(value_bytes) > 256:
            hex_chunks = []
            for i in range(0, len(value_bytes), 64):
                chunk = value_bytes[i : i + 64]
                hex_chunks.extend(f"0x{b:02x}" for b in chunk)
            cmd += hex_chunks
        else:
            cmd += [f"0x{b:02x}" for b in value_bytes]

        result = subprocess.run(cmd, capture_output=True, text=True, timeout=30)
        if result.returncode != 0:
            logger.warning(
                "bpftool binary map update failed (len=%d): %s",
                len(value_bytes),
                result.stderr[:200],
            )
            return False
        return True
    finally:
        for f in (key_file, val_file):
            try:
                os.unlink(f)
            except OSError:
                pass


# --- Direct bpf() syscall map update -------------------------------------
# bpftool's CLI parses each hex byte as a separate argv token, so a ~8 KB
# file_policy value (or ~4 KB exec_policy) overflows ARG_MAX / bpftool's token
# limit and the update silently fails. We update those maps via the bpf()
# syscall directly, passing the value as one contiguous buffer.
_NR_BPF = 321  # x86_64
_BPF_MAP_UPDATE_ELEM = 2
_BPF_OBJ_GET = 7
_BPF_ANY = 0
_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def _bpf_syscall(cmd: int, attr: "ctypes.Array") -> int:
    ctypes.set_errno(0)
    return _libc.syscall(
        ctypes.c_long(_NR_BPF),
        ctypes.c_long(cmd),
        ctypes.cast(attr, ctypes.c_void_p),
        ctypes.c_uint(len(attr)),
    )


def _bpf_obj_get(path: str) -> int:
    path_buf = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = (ctypes.c_uint8 * 16)()
    struct.pack_into("<QII", attr, 0, ctypes.addressof(path_buf), 0, 0)
    fd = _bpf_syscall(_BPF_OBJ_GET, attr)
    if fd < 0:
        raise OSError(ctypes.get_errno(), f"BPF_OBJ_GET failed for {path}")
    return fd


def _bpf_map_update_direct(map_path: str, key_bytes: bytes, value_bytes: bytes) -> bool:
    """Update a pinned BPF map via bpf() directly (no argv/token limits)."""
    try:
        fd = _bpf_obj_get(map_path)
    except OSError as exc:
        logger.warning("BPF_OBJ_GET failed for %s: %s", map_path, exc)
        return False
    try:
        key_buf = ctypes.create_string_buffer(key_bytes, len(key_bytes))
        val_buf = ctypes.create_string_buffer(value_bytes, len(value_bytes))
        attr = (ctypes.c_uint8 * 32)()
        struct.pack_into(
            "<IIQQQ",
            attr,
            0,
            fd,
            0,
            ctypes.addressof(key_buf),
            ctypes.addressof(val_buf),
            _BPF_ANY,
        )
        if _bpf_syscall(_BPF_MAP_UPDATE_ELEM, attr) != 0:
            logger.warning(
                "BPF_MAP_UPDATE_ELEM failed for %s: errno=%d",
                map_path,
                ctypes.get_errno(),
            )
            return False
        return True
    finally:
        os.close(fd)


def _require_map_update(
    map_path: str, key_bytes: bytes, value_bytes: bytes, desc: str
) -> None:
    """Fail closed if a policy map cannot be updated."""
    if not _bpf_map_update_direct(map_path, key_bytes, value_bytes):
        raise RuntimeError(
            f"Failed to update {desc} via bpf() syscall; refusing weakened policy"
        )


class EBPFSandbox:
    """
    L3 defense layer using eBPF LSM programs.

    When eBPF programs are loaded (requires root and a compatible kernel),
    this class manages per-PID policies in BPF maps. When eBPF is not
    available, activation raises instead of falling back to weaker enforcement.
    """

    def __init__(self):
        self._active_policies: Dict[int, Dict[str, Any]] = {}
        self._ebpf_available = self._check_ebpf_available()
        self._process_sandboxes: Dict[int, "ProcessSandbox"] = {}

    def is_available(self) -> bool:
        """Return whether the required eBPF programs and maps are available."""
        return self._ebpf_available

    def _check_ebpf_available(self) -> bool:
        """Check if eBPF LSM programs can be loaded."""
        # Check if we have the compiled BPF objects
        ebpf_dir = Path(__file__).resolve().parent.parent / "ebpf"
        bpf_objects = list(ebpf_dir.glob("*.bpf.o"))
        if not bpf_objects:
            return False

        # Check if we're running as root (required for BPF LSM)
        if os.geteuid() != 0:
            return False

        # Check kernel support
        try:
            with open("/sys/kernel/security/lsm", "r") as f:
                lsms = f.read().strip()
                if "bpf" not in lsms:
                    return False
        except (FileNotFoundError, PermissionError):
            return False

        # Check if programs are actually loaded (shared pid_policy_map pinned)
        return os.path.exists(SHARED_PID_MAP)

    def activate_policy(self, pid: int, policy: Dict[str, Any]) -> None:
        """
        Activate a sandbox policy for the given PID.

        If eBPF is available, writes policy to BPF maps. Otherwise raises so
        the evaluation cannot silently report fallback behavior as eBPF.
        """
        self._active_policies[pid] = policy

        if not self._ebpf_available:
            self._active_policies.pop(pid, None)
            raise RuntimeError(
                "eBPF programs/maps are unavailable; refusing fallback enforcement"
            )

        self._write_bpf_maps(pid, policy)

    def deactivate_policy(self, pid: int) -> None:
        """Remove sandbox policy for the given PID."""
        if pid in self._active_policies:
            del self._active_policies[pid]

        if self._ebpf_available:
            self._clear_bpf_maps(pid)
        elif pid in self._process_sandboxes:
            self._process_sandboxes[pid].deactivate()
            del self._process_sandboxes[pid]

    def is_active(self, pid: int) -> bool:
        """Check if a policy is active for the given PID."""
        return pid in self._active_policies

    def _write_bpf_maps(self, pid: int, policy: Dict[str, Any]) -> None:
        """
        Write policy to BPF maps for eBPF enforcement.

        pid_policy_map is shared across all four programs (file_guard,
        net_guard, proc_guard, fork_guard) via a single pinned map at
        /sys/fs/bpf/mcpguard/pid_policy_map. This means:
          - One update to the shared map is visible to all programs.
          - When fork_guard detects a child process and inserts its PID,
            file_guard/net_guard/proc_guard immediately enforce the
            parent's policy on the child.

        Per-program policy maps remain separate:
          - /sys/fs/bpf/mcpguard/file/file_policy_map
          - /sys/fs/bpf/mcpguard/net/net_policy_map
          - /sys/fs/bpf/mcpguard/proc/exec_policy_map

        We use the PID as the policy_id for simplicity (1:1 mapping).
        """
        policy_id = pid  # Use PID as policy_id for simplicity

        # Build the pid_policy_entry: { policy_id: u32, flags: u32 }
        pid_key = ["key"] + _int_to_le_hex(pid, 4)
        pid_value = ["value"] + _int_to_le_hex(policy_id, 4) + _int_to_le_hex(0, 4)

        # Update the shared pid_policy_map (one map for all four programs)
        _require_bpftool(
            ["map", "update", "pinned", SHARED_PID_MAP] + pid_key + pid_value,
            "pid_policy_map",
        )

        # Parse and write file policy
        self._write_file_policy(policy_id, policy)

        # Parse and write network policy
        self._write_net_policy(policy_id, policy)

        # Parse and write exec policy
        self._write_exec_policy(policy_id, policy)

    def _write_file_policy(  # noqa: C901
        self, policy_id: int, policy: Dict[str, Any]
    ) -> None:
        """Build and write file_policy struct to file_policy_map.

        Tracks per-path read/write permissions separately so that the
        BPF file_guard can enforce mode-specific access control.  A path
        that only appears in ``filesystem.read`` will have allow_write=0
        and vice-versa.  System paths are read-only by default.
        """
        tools = policy.get("tools", {})

        # Map from path prefix -> {allow_read, allow_write}
        path_perms: Dict[str, Dict[str, int]] = {}

        def _add_path(prefix: str, read: bool, write: bool) -> None:
            if prefix not in path_perms:
                path_perms[prefix] = {"allow_read": 0, "allow_write": 0}
            if read:
                path_perms[prefix]["allow_read"] = 1
            if write:
                path_perms[prefix]["allow_write"] = 1

        def _dir_prefix(prefix: str) -> str:
            return prefix if prefix.endswith("/") else prefix + "/"

        experiments_dir = str(Path(__file__).resolve().parent.parent)

        # Collect per-tool filesystem permissions
        for tool_policy in tools.values():
            fs = tool_policy.get("filesystem", {})
            for path in fs.get("read", []):
                is_dir_glob = path.endswith("/**") or path.endswith("/*")
                prefix = path.replace("/**", "").replace("/*", "")
                stored_prefix = _dir_prefix(prefix) if is_dir_glob else prefix
                _add_path(stored_prefix, read=True, write=False)
                # Resolve relative paths against experiments root
                if prefix.startswith("./"):
                    resolved = str((Path(experiments_dir) / prefix[2:]).resolve())
                    if is_dir_glob:
                        resolved = _dir_prefix(resolved)
                    _add_path(resolved, read=True, write=False)
            for path in fs.get("write", []):
                is_dir_glob = path.endswith("/**") or path.endswith("/*")
                prefix = path.replace("/**", "").replace("/*", "")
                stored_prefix = _dir_prefix(prefix) if is_dir_glob else prefix
                _add_path(stored_prefix, read=False, write=True)
                if prefix.startswith("./"):
                    resolved = str((Path(experiments_dir) / prefix[2:]).resolve())
                    if is_dir_glob:
                        resolved = _dir_prefix(resolved)
                    _add_path(resolved, read=False, write=True)

        # Always allow basic system paths (read-only) so the process can
        # function.  NOTE: Do NOT include /proc/self (leaks environ) or
        # /tmp (used by attack payloads for exfiltration staging files).
        system_paths = [
            "/lib/",
            "/lib64/",
            "/usr/lib/",
            "/usr/lib64/",
            "/usr/local/lib/",
            "/usr/local/bin/",
            "/usr/bin/",
            "/usr/sbin/",
            "/bin/",
            "/dev/null",
            "/dev/urandom",
            "/dev/pts/",
            "/etc/ld.so",
            "/etc/localtime",
            "/usr/local/fbcode/",
            "/usr/share/",
        ]

        for sp in system_paths:
            _add_path(sp, read=True, write=False)

        # Allow the experiments directory itself (read-only) so Python
        # can load server modules at runtime.
        _add_path(_dir_prefix(experiments_dir), read=True, write=False)

        allowed_paths = list(path_perms.keys())
        rule_count = min(len(allowed_paths), MAX_PATH_RULES)

        # Build file_policy struct:
        #   rules[MAX_PATH_RULES]: each is { path_prefix[256], allow_read, allow_write, allow_exec, _pad }
        #   rule_count: u32
        value_bytes = bytearray()

        for i in range(MAX_PATH_RULES):
            if i < rule_count:
                p = allowed_paths[i]
                perms = path_perms[p]
                path_bytes = p.encode("utf-8")[:MAX_PATH_LEN]
                path_bytes = path_bytes + b"\x00" * (MAX_PATH_LEN - len(path_bytes))
                value_bytes.extend(path_bytes)
                value_bytes.extend(
                    struct.pack(
                        "BBBB",
                        perms["allow_read"],
                        perms["allow_write"],
                        0,  # allow_exec
                        0,  # _pad
                    )
                )
            else:
                value_bytes.extend(b"\x00" * (MAX_PATH_LEN + 4))

        value_bytes.extend(struct.pack("<I", rule_count))

        _require_map_update(
            f"{FILE_MAP_DIR}/file_policy_map",
            struct.pack("<I", policy_id),
            bytes(value_bytes),
            "file_policy_map",
        )

    def _write_net_policy(self, policy_id: int, policy: Dict[str, Any]) -> None:
        """Build and write net_policy struct to net_policy_map."""
        tools = policy.get("tools", {})

        # Collect allowed network destinations
        net_rules: List[Dict[str, Any]] = []
        for tool_policy in tools.values():
            net = tool_policy.get("network", {})
            for dest in net.get("allow", []):
                # Parse destination format: "host:port" or "host" or "*:port"
                rule = self._parse_net_dest(dest)
                if rule and rule not in net_rules:
                    net_rules.append(rule)

        # NOTE: Do NOT add a blanket localhost allow rule here.
        # The MCP server communicates with the proxy via stdin/stdout
        # (no network sockets), so there is no legitimate need for
        # localhost connectivity. Adding one would allow malicious
        # servers to exfiltrate data to attacker listeners on 127.0.0.1.

        rule_count = min(len(net_rules), MAX_NET_RULES)

        # Build net_policy struct:
        #   rules[MAX_NET_RULES]: each is { addr: u32, port: u16, proto: u8, allow: u8 }
        #   rule_count: u32
        value_bytes = bytearray()

        for i in range(MAX_NET_RULES):
            if i < rule_count:
                r = net_rules[i]
                value_bytes.extend(
                    struct.pack(
                        "<IH BB",
                        socket.htonl(r["addr"]) if r["addr"] != 0 else 0,
                        socket.htons(r["port"]) if r["port"] != 0 else 0,
                        r.get("proto", 6),
                        r.get("allow", 1),
                    )
                )
            else:
                value_bytes.extend(b"\x00" * 8)

        value_bytes.extend(struct.pack("<I", rule_count))

        _require_map_update(
            f"{NET_MAP_DIR}/net_policy_map",
            struct.pack("<I", policy_id),
            bytes(value_bytes),
            "net_policy_map",
        )

    def _parse_net_dest(self, dest: str) -> Optional[Dict[str, Any]]:
        """Parse a network destination string into a net_rule dict."""
        # Formats: "1.2.3.4:80", "1.2.3.4", "*:443", "*"
        try:
            if ":" in dest:
                parts = dest.rsplit(":", 1)
                host = parts[0]
                port = int(parts[1])
            else:
                host = dest
                port = 0

            if host == "*" or host == "0.0.0.0":
                addr = 0
            else:
                addr = int(ipaddress.IPv4Address(host))

            return {"addr": addr, "port": port, "proto": 6, "allow": 1}
        except (ValueError, ipaddress.AddressValueError):
            logger.warning("Cannot parse network destination: %s", dest)
            return None

    def _write_exec_policy(self, policy_id: int, policy: Dict[str, Any]) -> None:
        """Build and write exec_policy struct to exec_policy_map."""
        tools = policy.get("tools", {})

        # Collect allowed executables from syscall policies
        allowed_execs: List[str] = []

        # Default set of executables any process needs
        default_execs = ["/usr/bin/python3", "/usr/bin/python", "/bin/sh"]
        for exe in default_execs:
            if exe not in allowed_execs:
                allowed_execs.append(exe)

        # Check if any tool allows execve
        for tool_policy in tools.values():
            syscalls = tool_policy.get("syscalls", {})
            allowed_sys = syscalls.get("allow", [])
            denied_sys = syscalls.get("deny", [])
            if "execve" in denied_sys:
                # This tool does NOT want execve; don't add extra executables
                continue
            if "execve" in allowed_sys:
                # Allow more executables for tools that permit exec
                extra = tool_policy.get("allowed_executables", [])
                for exe in extra:
                    if exe not in allowed_execs:
                        allowed_execs.append(exe)

        rule_count = min(len(allowed_execs), MAX_EXEC_RULES)

        # Build exec_policy struct:
        #   rules[MAX_EXEC_RULES]: each is { binary_path[256], allow: u8, _pad[3] }
        #   rule_count: u32
        value_bytes = bytearray()

        for i in range(MAX_EXEC_RULES):
            if i < rule_count:
                path_bytes = allowed_execs[i].encode("utf-8")[:MAX_PATH_LEN]
                path_bytes = path_bytes + b"\x00" * (MAX_PATH_LEN - len(path_bytes))
                value_bytes.extend(path_bytes)
                value_bytes.extend(struct.pack("BBBB", 1, 0, 0, 0))  # allow, _pad[3]
            else:
                value_bytes.extend(b"\x00" * (MAX_PATH_LEN + 4))

        value_bytes.extend(struct.pack("<I", rule_count))

        _require_map_update(
            f"{PROC_MAP_DIR}/exec_policy_map",
            struct.pack("<I", policy_id),
            bytes(value_bytes),
            "exec_policy_map",
        )

    def _clear_bpf_maps(self, pid: int) -> None:
        """
        Clear BPF map entries for the given PID.

        Removes the PID from the shared pid_policy_map and removes
        the corresponding policy entries from each per-program policy map.

        Note: child PIDs inserted by fork_guard also share the same
        policy_id (== parent PID). We iterate the shared pid_policy_map
        to find and remove any child PIDs that reference this policy_id.
        """
        policy_id = pid  # We use PID as policy_id

        pid_key = ["key"] + _int_to_le_hex(pid, 4)
        policy_key = ["key"] + _int_to_le_hex(policy_id, 4)

        # Remove the parent PID from the shared pid_policy_map
        _run_bpftool(
            [
                "map",
                "delete",
                "pinned",
                SHARED_PID_MAP,
            ]
            + pid_key
        )

        # Also remove any child PIDs that fork_guard inserted with the
        # same policy_id. We dump the map and delete matching entries.
        self._clear_child_pids(policy_id)

        # Remove policy entries from each per-program policy map
        _run_bpftool(
            [
                "map",
                "delete",
                "pinned",
                f"{FILE_MAP_DIR}/file_policy_map",
            ]
            + policy_key
        )
        _run_bpftool(
            [
                "map",
                "delete",
                "pinned",
                f"{NET_MAP_DIR}/net_policy_map",
            ]
            + policy_key
        )
        _run_bpftool(
            [
                "map",
                "delete",
                "pinned",
                f"{PROC_MAP_DIR}/exec_policy_map",
            ]
            + policy_key
        )

    def _clear_child_pids(self, policy_id: int) -> None:
        """
        Remove all child PIDs from the shared pid_policy_map that have
        the given policy_id. These were inserted by fork_guard when a
        monitored parent forked child processes.
        """
        try:
            result = subprocess.run(
                ["sudo", "bpftool", "map", "dump", "pinned", SHARED_PID_MAP, "-j"],
                capture_output=True,
                text=True,
                timeout=10,
            )
            if result.returncode != 0:
                return

            entries = json.loads(result.stdout)
            for entry in entries:
                # bpftool JSON format: each entry has "key" and "value" as
                # lists of hex strings or integers.
                key_bytes = entry.get("key", [])
                value_bytes = entry.get("value", [])

                # Parse key (4-byte LE u32 PID)
                if isinstance(key_bytes, list) and len(key_bytes) >= 4:
                    child_pid = int.from_bytes(
                        [self._parse_hex(b) for b in key_bytes[:4]],
                        "little",
                    )
                else:
                    continue

                # Parse value first 4 bytes (policy_id)
                if isinstance(value_bytes, list) and len(value_bytes) >= 4:
                    entry_policy_id = int.from_bytes(
                        [self._parse_hex(b) for b in value_bytes[:4]],
                        "little",
                    )
                else:
                    continue

                # If this entry has our policy_id, delete it
                if entry_policy_id == policy_id:
                    child_key = ["key"] + _int_to_le_hex(child_pid, 4)
                    _run_bpftool(
                        [
                            "map",
                            "delete",
                            "pinned",
                            SHARED_PID_MAP,
                        ]
                        + child_key
                    )

        except (subprocess.TimeoutExpired, json.JSONDecodeError, Exception) as exc:
            logger.warning("Failed to clear child PIDs: %s", exc)

    @staticmethod
    def _parse_hex(val) -> int:
        """Parse a bpftool JSON value (hex string or int) to an integer."""
        if isinstance(val, int):
            return val
        if isinstance(val, str):
            return int(val, 0)
        return 0


class ProcessSandbox:
    """
    Legacy process-level sandbox retained for direct smoke tests.

    The evaluation proxy no longer uses this as a substitute for eBPF
    configurations, because that would report weaker fallback behavior as L3.

    Provides basic isolation by:
      - Restricting environment variables
      - Setting restrictive working directory
      - Monitoring child process spawning
    """

    def __init__(self, pid: int, policy: Dict[str, Any]):
        self.pid = pid
        self.policy = policy
        self._restricted_env: Dict[str, str] = {}
        self._allowed_paths: Set[str] = set()
        self._denied_paths: Set[str] = set()
        self._active = False

        self._parse_policy()

    def _parse_policy(self) -> None:
        """Extract restrictions from the policy dict."""
        tools = self.policy.get("tools", {})
        for _tool_name, tool_policy in tools.items():
            # Collect allowed filesystem paths
            fs = tool_policy.get("filesystem", {})
            for path in fs.get("read", []):
                self._allowed_paths.add(path)
            for path in fs.get("write", []):
                self._allowed_paths.add(path)

            # Collect env var restrictions
            env_policy = tool_policy.get("env_vars", {})
            denied_patterns = env_policy.get("deny", [])
            for pattern in denied_patterns:
                if pattern == "*":
                    # Deny all env vars except explicitly allowed
                    self._restricted_env = {
                        k: v
                        for k, v in os.environ.items()
                        if k in ("PATH", "HOME", "LANG", "TERM", "PYTHON", "PYTHONPATH")
                    }
                    break

        # Common sensitive paths to deny
        self._denied_paths = {
            "/etc/shadow",
            "/etc/sudoers",
            os.path.expanduser("~/.ssh"),
            os.path.expanduser("~/.aws"),
            "/proc/self/environ",
        }

    def activate(self) -> None:
        """Activate process-level restrictions."""
        self._active = True
        # In a real implementation, this would use seccomp, namespaces,
        # or cgroups. For smoke testing, we just record that restrictions
        # are active and the proxy checks them.

    def deactivate(self) -> None:
        """Deactivate process-level restrictions."""
        self._active = False

    def check_file_access(self, path: str, mode: str = "r") -> bool:
        """Check if file access is allowed under this sandbox."""
        if not self._active:
            return True

        abs_path = os.path.abspath(path)

        # Check denied paths
        for denied in self._denied_paths:
            if abs_path.startswith(denied):
                return False

        return True

    def check_network_access(self, host: str, port: int) -> bool:
        """Check if network access is allowed under this sandbox."""
        if not self._active:
            return True
        # By default, deny all network access in fallback mode
        return False

    def check_exec(self, command: str) -> bool:
        """Check if process execution is allowed under this sandbox."""
        if not self._active:
            return True
        # By default, deny exec in fallback mode
        return False

    def get_restricted_env(self) -> Dict[str, str]:
        """Get the restricted environment for subprocess execution."""
        if self._restricted_env:
            return self._restricted_env.copy()
        # Default minimal env
        return {
            "PATH": os.environ.get("PATH", "/usr/bin:/bin"),
            "HOME": os.environ.get("HOME", "/tmp"),
            "LANG": os.environ.get("LANG", "C.UTF-8"),
        }
