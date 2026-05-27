<!--
Copyright (c) Meta Platforms, Inc. and affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
-->

# AgentBound-Style Baseline Policies

`C-AB` is a benchmark reproduction of AgentBound-style enforcement, not the
official AgentBound implementation.

The reproduction intentionally models the properties needed for comparison:

- Policies are server-level manifests. All tools exposed by the same MCP server
  share the same filesystem, network, environment, and command policy.
- Enforcement runs at the application layer before the tool call is forwarded.
  It sees the server name, tool name, and concrete JSON arguments.
- The checker does not observe implementation-hidden behavior. If a tool call
  has benign-looking arguments but the server code silently reads a file,
  opens a socket, or spawns a process, `C-AB` cannot block that behavior.

Run the conformance check with:

```bash
cd experiments
python3 runner/agentbound_check.py --run-id codex_20260523_agentbound
```
