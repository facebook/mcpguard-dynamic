<!--
Copyright (c) Meta Platforms, Inc. and affiliates.

This source code is licensed under the MIT license found in the
LICENSE file in the root directory of this source tree.
-->

# Contributing to MCPGuard-Dynamic

We welcome contributions: new MCP servers, additional test cases, policy improvements, and bug fixes.

## Pull Requests

1. Fork the repo and create your branch from `main`.
2. If you added code that should be tested, add a corresponding test case under `test_cases/`.
3. If you changed the proxy or the eBPF programs, run `python3 -m runner.smoke_test` and confirm it passes.
4. Make sure your code lints (follow the existing style; the Python code is `black`-formatted).
5. Open a pull request against `main` with a clear description of the change and the threat model it addresses.

## Contributor License Agreement (CLA)

In order to accept your pull request, we need you to submit a CLA. You only need to do this once to work on any of Meta's open-source projects.

Complete your CLA here: <https://code.facebook.com/cla>

## Issues

We use GitHub Issues to track public bugs and feature requests. Please ensure your description is clear and has sufficient instructions to reproduce the issue.

For security-sensitive issues, please follow the disclosure process in [SECURITY.md](SECURITY.md) instead.

## Coding Style

- Python: standard library only where possible; `black`-formatted; type hints encouraged on new code.
- eBPF C: keep BPF programs small and self-contained; document any kernel-version assumptions inline.
- New MCP servers belong under `servers/`; new benchmark cases belong under `test_cases/<category>/` with a deterministic verifier.

## License

By contributing to MCPGuard-Dynamic, you agree that your contributions will be licensed under the MIT License found in [LICENSE](LICENSE).
