#!/usr/bin/env python3
# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Process-sandbox baseline: stdlib seccomp-BPF deny-list wrapper.

This is an MCP-UNAWARE process sandbox used as a baseline against MCPGuard. It
installs a seccomp-BPF filter (via prctl, no third-party deps) that denies a
curated set of dangerous syscalls for the wrapped MCP server, then runs the
target server in-process.

Denied syscalls (x86_64):
  - execve / execveat : no spawning of child programs (curl, wget, /bin/sh, git)
  - socket / connect  : no outbound network (exfiltration)

Denied calls return EPERM (SECCOMP_RET_ERRNO) rather than killing the process,
so the MCP server surfaces a normal tool error instead of dying mid-request.

Why in-process (runpy) instead of exec'ing the server binary: a seccomp filter
that denies execve would also block the exec used to launch the target. Because
this wrapper is already a Python interpreter, it can load and run the target
Python server module directly with no further execve, allowing execve to be
denied for the server's entire lifetime. Consequence: this wrapper is
Python-only; it cannot wrap the Node.js (cross_language) servers.

Usage:
  python3 proxy/seccomp_wrapper.py <target_server_script.py>
"""

from __future__ import annotations

import ctypes
import runpy
import sys

# BPF instruction classes / ops (linux/bpf_common.h)
_BPF_LD = 0x00
_BPF_W = 0x00
_BPF_ABS = 0x20
_BPF_JMP = 0x05
_BPF_JEQ = 0x10
_BPF_RET = 0x06
_BPF_K = 0x00

_LD_ABS = _BPF_LD | _BPF_W | _BPF_ABS  # 0x20
_JEQ = _BPF_JMP | _BPF_JEQ | _BPF_K  # 0x15
_RET = _BPF_RET | _BPF_K  # 0x06

# seccomp return actions (linux/seccomp.h)
_SECCOMP_RET_ALLOW = 0x7FFF0000
_SECCOMP_RET_ERRNO = 0x00050000
_SECCOMP_RET_KILL_PROCESS = 0x80000000
_EPERM = 1

# Audit arch (linux/audit.h)
_AUDIT_ARCH_X86_64 = 0xC000003E

# prctl (linux/prctl.h) + seccomp mode
_PR_SET_NO_NEW_PRIVS = 38
_PR_SET_SECCOMP = 22
_SECCOMP_MODE_FILTER = 2

# x86_64 syscall numbers to deny
_SYS_EXECVE = 59
_SYS_EXECVEAT = 322
_SYS_SOCKET = 41
_SYS_CONNECT = 42

_DENIED_SYSCALLS = (_SYS_EXECVE, _SYS_EXECVEAT, _SYS_SOCKET, _SYS_CONNECT)


class _SockFilter(ctypes.Structure):
    _fields_ = [
        ("code", ctypes.c_ushort),
        ("jt", ctypes.c_ubyte),
        ("jf", ctypes.c_ubyte),
        ("k", ctypes.c_uint),
    ]


class _SockFprog(ctypes.Structure):
    _fields_ = [
        ("len", ctypes.c_ushort),
        ("filter", ctypes.POINTER(_SockFilter)),
    ]


def _build_program() -> list[tuple[int, int, int, int]]:
    """Build the seccomp-BPF program as a list of (code, jt, jf, k)."""
    n_denied = len(_DENIED_SYSCALLS)
    # Layout:
    #   0            : load arch
    #   1            : if arch != x86_64 -> KILL
    #   2            : load syscall nr
    #   3 .. 3+n-1   : per-syscall JEQ -> ERRNO
    #   3+n          : RET ALLOW
    #   4+n          : RET ERRNO
    #   5+n          : RET KILL
    allow_idx = 3 + n_denied
    errno_idx = allow_idx + 1
    kill_idx = allow_idx + 2

    prog: list[tuple[int, int, int, int]] = []
    prog.append((_LD_ABS, 0, 0, 4))  # 0: A = arch
    # 1: if A == x86_64 continue else jump to kill
    prog.append((_JEQ, 0, kill_idx - 1 - 1, _AUDIT_ARCH_X86_64))
    prog.append((_LD_ABS, 0, 0, 0))  # 2: A = syscall nr
    for offset, nr in enumerate(_DENIED_SYSCALLS):
        idx = 3 + offset
        prog.append((_JEQ, errno_idx - idx - 1, 0, nr))
    prog.append((_RET, 0, 0, _SECCOMP_RET_ALLOW))  # allow_idx
    prog.append((_RET, 0, 0, _SECCOMP_RET_ERRNO | _EPERM))  # errno_idx
    prog.append((_RET, 0, 0, _SECCOMP_RET_KILL_PROCESS))  # kill_idx
    return prog


def install_seccomp_filter() -> None:
    """Install the deny-list seccomp filter on the current thread/process."""
    libc = ctypes.CDLL("libc.so.6", use_errno=True)

    if libc.prctl(_PR_SET_NO_NEW_PRIVS, 1, 0, 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"prctl(PR_SET_NO_NEW_PRIVS) failed: {err}")

    instrs = _build_program()
    filt_array = (_SockFilter * len(instrs))(
        *[_SockFilter(code=c, jt=jt, jf=jf, k=k) for (c, jt, jf, k) in instrs]
    )
    prog = _SockFprog(len=len(instrs), filter=filt_array)

    if libc.prctl(_PR_SET_SECCOMP, _SECCOMP_MODE_FILTER, ctypes.byref(prog), 0, 0) != 0:
        err = ctypes.get_errno()
        raise OSError(err, f"prctl(PR_SET_SECCOMP) failed: {err}")


def main() -> None:
    if len(sys.argv) < 2:
        print("usage: seccomp_wrapper.py <target_server_script.py>", file=sys.stderr)
        raise SystemExit(2)

    target = sys.argv[1]
    install_seccomp_filter()

    # Present argv to the target as if it were invoked directly.
    sys.argv = [target] + sys.argv[2:]
    runpy.run_path(target, run_name="__main__")


if __name__ == "__main__":
    main()
