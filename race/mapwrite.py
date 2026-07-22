# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

"""
Minimal root helper: update a pinned BPF map via the bpf() syscall directly.

`bpftool map update ... value hex` caps the number of hex tokens it will parse
on one command, which overflows for the ~8KB file_policy struct. This helper
takes the whole value as a single hex-string argument and issues
BPF_OBJ_GET + BPF_MAP_UPDATE_ELEM through ctypes, avoiding both argv and
bpftool token limits.

Usage (run under sudo):
    sudo python3 mapwrite.py <pinned_map_path> <key_hex> <value_hex>
"""

from __future__ import annotations

import ctypes
import struct
import sys

__NR_bpf = 321  # x86_64
BPF_MAP_UPDATE_ELEM = 2
BPF_OBJ_GET = 7
BPF_ANY = 0

_libc = ctypes.CDLL(None, use_errno=True)
_libc.syscall.restype = ctypes.c_long


def _bpf(cmd: int, attr: ctypes.Array) -> int:
    ctypes.set_errno(0)
    ret = _libc.syscall(
        ctypes.c_long(__NR_bpf),
        ctypes.c_long(cmd),
        ctypes.cast(attr, ctypes.c_void_p),
        ctypes.c_uint(len(attr)),
    )
    return ret


def _obj_get(path: str) -> int:
    path_buf = ctypes.create_string_buffer(path.encode() + b"\x00")
    attr = (ctypes.c_uint8 * 16)()
    struct.pack_into("<QII", attr, 0, ctypes.addressof(path_buf), 0, 0)
    fd = _bpf(BPF_OBJ_GET, attr)
    if fd < 0:
        raise OSError(ctypes.get_errno(), f"BPF_OBJ_GET failed for {path}")
    return fd


def _map_update(map_fd: int, key: bytes, value: bytes) -> None:
    key_buf = ctypes.create_string_buffer(key, len(key))
    val_buf = ctypes.create_string_buffer(value, len(value))
    attr = (ctypes.c_uint8 * 32)()
    # struct { u32 map_fd; pad; u64 key; u64 value; u64 flags; }
    struct.pack_into(
        "<IIQQQ",
        attr,
        0,
        map_fd,
        0,
        ctypes.addressof(key_buf),
        ctypes.addressof(val_buf),
        BPF_ANY,
    )
    ret = _bpf(BPF_MAP_UPDATE_ELEM, attr)
    if ret != 0:
        raise OSError(ctypes.get_errno(), "BPF_MAP_UPDATE_ELEM failed")


def main() -> None:
    map_path, key_hex, value_hex = sys.argv[1], sys.argv[2], sys.argv[3]
    key = bytes.fromhex(key_hex)
    value = bytes.fromhex(value_hex)
    fd = _obj_get(map_path)
    _map_update(fd, key, value)


if __name__ == "__main__":
    main()
