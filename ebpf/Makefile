# Copyright (c) Meta Platforms, Inc. and affiliates.
#
# This source code is licensed under the MIT license found in the
# LICENSE file in the root directory of this source tree.

# MCPGuard eBPF Build Instructions
#
# Prerequisites:
#   - clang >= 12 with BPF target support
#   - bpftool for generating vmlinux.h and skeleton headers
#   - libbpf-dev for BPF helper headers
#   - Linux kernel >= 5.7 with BPF LSM support
#
# Kernel configuration requirements:
#   CONFIG_BPF=y
#   CONFIG_BPF_SYSCALL=y
#   CONFIG_BPF_LSM=y
#   CONFIG_LSM="...,bpf"   (bpf must be in the LSM list)
#
# Usage:
#   make                   # Build all BPF objects
#   make vmlinux           # Generate vmlinux.h from running kernel
#   make clean             # Remove built artifacts
#   sudo make install      # Load BPF programs and pin maps
#   sudo make uninstall    # Unload BPF programs and remove pins

CLANG ?= clang
BPFTOOL_CMD := $(shell if bpftool version >/dev/null 2>&1; then echo bpftool; else find /usr/lib/linux-tools -name bpftool 2>/dev/null | head -n 1; fi)
BPFTOOL ?= $(if $(BPFTOOL_CMD),$(BPFTOOL_CMD),bpftool)

# BPF compilation flags
BPF_CFLAGS := -g -O2 -target bpf
BPF_CFLAGS += -D__TARGET_ARCH_x86
BPF_CFLAGS += -I.
BPF_CFLAGS += -Wall -Werror

# Source files
BPF_SRCS := file_guard.bpf.c net_guard.bpf.c proc_guard.bpf.c fork_guard.bpf.c
BPF_OBJS := $(BPF_SRCS:.bpf.c=.bpf.o)

# Pin path for BPF maps
PIN_PATH := /sys/fs/bpf/mcpguard

.PHONY: all clean vmlinux install uninstall

all: vmlinux.h $(BPF_OBJS)

# Generate vmlinux.h from the running kernel's BTF, unless one is
# already checked out (some RC/custom kernels produce a broken dump).
vmlinux.h:
	@if [ -s vmlinux.h ]; then \
		echo "Using pre-existing vmlinux.h"; \
	else \
		$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h; \
	fi

vmlinux:
	$(BPFTOOL) btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h

# Compile BPF C sources to BPF objects
# Use --strip-debug in clang instead of llvm-strip (which may not be installed)
%.bpf.o: %.bpf.c common.h vmlinux.h
	$(CLANG) $(BPF_CFLAGS) -c $< -o $@

# Install: load BPF programs with a shared pid_policy_map.
#
# All four programs (file_guard, net_guard, proc_guard, fork_guard) need
# to share a single pid_policy_map so that when fork_guard adds a child
# PID, the other three programs immediately see it and enforce the
# parent's policy on the child.
#
# Strategy:
#   1. Create the shared pid_policy_map via bpftool map create
#   2. Load fork_guard first (it only uses pid_policy_map + audit_events)
#   3. Load file_guard, net_guard, proc_guard each with their own
#      pinmaps subdirectory, but reuse the shared pid_policy_map via
#      bpftool's "map name pid_policy_map pinned <path>" option
install: $(BPF_OBJS)
	@echo "Loading MCPGuard BPF programs with shared pid_policy_map..."
	@mkdir -p $(PIN_PATH)/fork $(PIN_PATH)/file $(PIN_PATH)/net $(PIN_PATH)/proc
	@# Step 1: Create the shared pid_policy_map if it does not already exist.
	@# key = __u32 (4 bytes), value = struct pid_policy_entry (8 bytes)
	@if [ ! -e $(PIN_PATH)/pid_policy_map ]; then \
		$(BPFTOOL) map create $(PIN_PATH)/pid_policy_map \
			type hash key 4 value 8 entries 1024 \
			name pid_policy_map; \
	fi
	@# Step 2: Load fork_guard (tracepoint, not LSM) reusing shared pid_policy_map.
	$(BPFTOOL) prog loadall fork_guard.bpf.o $(PIN_PATH)/fork \
		type tracepoint \
		pinmaps $(PIN_PATH)/fork \
		map name pid_policy_map \
		pinned $(PIN_PATH)/pid_policy_map \
		autoattach
	@# Step 3: Load file_guard, net_guard, proc_guard, each reusing the
	@#          shared pid_policy_map.
	$(BPFTOOL) prog loadall file_guard.bpf.o $(PIN_PATH)/file \
		type lsm \
		pinmaps $(PIN_PATH)/file \
		map name pid_policy_map \
		pinned $(PIN_PATH)/pid_policy_map \
		autoattach
	$(BPFTOOL) prog loadall net_guard.bpf.o $(PIN_PATH)/net \
		type lsm \
		pinmaps $(PIN_PATH)/net \
		map name pid_policy_map \
		pinned $(PIN_PATH)/pid_policy_map \
		autoattach
	$(BPFTOOL) prog loadall proc_guard.bpf.o $(PIN_PATH)/proc \
		type lsm \
		pinmaps $(PIN_PATH)/proc \
		map name pid_policy_map \
		pinned $(PIN_PATH)/pid_policy_map \
		autoattach
	@echo "BPF programs loaded with shared pid_policy_map at $(PIN_PATH)/pid_policy_map"

# Uninstall: detach BPF programs and remove pinned maps
uninstall:
	@echo "Unloading MCPGuard BPF programs..."
	rm -rf $(PIN_PATH)
	@echo "BPF programs unloaded"

clean:
	rm -f $(BPF_OBJS) vmlinux.h
