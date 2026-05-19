// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * MCPGuard Fork Guard - BPF LSM program for child process tracking.
 *
 * Attaches to the task_alloc LSM hook and automatically propagates
 * sandbox policies from parent to child processes. Without this,
 * a monitored server can escape the sandbox by forking a child
 * process (e.g., via os.system() or subprocess.Popen()) whose PID
 * is not in the pid_policy_map, causing file_guard, net_guard, and
 * proc_guard to allow all operations for that child.
 *
 * Design:
 *   1. On task_alloc, get the parent PID from the current task
 *   2. Look up the parent PID in pid_policy_map
 *   3. If the parent is monitored, read the child PID from the new task
 *   4. Insert the child PID into pid_policy_map with the same policy_id
 *   5. Since pid_policy_map is shared across all four programs (via
 *      bpftool map pinning), file_guard/net_guard/proc_guard immediately
 *      see the child PID and enforce the parent's policy on it
 *   6. Always return 0 (allow the fork -- we track, not block)
 *   7. Emit an audit event for child tracking
 */

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
#include "vmlinux.h"

char LICENSE[] SEC("license") = "GPL";

/* -----------------------------------------------------------------------
 * BPF Maps
 *
 * pid_policy_map is shared across all four guard programs via bpftool
 * pinned map reuse. When fork_guard inserts a child PID here,
 * file_guard, net_guard, and proc_guard immediately see it.
 * ----------------------------------------------------------------------- */

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_PIDS);
  __type(key, __u32); /* PID */
  __type(value, struct pid_policy_entry);
} pid_policy_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} audit_events SEC(".maps");

/* -----------------------------------------------------------------------
 * LSM Hook: task_alloc
 *
 * Called when a new task (process/thread) is being created.
 * Arguments:
 *   task         - the NEW child task_struct
 *   clone_flags  - flags passed to clone/fork
 *   ret          - return value from prior LSM hooks (0 = allowed so far)
 *
 * The current context (bpf_get_current_pid_tgid) is the PARENT process.
 * ----------------------------------------------------------------------- */

SEC("tp/sched/sched_process_fork")
int fork_guard_sched_fork(struct trace_event_raw_sched_process_fork* ctx) {
  /* Get parent and child PIDs from the tracepoint args.
   * sched_process_fork fires AFTER the child PID is assigned,
   * so parent_pid and child_pid are both valid here. */
  __u32 parent_pid = ctx->parent_pid;
  __u32 child_pid = ctx->child_pid;

  /* Look up parent in pid_policy_map */
  struct pid_policy_entry* parent_entry =
      bpf_map_lookup_elem(&pid_policy_map, &parent_pid);
  if (!parent_entry) {
    return 0;
  }

  /* Skip if child PID is 0 or same as parent */
  if (child_pid == 0 || child_pid == parent_pid)
    return 0;

  /* Build the child's policy entry with the same policy_id as the parent */
  struct pid_policy_entry child_entry = {
      .policy_id = parent_entry->policy_id,
      .flags = parent_entry->flags,
  };

  /* Insert child PID into the shared pid_policy_map.
   * BPF_NOEXIST flag: only insert if not already present (avoid
   * overwriting if child PID was already monitored for some reason). */
  bpf_map_update_elem(&pid_policy_map, &child_pid, &child_entry, BPF_NOEXIST);

  /* Emit audit event for child process tracking */
  struct audit_event* evt =
      bpf_ringbuf_reserve(&audit_events, sizeof(struct audit_event), 0);
  if (evt) {
    evt->pid = child_pid;
    evt->tgid = parent_pid;
    evt->event_type = EVENT_FORK;
    evt->action = ACTION_ALLOWED;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* Store parent PID and child PID in detail for userspace logging */
    __builtin_memset(evt->detail, 0, MAX_PATH_LEN);
    /* Format: "parent=<pid> child=<pid>" stored as raw bytes */
    __builtin_memcpy(evt->detail, &parent_pid, 4);
    __builtin_memcpy(evt->detail + 4, &child_pid, 4);

    bpf_ringbuf_submit(evt, 0);
  }

  /* Always allow the fork -- we are tracking, not blocking */
  return 0;
}
