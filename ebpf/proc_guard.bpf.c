// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * MCPGuard Proc Guard - BPF LSM program for process/exec control.
 *
 * Attaches to the bprm_check_security LSM hook and enforces per-PID
 * process execution policies. When a monitored PID attempts to exec
 * a new binary, this program checks whether the binary path is in the
 * process's allowed executables list.
 *
 * Design:
 *   1. On bprm_check_security, get the calling PID
 *   2. Look up PID in pid_policy_map to find policy_id
 *   3. If no policy, allow (unmonitored process)
 *   4. Look up policy_id in exec_policy_map to find allowed executables
 *   5. Read the binary path from linux_binprm->filename
 *   6. Compare against each allowed executable rule
 *   7. If no match, return -EACCES to deny the exec
 *   8. Emit an audit event via perf buffer
 */

#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
#include "vmlinux.h"

char LICENSE[] SEC("license") = "GPL";

/* -----------------------------------------------------------------------
 * BPF Maps
 * ----------------------------------------------------------------------- */

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, MAX_PIDS);
  __type(key, __u32);
  __type(value, struct pid_policy_entry);
} pid_policy_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, policy_id_t);
  __type(value, struct exec_policy);
} exec_policy_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} audit_events SEC(".maps");

/* Scratch space to avoid exceeding 512-byte stack limit.
 * Uses ARRAY instead of PERCPU_ARRAY: sleepable BPF programs cannot
 * use PERCPU maps. The race window is acceptable for this experiment. */
struct scratch {
  char filename[MAX_PATH_LEN];
  struct audit_event evt;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct scratch);
} heap SEC(".maps");

/* -----------------------------------------------------------------------
 * Helper: bounded string equality
 * ----------------------------------------------------------------------- */

/*
 * Bound the per-rule comparison to EXEC_CMP_LEN characters rather than the
 * full MAX_PATH_LEN. MAX_PATH_LEN (256) x MAX_EXEC_RULES (16) exceeds the
 * BPF verifier's jump-complexity budget on kernel 6.16 ("sequence of jumps
 * too complex"), even though it verified on the 6.9 kernel used in the
 * original evaluation. Executable paths are short (e.g. /usr/bin/python3),
 * so a 64-char bound preserves matching for all realistic binaries; two
 * binaries sharing a 64-char path prefix would be indistinguishable, which
 * does not occur for standard interpreter/binary paths.
 */
#define EXEC_CMP_LEN 64
static __always_inline int str_eq(const char* a, const char* b) {
  for (int i = 0; i < EXEC_CMP_LEN; i++) {
    if (a[i] != b[i])
      return 0;
    if (a[i] == '\0')
      return 1; /* both ended at same position */
  }
  return 1;
}

/* -----------------------------------------------------------------------
 * LSM Hook: bprm_check_security
 * ----------------------------------------------------------------------- */

SEC("lsm.s/bprm_check_security")
int BPF_PROG(proc_guard_exec, struct linux_binprm* bprm, int ret) {
  /* If a previous LSM already denied, respect that */
  if (ret != 0)
    return ret;

  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  /* Look up PID policy */
  struct pid_policy_entry* entry = bpf_map_lookup_elem(&pid_policy_map, &pid);
  if (!entry) {
    return 0; /* PID not monitored */
  }

  policy_id_t pol_id = entry->policy_id;

  /* Look up exec policy */
  struct exec_policy* epol = bpf_map_lookup_elem(&exec_policy_map, &pol_id);
  if (!epol) {
    /* No exec policy = deny all exec for monitored PIDs */
    return -1;
  }

  /* Obtain per-CPU scratch space */
  __u32 zero = 0;
  struct scratch* s = bpf_map_lookup_elem(&heap, &zero);
  if (!s)
    return -1;

  /* Read the binary path from bprm->filename. */
  const char* fname;
  BPF_CORE_READ_INTO(&fname, bprm, filename);
  bpf_probe_read_kernel_str(s->filename, sizeof(s->filename), fname);

  /* Check binary against allowed executables. */
  __u32 rule_count = epol->rule_count;
  if (rule_count > MAX_EXEC_RULES)
    rule_count = MAX_EXEC_RULES;

  for (__u32 i = 0; i < MAX_EXEC_RULES; i++) {
    if (i >= rule_count)
      break;
    struct exec_rule* rule = &epol->rules[i];
    if (rule->allow && str_eq(s->filename, rule->binary_path))
      return 0; /* allowed */
  }

  /* No match: deny and audit via ringbuf */
  struct audit_event* evt =
      bpf_ringbuf_reserve(&audit_events, sizeof(struct audit_event), 0);
  if (evt) {
    evt->pid = pid;
    evt->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt->event_type = EVENT_EXEC;
    evt->action = ACTION_DENIED;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    __builtin_memcpy(evt->detail, s->filename, MAX_PATH_LEN);
    bpf_ringbuf_submit(evt, 0);
  }

  return -1; /* -EACCES */
}
