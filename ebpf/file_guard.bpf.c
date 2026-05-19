// SPDX-License-Identifier: GPL-2.0
/*
 * MCPGuard File Guard - BPF LSM program for file access control.
 *
 * Attaches to the file_open LSM hook and enforces per-PID file access
 * policies. When a monitored PID (MCP server process) opens a file,
 * this program checks whether the file path matches any allowed prefix
 * in the process's policy. If not, the open is denied.
 *
 * Design:
 *   1. On file_open, get the calling PID
 *   2. Look up PID in pid_policy_map to find policy_id
 *   3. If no policy, allow (unmonitored process)
 *   4. Look up policy_id in file_policy_map to find allowed paths
 *   5. Read the file path from the file struct
 *   6. Compare against each allowed prefix
 *   7. If no match, return -EACCES to deny the open
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
  __type(key, __u32); /* PID */
  __type(value, struct pid_policy_entry);
} pid_policy_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_HASH);
  __uint(max_entries, 64);
  __type(key, policy_id_t);
  __type(value, struct file_policy);
} file_policy_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} audit_events SEC(".maps");

/* Scratch space to avoid exceeding 512-byte stack limit.
 * path_buf (256B) + audit_event (288B) = 544B > 512B stack limit.
 * Uses ARRAY instead of PERCPU_ARRAY: sleepable BPF programs cannot
 * use PERCPU maps. The race window is acceptable for this experiment. */
struct scratch {
  char path_buf[MAX_PATH_LEN];
  struct audit_event evt;
};

struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct scratch);
} heap SEC(".maps");

/* -----------------------------------------------------------------------
 * Helper: compare path against prefix
 * ----------------------------------------------------------------------- */

static __always_inline int path_starts_with(
    const char* path,
    const char* prefix) {
  /* Bounded string prefix comparison for BPF verifier. */
  for (int i = 0; i < MAX_PATH_LEN; i++) {
    if (prefix[i] == '\0')
      return 1; /* prefix ended = match */
    if (path[i] != prefix[i])
      return 0; /* mismatch */
  }
  return 1;
}

/* -----------------------------------------------------------------------
 * LSM Hook: file_open
 * ----------------------------------------------------------------------- */

SEC("lsm.s/file_open")
int BPF_PROG(file_guard_open, struct file* file, int ret) {
  /* If a previous LSM already denied, respect that */
  if (ret != 0)
    return ret;

  __u32 pid = bpf_get_current_pid_tgid() >> 32;

  /* Look up PID policy */
  struct pid_policy_entry* entry = bpf_map_lookup_elem(&pid_policy_map, &pid);
  if (!entry) {
    /* PID not monitored, allow */
    return 0;
  }

  policy_id_t pol_id = entry->policy_id;

  /* Look up file policy */
  struct file_policy* fpol = bpf_map_lookup_elem(&file_policy_map, &pol_id);
  if (!fpol) {
    /* No file policy defined, deny by default for monitored PIDs */
    return -1;
  }

  /* Obtain per-CPU scratch space */
  __u32 zero = 0;
  struct scratch* s = bpf_map_lookup_elem(&heap, &zero);
  if (!s)
    return -1;

  /* Read the file path using bpf_d_path (available since kernel 5.10). */
  int path_len = bpf_d_path(&file->f_path, s->path_buf, MAX_PATH_LEN);
  if (path_len < 0) {
    /* Cannot read path; deny for safety */
    goto deny;
  }

  /* Determine whether this is a write open.
   * f_mode bit 1 = FMODE_WRITE. */
  unsigned int fmode = 0;
  BPF_CORE_READ_INTO(&fmode, file, f_mode);
  int is_write = fmode & 2;

  /* Check path against allowed prefixes (first match wins).
   * For the matching rule, verify the appropriate permission flag. */
  __u32 rule_count = fpol->rule_count;
  if (rule_count > MAX_PATH_RULES)
    rule_count = MAX_PATH_RULES;

  for (__u32 i = 0; i < MAX_PATH_RULES; i++) {
    if (i >= rule_count)
      break;
    if (path_starts_with(s->path_buf, fpol->rules[i].path_prefix)) {
      if (is_write && !fpol->rules[i].allow_write)
        goto deny;
      if (!is_write && !fpol->rules[i].allow_read)
        goto deny;
      return 0; /* allowed */
    }
  }

  /* No matching rule — deny */

deny:;
  /* Emit audit event via ringbuf */
  struct audit_event* evt =
      bpf_ringbuf_reserve(&audit_events, sizeof(struct audit_event), 0);
  if (evt) {
    evt->pid = pid;
    evt->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt->event_type = EVENT_FILE;
    evt->action = ACTION_DENIED;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));
    __builtin_memcpy(evt->detail, s->path_buf, MAX_PATH_LEN);
    bpf_ringbuf_submit(evt, 0);
  }

  return -1; /* -EACCES */
}
