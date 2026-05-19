// SPDX-License-Identifier: GPL-2.0
/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * MCPGuard Net Guard - BPF LSM program for network access control.
 *
 * Attaches to the socket_connect LSM hook and enforces per-PID network
 * access policies. When a monitored PID attempts to connect to a remote
 * address, this program checks whether the destination matches any
 * allowed network rule in the process's policy.
 *
 * Design:
 *   1. On socket_connect, get the calling PID
 *   2. Look up PID in pid_policy_map to find policy_id
 *   3. If no policy, allow (unmonitored process)
 *   4. Look up policy_id in net_policy_map to find allowed destinations
 *   5. Extract destination address and port from sockaddr
 *   6. Compare against each allowed destination rule
 *   7. If no match, return -EACCES to deny the connection
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
  __type(value, struct net_policy);
} net_policy_map SEC(".maps");

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 256 * 1024); /* 256KB ring buffer */
} audit_events SEC(".maps");

/* Scratch space for audit event (288B > comfortable stack margin).
 * Uses ARRAY instead of PERCPU_ARRAY: sleepable BPF programs cannot
 * use PERCPU maps. The race window is acceptable for this experiment. */
struct {
  __uint(type, BPF_MAP_TYPE_ARRAY);
  __uint(max_entries, 1);
  __type(key, __u32);
  __type(value, struct audit_event);
} heap SEC(".maps");

/* -----------------------------------------------------------------------
 * LSM Hook: socket_connect
 * ----------------------------------------------------------------------- */

SEC("lsm.s/socket_connect")
int BPF_PROG(
    net_guard_connect,
    struct socket* sock,
    struct sockaddr* address,
    int addrlen,
    int ret) {
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

  /* Look up network policy */
  struct net_policy* npol = bpf_map_lookup_elem(&net_policy_map, &pol_id);
  if (!npol) {
    /* No network policy = deny all for monitored PIDs */
    goto deny;
  }

  /* Only handle AF_INET for now */
  __u16 family;
  BPF_CORE_READ_INTO(&family, address, sa_family);
  if (family != 2) /* AF_INET = 2 */
    return 0; /* Allow non-IPv4 (e.g., AF_UNIX) */

  struct sockaddr_in* sin = (struct sockaddr_in*)address;
  __u32 dst_addr = 0;
  __u16 dst_port = 0;
  BPF_CORE_READ_INTO(&dst_addr, sin, sin_addr.s_addr);
  BPF_CORE_READ_INTO(&dst_port, sin, sin_port);

  /* Check destination against allowed rules. */
  __u32 rule_count = npol->rule_count;
  if (rule_count > MAX_NET_RULES)
    rule_count = MAX_NET_RULES;

  for (__u32 i = 0; i < MAX_NET_RULES; i++) {
    if (i >= rule_count)
      break;
    struct net_rule* rule = &npol->rules[i];
    if (rule->addr == dst_addr || rule->addr == 0) {
      if (rule->port == dst_port || rule->port == 0) {
        if (rule->allow)
          return 0; /* allowed */
      }
    }
  }

deny:;
  /* Emit audit event via ringbuf */
  struct audit_event* evt =
      bpf_ringbuf_reserve(&audit_events, sizeof(struct audit_event), 0);
  if (evt) {
    evt->pid = pid;
    evt->tgid = bpf_get_current_pid_tgid() & 0xFFFFFFFF;
    evt->event_type = EVENT_NET;
    evt->action = ACTION_DENIED;
    bpf_get_current_comm(&evt->comm, sizeof(evt->comm));

    /* Store raw address bytes in detail for userspace to decode */
    __builtin_memset(evt->detail, 0, MAX_PATH_LEN);
    /* Store 4 bytes of IP + 2 bytes of port at start of detail */
    __builtin_memcpy(evt->detail, &dst_addr, 4);
    __builtin_memcpy(evt->detail + 4, &dst_port, 2);

    bpf_ringbuf_submit(evt, 0);
  }

  return -1; /* -EACCES */
}
