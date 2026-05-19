/* SPDX-License-Identifier: GPL-2.0 */
/* Copyright (c) Meta Platforms, Inc. and affiliates. */
/*
 * MCPGuard eBPF Common Definitions
 *
 * Shared BPF map definitions and data structures used across
 * file_guard, net_guard, proc_guard, and fork_guard BPF LSM programs.
 */

#ifndef __MCPGUARD_COMMON_H
#define __MCPGUARD_COMMON_H

/* Do not include <linux/types.h> here; vmlinux.h provides all kernel
 * type definitions (__u8, __u16, __u32, etc.) and including the kernel
 * header would cause duplicate typedef errors. */

/* Maximum path prefix length stored in BPF maps */
#define MAX_PATH_LEN 256

/* Maximum number of monitored PIDs */
#define MAX_PIDS 1024

/* Maximum number of allowed path prefixes per policy */
#define MAX_PATH_RULES 32

/* Maximum number of allowed network destinations per policy */
#define MAX_NET_RULES 16

/* Maximum number of allowed executables per policy */
#define MAX_EXEC_RULES 16

/* Policy ID type */
typedef __u32 policy_id_t;

/* -----------------------------------------------------------------------
 * Data structures
 * ----------------------------------------------------------------------- */

/* Maps a PID to its policy ID */
struct pid_policy_entry {
  policy_id_t policy_id;
  __u32 flags; /* Reserved for future use */
};

/* File access policy rule */
struct file_rule {
  char path_prefix[MAX_PATH_LEN];
  __u8 allow_read;
  __u8 allow_write;
  __u8 allow_exec;
  __u8 _pad;
};

/* Network access policy rule */
struct net_rule {
  __u32 addr; /* IPv4 address in network byte order */
  __u16 port; /* Port in network byte order, 0 = any */
  __u8 proto; /* IPPROTO_TCP or IPPROTO_UDP */
  __u8 allow; /* 1 = allow, 0 = deny */
};

/* Process execution policy rule */
struct exec_rule {
  char binary_path[MAX_PATH_LEN];
  __u8 allow;
  __u8 _pad[3];
};

/* File policy: array of file rules for a policy_id */
struct file_policy {
  struct file_rule rules[MAX_PATH_RULES];
  __u32 rule_count;
};

/* Network policy: array of net rules for a policy_id */
struct net_policy {
  struct net_rule rules[MAX_NET_RULES];
  __u32 rule_count;
};

/* Exec policy: array of exec rules for a policy_id */
struct exec_policy {
  struct exec_rule rules[MAX_EXEC_RULES];
  __u32 rule_count;
};

/* Audit event sent to userspace via perf buffer */
struct audit_event {
  __u32 pid;
  __u32 tgid;
  __u32 event_type; /* 1=file, 2=net, 3=exec, 4=fork */
  __u32 action; /* 0=denied, 1=allowed */
  char comm[16];
  char detail[MAX_PATH_LEN];
};

/* Event types */
#define EVENT_FILE 1
#define EVENT_NET 2
#define EVENT_EXEC 3
#define EVENT_FORK 4

/* Actions */
#define ACTION_DENIED 0
#define ACTION_ALLOWED 1

/* -----------------------------------------------------------------------
 * BPF Map declarations (used in all four guards)
 *
 * These maps are pinned to /sys/fs/bpf/mcpguard/ so that the userspace
 * proxy can update policies at runtime.
 * ----------------------------------------------------------------------- */

/*
 * pid_policy_map: PID -> pid_policy_entry
 * Looked up on every LSM hook to find the policy for the calling process.
 */

/*
 * file_policy_map: policy_id -> file_policy
 * Contains allowed file path prefixes for each policy.
 */

/*
 * net_policy_map: policy_id -> net_policy
 * Contains allowed network destinations for each policy.
 */

/*
 * exec_policy_map: policy_id -> exec_policy
 * Contains allowed executables for each policy.
 */

/*
 * audit_events: ring buffer (BPF_MAP_TYPE_RINGBUF)
 * Sends audit events to userspace for logging and alerting.
 * Changed from PERF_EVENT_ARRAY to RINGBUF for sleepable BPF compatibility.
 */

#endif /* __MCPGUARD_COMMON_H */
