//go:build ignore

#include "common.h"

#include "bpf_endian.h"
#include "bpf_tracing.h"

#define AF_INET 2 /* Internet IP Protocol 	*/
#define TASK_COMM_LEN 16

#define TCP_ESTABLISHED 1
#define TCP_CLOSE 7

char __license[] SEC("license") = "Dual MIT/GPL";

/**
 * struct sock_common reflects the start of the kernel's struct sock_common.
 * It only contains the fields up until skc_family that are accessed in the
 * program, with padding to match the kernel's declaration.
 */
struct sock_common {
  union {
    struct {
      __be32 skc_daddr;     // Foreign IPv4 addr
      __be32 skc_rcv_saddr; // Bound local IPv4 addr
    };
  };
  union {
    // Padding out union skc_hash.
    __u32 _;
  };
  union {
    struct {
      __be16 skc_dport; // placeholder for inet_dport/tw_dport
      __u16 skc_num;    // placeholder for inet_num/tw_num
    };
  };
  short unsigned int skc_family; // network address family
  unsigned char skc_state;
};

/**
 * struct sock reflects the start of the kernel's struct sock.
 */
struct sock {
  struct sock_common __sk_common;
};

struct {
  __uint(type, BPF_MAP_TYPE_RINGBUF);
  __uint(max_entries, 1 << 24);
} events SEC(".maps");

/**
 * The sample submitted to userspace over a ring buffer.
 * Emit struct event's type info into the ELF's BTF so bpf2go
 * can generate a Go type from it.
 */
struct event {
  u8 comm[16];
  __u16 sport;
  __be16 dport;
  __be32 saddr;
  __be32 daddr;
  u8 state;
};
struct event *unused __attribute__((unused));

SEC("fentry/tcp_set_state")
int BPF_PROG(tcp_set_state, struct sock *sk, int state) {
  if (sk->__sk_common.skc_family != AF_INET) {
    return 0;
  }

	if (state != TCP_ESTABLISHED && state != TCP_CLOSE){
		return 0;
	}

  struct event *tcp_info;
  tcp_info = bpf_ringbuf_reserve(&events, sizeof(struct event), 0);
  if (!tcp_info) {
    return 0;
  }

  tcp_info->saddr = sk->__sk_common.skc_rcv_saddr;
  tcp_info->daddr = sk->__sk_common.skc_daddr;
  tcp_info->dport = sk->__sk_common.skc_dport;
  tcp_info->sport = bpf_htons(sk->__sk_common.skc_num);
  tcp_info->state = state;

  bpf_get_current_comm(&tcp_info->comm, TASK_COMM_LEN);

  bpf_ringbuf_submit(tcp_info, 0);

  return 0;
}
