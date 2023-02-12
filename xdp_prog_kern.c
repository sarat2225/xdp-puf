#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>

#include <linux/bpf.h>
#include <linux/in.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>

// The parsing helper functions from the packet01 lesson have moved here
#include "../common/parsing_helpers.h"

#include "common_kern_user.h"

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

#ifndef lock_xadd
#define lock_xadd(ptr, val)((void) __sync_fetch_and_add(ptr, val))
#endif

struct bpf_map_def SEC("maps") cr_db_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct UAV_CR_DB),
  .max_entries = no_of_IOT,
};

SEC("xdp_prog")
int xdp_parsing(struct xdp_md * ctx) {

  // structures for parsing appropriate headers
  int eth_type, ip_type=0;
  struct ethhdr * eth;
  struct iphdr * iphdr;
  struct ipv6hdr * ipv6hdr;
  struct udphdr * udphdr;
  struct tcphdr * tcphdr;
  struct icmphdr * icmphdr;
  struct icmp6hdr * icmp6hdr;
  struct collect_vlans vlans;
  
  __u32 key = 200;
  struct UAV_CR_DB* rec;
  rec = bpf_map_lookup_elem(&cr_db_map, &key);
  
  if (!rec)
  {
  	bpf_printk("doesn't exist yet\n");
	return XDP_ABORTED;
  }
  
  else
  {
  	bpf_printk("%u %llu",rec->crp[200].ch1,rec->crp[200].resp1);
  }

  void * data_end = (void * )(long) ctx -> data_end;
  void * data = (void * )(long) ctx -> data;
  struct hdr_cursor nh = {
    .pos = data
  };

  eth_type = parse_ethhdr_vlan( & nh, data_end, & eth, & vlans);
  if (eth_type < 0) {
    return XDP_ABORTED;
  }
  if (eth_type == bpf_htons(ETH_P_IP)) {
    ip_type = parse_iphdr( & nh, data_end, & iphdr);
  } 
  else if (eth_type == bpf_htons(ETH_P_IPV6)) 
  {
    ip_type = parse_ip6hdr( & nh, data_end, & ipv6hdr);
  }
  
  if (ip_type == IPPROTO_UDP) 
  {
    if (parse_udphdr( & nh, data_end, & udphdr) < 0) {
      return XDP_ABORTED;
    }
    udphdr -> dest = bpf_htons(bpf_ntohs(udphdr -> dest) - 1);
  }
  
  else if (ip_type == IPPROTO_TCP) 
  {

    if (parse_tcphdr( & nh, data_end, & tcphdr) < 0) {
      return XDP_ABORTED;
    }
    tcphdr -> dest = bpf_htons(bpf_ntohs(tcphdr -> dest) - 1);
  }
  
  else if (ip_type == IPPROTO_ICMP) 
  {

    if (parse_icmphdr( & nh, data_end, & icmphdr) < 0)
      return XDP_ABORTED;
  }

  else if (ip_type == IPPROTO_ICMPV6) 
  {

    if (parse_icmp6hdr( & nh, data_end, & icmp6hdr) < 0)
      return XDP_ABORTED;

  }
  
  return XDP_PASS;

}
char _license[] SEC("license") = "GPL";
