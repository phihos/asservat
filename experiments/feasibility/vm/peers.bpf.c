// Isolated experiment: a TCX observer, never drops or redirects workload traffic.
// SPDX-License-Identifier: Apache-2.0
#include <linux/bpf.h>
#include <linux/pkt_cls.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>
struct inner { __uint(type,BPF_MAP_TYPE_HASH); __uint(max_entries,64); __type(key,__u32); __type(value,__u32); };
struct { __uint(type,BPF_MAP_TYPE_ARRAY_OF_MAPS); __uint(max_entries,1); __type(key,__u32); __array(values,struct inner); } peers SEC(".maps");
struct { __uint(type,BPF_MAP_TYPE_ARRAY); __uint(max_entries,128); __type(key,__u32); __type(value,__u64); } counts SEC(".maps");
SEC("tc") int observe(struct __sk_buff *skb){
 void *data=(void *)(long)skb->data,*end=(void *)(long)skb->data_end;
 struct ethhdr *eth=data;if((void *)(eth+1)>end||eth->h_proto!=bpf_htons(ETH_P_IP))return TC_ACT_OK;
 struct iphdr *ip=(void *)(eth+1);if((void *)(ip+1)>end||ip->ihl!=5||ip->protocol!=17)return TC_ACT_OK;
 struct udphdr *udp=(void *)(ip+1);if((void *)(udp+1)>end||udp->dest!=bpf_htons(58888))return TC_ACT_OK;
 __u32 zero=0;void *m=bpf_map_lookup_elem(&peers,&zero);if(!m)return TC_ACT_OK;
 __u32 address=ip->saddr;__u32 *generation=bpf_map_lookup_elem(m,&address);
 if(!generation){address=ip->daddr;generation=bpf_map_lookup_elem(m,&address);}
 if(generation){__u32 g=*generation;__u64 *n=bpf_map_lookup_elem(&counts,&g);if(n)__sync_fetch_and_add(n,1);}
 return TC_ACT_OK;
}
char LICENSE[] SEC("license")="Dual BSD/GPL";
