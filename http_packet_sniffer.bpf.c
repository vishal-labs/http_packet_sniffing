// http_tc.c
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/in.h>
#include <linux/ip.h>
#include <linux/pkt_cls.h>
#include <linux/tcp.h>

SEC("tc")
int http_sniff(struct __sk_buff *skb) {
  // Make sure headers are linear: eth + min IPv4 + min TCP
  if (bpf_skb_pull_data(skb, sizeof(struct ethhdr) + sizeof(struct iphdr) +
                                 sizeof(struct tcphdr)) < 0)
    return TC_ACT_OK;

  void *data = (void *)(long)skb->data;
  void *data_end = (void *)(long)skb->data_end;

  // Ethernet
  if (data + sizeof(struct ethhdr) > data_end)
    return TC_ACT_OK;
  struct ethhdr *eth = data;
  if (eth->h_proto != bpf_htons(ETH_P_IP))
    return TC_ACT_OK;

  // IPv4
  struct iphdr *iph = (void *)(eth + 1);
  if ((void *)(iph + 1) > data_end)
    return TC_ACT_OK;
  if (iph->protocol != IPPROTO_TCP)
    return TC_ACT_OK;

  __u32 ihl = iph->ihl * 4;
  if ((void *)iph + ihl > data_end)
    return TC_ACT_OK;

  // TCP
  struct tcphdr *th = (void *)iph + ihl;
  if ((void *)(th + 1) > data_end)
    return TC_ACT_OK;

  __u16 sport = bpf_ntohs(th->source);
  __u16 dport = bpf_ntohs(th->dest);
  /* Only allow traffic to/from ports 8080 or 8088 */
  if (!(dport == 8000))
    return TC_ACT_OK;

  __u32 doff = th->doff * 4;
  if ((void *)th + doff > data_end)
    return TC_ACT_OK;

  // Compute payload offset/length
  __u32 payload_off = sizeof(struct ethhdr) + ihl + doff;
  __u16 tot_len = bpf_ntohs(iph->tot_len);
  if (tot_len < ihl + doff)
    return TC_ACT_OK;
  __u32 payload_len = tot_len - ihl - doff;
  if (payload_len == 0)
    return TC_ACT_OK;

  // Copy and print the first bytes (e.g., first 64)
  char buf[63];
  __u32 tocopy = payload_len < sizeof(buf) - 1 ? payload_len : sizeof(buf) - 1;
  if (bpf_skb_load_bytes(skb, payload_off, buf, tocopy) < 0)
    return TC_ACT_OK;
  buf[tocopy] = 0;

  bpf_printk("HTTP payload (%u bytes and %d port ): %s", tocopy, sport, buf);
  bpf_printk("=======================================================");

  return TC_ACT_OK;
}

char LICENSE[] SEC("license") = "GPL";
