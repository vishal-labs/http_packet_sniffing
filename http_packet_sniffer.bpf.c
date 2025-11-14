#include <linux/bpf.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/tcp.h>
#include <linux/in.h>          
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>    


char LICENSE[] SEC("license") = "GPL";

static __always_inline int parse_ipv4_tcp(void *data, void *data_end,
                                          struct iphdr **iph, struct tcphdr **tcph,
                                          int *l4_off)
{
    struct ethhdr *eth = data;
    if ((void *)(eth + 1) > data_end) return -1;
    if (eth->h_proto != __bpf_htons(ETH_P_IP)) return -1;

    struct iphdr *ip = (void *)(eth + 1);
    if ((void *)(ip + 1) > data_end) return -1;
    if (ip->protocol != IPPROTO_TCP) return -1;

    int ihl = ip->ihl * 4;
    if (ihl < sizeof(*ip)) return -1;
    struct tcphdr *tcp = (void *)ip + ihl;
    if ((void *)(tcp + 1) > data_end) return -1;

    *iph = ip;
    *tcph = tcp;
    *l4_off = (void *)tcp - data;
    return 0;
}

SEC("tc")
int http_lo_8000(struct __sk_buff *skb)
{
    void *data = (void *)(long)skb->data;
    void *data_end = (void *)(long)skb->data_end;

    struct iphdr *ip;
    struct tcphdr *tcp;
    int tcp_off;

    if (parse_ipv4_tcp(data, data_end, &ip, &tcp, &tcp_off) < 0)
        return BPF_OK;

    // Only loopback (127.0.0.0/8) traffic
    if ((ip->saddr & __bpf_htonl(0xFF000000)) != __bpf_htonl(0x7F000000) ||
        (ip->daddr & __bpf_htonl(0xFF000000)) != __bpf_htonl(0x7F000000))
        return BPF_OK;

    // Ports (host order)
    __u16 sport = __bpf_ntohs(tcp->source);
    __u16 dport = __bpf_ntohs(tcp->dest);

    // Filter localhost:8000 traffic either direction
    if (sport != 8000 && dport != 8000)
        return BPF_OK;

    int doff = tcp->doff * 4;
    if (doff < sizeof(*tcp)) return BPF_OK;

    int l3_off = (void *)ip - data;
    int ihl = ip->ihl * 4;

    int payload_off = l3_off + ihl + doff;
    if (payload_off >= (int) (skb->len)) return BPF_OK;

    // Payload length from IP total length
    __u16 tlen = __bpf_ntohs(ip->tot_len);
    int payload_len = (int)tlen - ihl - doff;
    if (payload_len <= 0) return BPF_OK;

    // Read up to first 128 bytes to print first lines
    int copy_len = payload_len < 128 ? payload_len : 128;

    // Small stack buffer; verifier-friendly bounded loop
    char buf[128] = {};
    // Use helper to read linear bytes from skb starting at payload offset
    if (bpf_skb_load_bytes(skb, payload_off, buf, copy_len) < 0)
        return BPF_OK;

    // Print header line: "HTTP payload (N bytes and PORT port ):"
    // Note: show opposite endpoint port (client) if server is 8000.
    __u16 peer_port = (dport == 8000) ? sport : dport;

    bpf_printk("HTTP payload (%d bytes and %d port ):", payload_len, peer_port);
    // Print first line(s) as ASCII; print two lines if CRLFs present.
    // For simplicity, emit the buffer as-is; trace viewer shows lines.
    // Ensure it’s NUL-terminated for safe %s usage.
    if (copy_len < 128) buf[copy_len] = '\0';
    else buf[127] = '\0';

    // Try to split visually: print first line up to newline if any.
    // Verifier doesn’t allow parsing loops easily; just print buffer,
    // then the next 64 bytes as a second line slice.
    bpf_printk("%s", buf);
    if (copy_len > 64) {
        char buf2[65] = {};
        __builtin_memcpy(buf2, buf + 64, 64);
        buf2[64] = '\0';
        bpf_printk("%s", buf2);
    }

    return BPF_OK; // direct-action passthrough
}
