//go:build ignore

#include "headers/bpf_endian.h"
#include "headers/common.h"
#include "iso8583.h" // Include iso8583.h
#include <stddef.h>

char __license[] SEC("license") = "Dual MIT/GPL";

#define MAX_MAP_ENTRIES 16
#define PORT 8080
#define MAX_MESSAGE_SIZE 1024

struct value_data {
    __u32 countInvalid;
    __u32 countValid;
};

/* Define a hash map for storing packet count by source IPv4 address */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_MAP_ENTRIES);
    __type(key, __u32);               // source IPv4 address
    __type(value, struct value_data); // packet count
} xdp_stats_map SEC(".maps");

// Define ETH_P_8021Q and ETH_P_8021AD
#define ETH_P_8021Q  0x8100          /* 802.1Q VLAN Extended Header  */
#define ETH_P_8021AD 0x88A8          /* 802.1ad Service VLAN        */

#define IPPROTO_TCP     6              /* Transmission Control Protocol */

struct vlan_hdr {
    __be16  h_vlan_TCI;
    __be16  h_vlan_encapsulated_proto;
};

static __always_inline int parse_ethhdr(void **data, void *data_end, __u16 *eth_proto)
{
    struct ethhdr *eth = *data;

    if ((void *)(eth + 1) > data_end)
        return -1;

    *eth_proto = eth->h_proto;
    *data = eth + 1;
    return 0;
}

static __always_inline int parse_vlanhdr(void **data, void *data_end, __u16 *eth_proto)
{
    struct vlan_hdr *vlan_hdr = *data;

    if ((void *)(vlan_hdr + 1) > data_end)
        return -1;

    *eth_proto = vlan_hdr->h_vlan_encapsulated_proto;
    *data = vlan_hdr + 1;
    return 0;
}

static __always_inline int parse_iphdr(void **data, void *data_end, struct iphdr **ip)
{
    struct iphdr *iph = *data;

    if ((void *)(iph + 1) > data_end)
        return -1;

    // Check IP header length
    if (iph->ihl < 5)
        return -1;

    __u32 ip_hdr_len = iph->ihl * 4;
    if ((void *)iph + ip_hdr_len > data_end)
        return -1;

    *ip = iph;
    *data = (void *)iph + ip_hdr_len;
    return 0;
}

static __always_inline int parse_tcphdr(void **data, void *data_end, struct tcphdr **tcp)
{
    struct tcphdr *tcph = *data;

    if ((void *)(tcph + 1) > data_end)
        return -1;

    // Check TCP header length
    if (tcph->doff < 5)
        return -1;

    __u32 tcp_hdr_len = tcph->doff * 4;
    if ((void *)tcph + tcp_hdr_len > data_end)
        return -1;

    *tcp = tcph;
    *data = (void *)tcph + tcp_hdr_len;
    return 0;
}

int str_cmp(const char *str1, const char *str2, int len) {
    for (int i = 0; i < len; i++) {
        if (str1[i] != str2[i]) {
            return 0;
        }
    }
    return 1;
}

SEC("xdp")
int xdp_prog_func(struct xdp_md *ctx)
{
    void *data = (void *)(long)ctx->data;
    void *data_end = (void *)(long)ctx->data_end;
    __u32 ip_src;
    int ret;
    struct value_data *value;

    // Parse the Ethernet header
    __u16 eth_proto;
    ret = parse_ethhdr(&data, data_end, &eth_proto);
    if (ret < 0)
        goto done;

    // Handle VLAN tags if present
    if (eth_proto == bpf_htons(ETH_P_8021Q) || eth_proto == bpf_htons(ETH_P_8021AD)) {
        ret = parse_vlanhdr(&data, data_end, &eth_proto);
        if (ret < 0)
            goto done;
    }

    if (eth_proto != bpf_htons(ETH_P_IP)) {
        // The protocol is not IPv4
        goto done;
    }

    // Parse the IP header
    struct iphdr *ip;
    ret = parse_iphdr(&data, data_end, &ip);
    if (ret < 0)
        goto done;

    ip_src = ip->saddr;

    // Only handle TCP packets
    if (ip->protocol != IPPROTO_TCP)
        goto done;

    // Parse the TCP header
    struct tcphdr *tcp;
    ret = parse_tcphdr(&data, data_end, &tcp);
    if (ret < 0)
        goto done;

    // Check the destination port
    if (bpf_ntohs(tcp->dest) != PORT)
        goto done;


    // Exclude packets with SYN, FIN, RST flags
    if (tcp->syn || tcp->fin || tcp->rst)
        goto done;

    // 'data' now points to the TCP payload
    // Ensure there is enough data for the length field (2 bytes)
    if (data + sizeof(__u16) > data_end)
        goto done;

    // Read the length field
    // __u16 message_size = bpf_ntohs(*(__u16 *)data);
    struct iso8583_message *message = (struct iso8583_message *)data;

    if ((void *)(message + 1) > data_end)
        goto done;

    __u16 message_size = iso8583_parse_size(message);    
    // Ensure message_size is within acceptable bounds
    if (message_size == 0 || message_size > MAX_MESSAGE_SIZE)
        goto done;

    // Ensure there is enough data for the entire message
    if (data + sizeof(__u16) + message_size != data_end)
        goto done;

    // Move data pointer to the start of the ISO8583 message
    data += sizeof(__u16);

    // Now process 'message' as needed
    bpf_printk("Message size: %d\n", message_size);

    // Validate message_type_indicator size is < data_end
    if (data + MTI_SIZE > data_end)
        goto done;

    char mti[MTI_SIZE];

    #pragma clang loop unroll(full)
    for (int i = 0; i < MTI_SIZE; i++) {
        mti[i] = ((char *)data)[i];
    }

    if (str_cmp(mti, "0200", MTI_SIZE)){
        bpf_printk("Transaction Request\n");
    } else if (str_cmp(mti, "0210", MTI_SIZE)){
        bpf_printk("Transaction Response\n");
    } else if (str_cmp(mti, "0400", MTI_SIZE)){
        bpf_printk("Reversal Request\n");
    } else if (str_cmp(mti, "0410", MTI_SIZE)){
        bpf_printk("Reversal Response\n");
    } else {
        bpf_printk("Unknown message type\n");
    }

    // TODO: obtain rule from userpace to filter by enabled fields
    // Implement also the multiple rules capability
    int field_number = 2;
    if(!iso8583_is_field_present(message, field_number)){
        int test = iso8583_is_field_present(message, field_number);
        bpf_printk("Field %d is not present\n", field_number);
        goto done;
    } else {
        bpf_printk("Field %d is present\n", field_number);
    }

    struct iso8583_field field;
    if (iso8583_get_field(message, field_number, &field, data_end) > 0) {
        bpf_printk("Field %d: %.*s\n", field_number, field.length, field.value);
    } else {
        bpf_printk("Failed to get field %d\n", field_number);
    }


    // Update the packet count in the map
    value = bpf_map_lookup_elem(&xdp_stats_map, &ip_src);
    if (value) {
        value->countValid += 1;
    } else {
        struct value_data init_value = {0, 1}; // Initialize countValid to 1
        if (bpf_map_update_elem(&xdp_stats_map, &ip_src, &init_value, BPF_ANY) < 0) {
            // Failed to initialize the map
            goto done;
        }
    }

done:
    // Pass the packet to the next processing stage
    return XDP_PASS;
}
