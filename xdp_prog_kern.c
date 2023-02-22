#include <stddef.h>
#include <stdbool.h>
#include <stdint.h>
#include <zlib.h>

#include <linux/pkt_cls.h>
#include <linux/swab.h>
#include <linux/if_ether.h>
#include <linux/ip.h>
#include <linux/udp.h>
#include <linux/tcp.h>
#include <linux/in.h>

#include <linux/bpf.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_endian.h>


#include "common_kern_user.h"
#include "../common/parsing_helpers.h"
#include "../common/rewrite_helpers.h"

#define bpf_printk(fmt, ...)                                    \
({                                                              \
        char ____fmt[] = fmt;                                   \
        bpf_trace_printk(____fmt, sizeof(____fmt),              \
                         ##__VA_ARGS__);                        \
})

#ifndef lock_xadd
#define lock_xadd(ptr, val)((void) __sync_fetch_and_add(ptr, val))
#endif

struct auth_hdr {
  uint8_t msgType;
  uint32_t challenge1;
  uint32_t challenge2;
  uint64_t randomnumber;
  uint32_t hash;
  uint32_t identifier;
  uint32_t prTime;
};


struct bpf_map_def SEC("maps") cr_db_map = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(struct crPair),
  .max_entries = no_of_IOT,
};

struct bpf_map_def SEC("maps") hashValues = {
  .type = BPF_MAP_TYPE_ARRAY,
  .key_size = sizeof(__u32),
  .value_size = sizeof(__u32),
  .max_entries = no_of_IOT,
};



static __u32 computeHash(uint64_t r1,uint64_t r2,uint64_t rn)
{
    __u64 sum = r1 + r2 + rn;
    __u32 hash = (sum & 0xffffffff) + ((sum >> 32) & 0xffffffff);
    hash += (hash >> 16);
    hash &= 0x0000ffff;
    hash += (hash >> 8);
    hash &= 0x000000ff;
    
    return hash;
}

static uint32_t make_challenge_header(struct auth_hdr* payload)
{
	bpf_printk("Msg type is 0, this is a auth request message");
	
	uint32_t id = payload->identifier - 1;
        
        struct crPair* rec;
        
        uint64_t RN = bpf_get_prandom_u32();
          
        __u32 i = RN%no_of_IOT;
        
        
        rec = bpf_map_lookup_elem(&cr_db_map, &i);
        
        if (!rec)
        {
        	bpf_printk("No such key exist!!\n");
		return 0;
        }
        
        
        
        
        uint32_t c1=rec->ch1;
        uint32_t c2=rec->ch2;
	uint64_t r1=rec->resp1;
	uint64_t r2=rec->resp2;;
	
        
        uint64_t RN1 = (RN ^ (r1 | r2));

        // --------Challenge Header--------------
                
	payload->msgType = 0x1;
	payload->challenge1 = bpf_htonl(c1);
	payload->challenge2 = bpf_htonl(c2);
	payload->randomnumber = bpf_htonl(RN1);
	payload->identifier = bpf_htonl(id+1);
	
	
	uint32_t hash = computeHash(r1,r2,RN);
	
	return hash;
}

static unsigned short ip_checksum(void *vdata, unsigned int length) {
    // Cast the data pointer to a char pointer
    char *data = (char *)vdata;
    
    // Initialize the checksum variable
    unsigned int sum = 0;
    
    // Sum up 16-bit words
    while (length > 1) {
        sum += *(unsigned short *)data;
        data += 2;
        length -= 2;
    }
    
    // Add any remaining byte
    if (length > 0) {
        sum += *(unsigned char *)data;
    }
    
    // Add the carry
    while (sum >> 16) {
        sum = (sum & 0xffff) + (sum >> 16);
    }
    
    // Take the one's complement of the sum
    return (unsigned short)(~sum);
}


SEC("xdp_prog")

int xdp_parsing(struct xdp_md * ctx) {

  // structures for parsing appropriate headers
  struct ethhdr * eth;
  struct iphdr * iph;
  struct udphdr * udph;
    
  void * data_end = (void * )(long) ctx -> data_end;
  void * data = (void * )(long) ctx -> data;
  
  if(data < data_end)
  {
        eth = data;
        if (data + sizeof(*eth) > data_end)
            return XDP_DROP;
	
        if (bpf_htons(eth->h_proto) != 0x0800) {
            return XDP_PASS;
        }

	// it is an IP packet (till here)
        iph = data + sizeof(*eth);
        if (data + sizeof(*eth) + sizeof(*iph) > data_end)
            return XDP_DROP;

        if (iph->protocol != 0x11) 
        {
        	return XDP_PASS;
        }
        else //UDP
        {
           udph = data + sizeof(*eth) + sizeof(*iph);
           if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) > data_end)
               return XDP_DROP;
           bpf_printk("Received UDP packet with src_port=%d, dest_port=%d", bpf_htons(udph->source), bpf_htons(udph->dest));
          
          
           struct auth_hdr *payload = data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph);
           if(data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) +sizeof(*payload) > data_end){
            	return XDP_DROP;
           }

	   // boundary check for payload             
	   if (data + sizeof(*eth) + sizeof(*iph) + sizeof(*udph) + sizeof(*payload) > data_end){
            	return XDP_DROP;
           }
           
           uint8_t msg_type = payload->msgType;
           uint32_t id = payload->identifier - 1;
           
           if(msg_type == 0)
           {
           	uint32_t h = make_challenge_header(payload);
           	if(h == -1)
           		return XDP_ABORTED;
           	else
           	{
           		bpf_map_update_elem(&hashValues,&id,&h,BPF_ANY);
           	}
           	bpf_printk("Sending Challenge packet!!");
           	
           	
           	// Swap the source and destination IP addresses and port numbers.
    		swap_src_dst_ipv4(iph);
    		
    		swap_src_dst_mac(eth);

    		__be16 src_port = udph->source;
    		udph->source = udph->dest;
    		udph->dest = src_port;
    		
    		
    		//set udp checksum to 0 NIC will recalculate checksum
    		udph->check = 0;
    		
    		//recalculate ip checksum
    		iph->check = 0;
    		iph->check = ip_checksum(iph, sizeof(struct iphdr));
    		
    		return XDP_TX;

           }
           
           else if(msg_type == 2)
           {
           	uint32_t h1 = payload->hash;
           	uint32_t* h2 = bpf_map_lookup_elem(&hashValues,&id);
           	
           	if(!h2)
           	{
           		bpf_printk("Unavibale map for hash values");
           		return XDP_ABORTED;
           	}
           		
           	
           	if(h1 == *h2)
           	{
           		payload->msgType = 0x3;
           		payload->identifier = bpf_htonl(id+1);
           		
           		bpf_printk("SUCCESSFUL AUTHENTICATION. Sending ACK!!");
           		
           		// Swap the source and destination IP addresses and port numbers.
    			swap_src_dst_ipv4(iph);
    		
    			swap_src_dst_mac(eth);

    			__be16 src_port = udph->source;
    			udph->source = udph->dest;
    			udph->dest = src_port;
    		
    		
    			//set udp checksum to 0 NIC will recalculate checksum
    			udph->check = 0;
    		
    			//recalculate ip checksum
    			iph->check = 0;
    			iph->check = ip_checksum(iph, sizeof(struct iphdr));
    		
    			return XDP_TX;
           	}
           }
           
           else
           	return XDP_PASS;
        }
  }
  
  else
  {
  	return XDP_DROP;
  }
    
  
  return XDP_PASS;

}
char _license[] SEC("license") = "GPL";
