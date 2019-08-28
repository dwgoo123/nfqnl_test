#include <stdlib.h>
#include <string.h>

#include "packet.h"


struct IP_header ip_header;
struct TCP_header tcp;
//struct http_data payload;

char *target;
int boolean = 0;

/*
void http_print(unsigned char* packet){
    memcpy(payload.data, packet, 0x30);
}
*/
#pragma pack(push, 1)
void ip_print(const u_char* packet){
    uint8_t val_v_len = *packet;
    ip_header.version = (val_v_len & 0xF0)>>4;
    ip_header.hdr_len = (val_v_len & 0x0F) * 4;
    ip_header.dscp = *(packet=packet+1);
    ip_header.totallength = *(packet=packet+1) << 8 | *(packet=packet+1);
    ip_header.identification = *(packet=packet+1) << 8 | *(packet=packet+1);
    ip_header.flags = *(packet=packet+1) << 8 | *(packet=packet+1);
    ip_header.ttl = *(packet=packet+1);
    ip_header.protocol = *(packet=packet+1);
    ip_header.checksum = *(packet=packet+1) << 8 | *(packet=packet+1);
    memcpy(ip_header.sIP, (packet=packet+1), 4);
    memcpy(ip_header.dIP, (packet=packet+4), 4);
    //ntohl(&ip_header.sIP);
    if(ip_header.version == 4){
        printf("IP Version : %02x\n",ip_header.version);
        printf("Total Header Length : %d\n",ip_header.totallength);
        if(ip_header.protocol == 0x6){
            printf("Protocol : TCP\n");
            printf("Source IP :");
            for(int i=0;i<4;i++){
                if(i<3)
                    printf("%d.",ip_header.sIP[i]);
                else
                    printf("%d\n",ip_header.sIP[i]);
            }
            printf("Destination IP :");
            for(int i=0;i<4;i++){
                if(i<3)
                    printf("%d.",ip_header.dIP[i]);
                else
                    printf("%d\n",ip_header.dIP[i]);

            }
            printf("IP header length: %d\n", ip_header.hdr_len);
        }//tcp
    }

}

void tcp_print(unsigned char* packet){
    tcp.sPort = *(packet) << 8 | *(packet=packet+1);
    tcp.dPort = *(packet=packet+1) << 8 | *(packet=packet+1);
    memcpy(&tcp.sequence, (packet=packet+1), 4);
    memcpy(&tcp.acknowledge, (packet=packet+4), 4);
    uint8_t val_v_len = *(packet=packet+4);
    //length 8, flags 0x018 ...
    tcp.hdr_len = ((val_v_len & 0xF0) >> 4 )*4;
    tcp.flags = (val_v_len & 0x0F) * 4 | *(packet=packet+1);
    tcp.windowsize =  *(packet=packet+1) << 8 | *(packet=packet+1);
    tcp.checksum = *(packet=packet+1) << 8 | *(packet=packet+1);
    tcp.urgentPointer = *(packet=packet+1) << 8 | *(packet=packet+1);
}

static u_int32_t print_pkt (struct nfq_q_handle* qh, struct nfq_data *tb)
{
    int id = 0;
    int boolean = 0;
    struct nfqnl_msg_packet_hdr *ph;
    struct nfqnl_msg_packet_hw *hwph;
    u_int32_t mark,ifi;
    int ret;
    unsigned char *data;

    ph = nfq_get_msg_packet_hdr(tb);
    if (ph) {
        id = ntohl(ph->packet_id);
        printf("hw_protocol=0x%04x hook=%u id=%u ",
            ntohs(ph->hw_protocol), ph->hook, id);
    }

    hwph = nfq_get_packet_hw(tb);
    if (hwph) {
        int i, hlen = ntohs(hwph->hw_addrlen);

        printf("hw_src_addr=");
        for (i = 0; i < hlen-1; i++)
            printf("%02x:", hwph->hw_addr[i]);
        printf("%02x ", hwph->hw_addr[hlen-1]);
    }

    mark = nfq_get_nfmark(tb);
    if (mark)
        printf("mark=%u ", mark);

    ifi = nfq_get_indev(tb);
    if (ifi)
        printf("indev=%u ", ifi);

    ifi = nfq_get_outdev(tb);
    if (ifi)
        printf("outdev=%u ", ifi);
    ifi = nfq_get_physindev(tb);
    if (ifi)
        printf("physindev=%u ", ifi);

    ifi = nfq_get_physoutdev(tb);
    if (ifi)
        printf("physoutdev=%u ", ifi);

    ret = nfq_get_payload(tb, &data);
    if (ret >= 0)
        printf("payload_len=%d ", ret);

    if (ret > 0){
        ip_print(data);
        tcp_print(&data[ip_header.hdr_len]);
        if (ip_header.version == 0x4){
            if (ip_header.protocol == 0x6){
                if (tcp.dPort == 80){
                    //unsigned char *http_data;
                    //http_data = (unsigned char *)(data+(ip_header.hdr_len) + (tcp.hdr_len));
                    if (ret > ip_header.hdr_len + tcp.hdr_len){
                        int http_data = ip_header.hdr_len + tcp.hdr_len;
                        //Host: User-Agent:
                        unsigned char *payload = &data[http_data+22];
                        if(!strncmp(reinterpret_cast<const char*>(payload), (target), strlen(target))){
                            boolean = nfq_set_verdict(qh, id, NF_DROP, 0, NULL);
                            fprintf(stdout, "[-]Blocked\n");
                         }
                    }
                } //dport 80
            } //tcp 6
        } //version 4
    } // in data


    fputc('\n', stdout);
    boolean = nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);

    return boolean;
}

static int cb(struct nfq_q_handle *qh, struct nfgenmsg *nfmsg,
          struct nfq_data *nfa, void *data)
{
    u_int32_t id = print_pkt(qh, nfa);
    printf("entering callback\n");
    return nfq_set_verdict(qh, id, NF_ACCEPT, 0, NULL);
}


int main(int argc, char **argv)
{
    target = argv[1];
    struct nfq_handle *h;
    struct nfq_q_handle *qh;
    struct nfnl_handle *nh;
    int fd;
    int rv;
    char buf[4096] __attribute__ ((aligned));



    printf("opening library handle\n");
    h = nfq_open();
    if (!h) {
        fprintf(stderr, "error during nfq_open()\n");
        exit(1);
    }

    printf("unbinding existing nf_queue handler for AF_INET (if any)\n");
    if (nfq_unbind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_unbind_pf()\n");
        exit(1);
    }

    printf("binding nfnetlink_queue as nf_queue handler for AF_INET\n");
    if (nfq_bind_pf(h, AF_INET) < 0) {
        fprintf(stderr, "error during nfq_bind_pf()\n");
        exit(1);
    }

    printf("binding this socket to queue '0'\n");
    qh = nfq_create_queue(h,  0, &cb, NULL);
    if (!qh) {
        fprintf(stderr, "error during nfq_create_queue()\n");
        exit(1);
    }

    printf("setting copy_packet mode\n");
    if (nfq_set_mode(qh, NFQNL_COPY_PACKET, 0xffff) < 0) {
        fprintf(stderr, "can't set packet_copy mode\n");
        exit(1);
    }

    fd = nfq_fd(h);

    for (;;) {
        if ((rv = recv(fd, buf, sizeof(buf), 0)) >= 0) {
            printf("pkt received\n");
            nfq_handle_packet(h, buf, rv);
            continue;
        }
        /* if your application is too slow to digest the packets that
         * are sent from kernel-space, the socket buffer that we use
         * to enqueue packets may fill up returning ENOBUFS. Depending
         * on your application, this error may be ignored. nfq_nlmsg_verdict_putPlease, see
         * the doxygen documentation of this library on how to improve
         * this situation.
         */
        if (rv < 0 && errno == ENOBUFS) {
            printf("losing packets!\n");
            continue;
        }
        perror("recv failed");
        break;
    }

    printf("unbinding from queue 0\n");
    nfq_destroy_queue(qh);

#ifdef INSANE
    /* normally, applications SHOULD NOT issue this command, since
     * it detaches other programs/sockets from AF_INET, too ! */
    printf("unbinding from AF_INET\n");
    nfq_unbind_pf(h, AF_INET);
#endif

    printf("closing library handle\n");
    nfq_close(h);

    exit(0);
}

