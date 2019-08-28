#ifndef PACKET_H
#define PACKET_H
#include <stdint.h>
#include <stdio.h>
#include <string.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <unistd.h>
#include <linux/netfilter.h>
#include <errno.h>
#include <libnetfilter_queue/libnetfilter_queue.h>

#pragma pack(push, 1)



struct E_header
{
    uint8_t dMac[6];
    uint8_t sMac[6];
    uint16_t ethertype;
};

struct IP_header{
    uint8_t version;
    uint8_t hdr_len;
    uint8_t dscp;
    uint16_t totallength;
    uint16_t identification;
    uint16_t flags;
    uint8_t ttl;
    uint8_t protocol;
    uint16_t checksum;
    uint8_t sIP[4];
    uint8_t dIP[4];
};


struct TCP_header{
    uint16_t sPort;
    uint16_t dPort;
    uint32_t sequence;
    uint32_t acknowledge;
    uint8_t hdr_len;
    uint16_t flags;
    uint16_t windowsize;
    uint16_t checksum;
    uint16_t urgentPointer;
};

struct http_data{
    uint8_t data[0x30];
};

#pragma pack(pop)

uint32_t ntohl(uint32_t n){
        return (((n & 0xff000000) >> 24) | ((n & 0x00ff0000) >> 8) | ((n & 0x0000ff00 << 8) | ((n & 0x000000ff) << 24)));
};

uint16_t ntohs(uint16_t n){
    return ((n >> 8) | (n << 8));
};


#endif PACKET_H
