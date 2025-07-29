#ifndef DOS_SYN
#define DOS_SYN
#include <sys/socket.h>
#include <netinet/ip.h>
#include <stdlib.h>
#include <string.h>

#define PAYLOAD_SIZE (20 + 20)

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
} ipv4_header;

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
} tcp_header;

typedef struct {
    unsigned char src_addr[4];
    unsigned char dst_addr[4];
    unsigned char zeros;
    unsigned char protocol;
    unsigned short tcp_length;
} tcp_pseudo_header;

typedef struct {
    ipv4_header *ip;
    tcp_header *tcp;
} Payload;

typedef struct {
    void *buffer;
    unsigned short index;
} Buffer;

typedef struct {
    char src_addr[4];
    char host[4];
    unsigned int port;
    unsigned long count;
    unsigned char rand_port : 1;
    float wait_time;
} DoS_SYN_args;

unsigned int init_socket(void);
void pack_ipv4_header(Buffer *buf, Payload *payload);
void pack_tcp_header(Buffer *buf, Payload *payload);
unsigned short handle_checksum(Payload *payload, tcp_pseudo_header *pseudo_header);
signed int push_payload(int sockfd, Buffer *buf, struct sockaddr_in *addr);

void free_buffer(Buffer *buf);
size_t flood(DoS_SYN_args *args);

#endif
