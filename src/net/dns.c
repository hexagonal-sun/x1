#include <errno.h>
#include <string.h>
#include <stdlib.h>
#include <lib/byteswap.h>
#include <network/udp.h>
#include <network/dns.h>

#include "packet.h"
#include "udp.h"

static uint32_t DNS_SERVER = 0xC0A80408;

struct dns_header {
    uint16_t identification;
    uint16_t flags;
    uint16_t question_count;
    uint16_t answer_count;
    uint16_t authority_count;
    uint16_t additional_count;
} __attribute__((packed));

struct domain_label {
    char *buf;
    size_t sz;
};

struct dns_question {
    struct domain_label QNAME;

    struct {
        uint16_t QTYPE;
        uint16_t QCLASS;
    } __attribute__((packed)) question_addtional;
};

struct dns_answer {
    struct domain_label ANAME;

    struct {
        uint16_t ATYPE;
        uint16_t ACLASS;
        uint32_t TTL;
        uint16_t DATA_LENGTH;
    } __attribute__((packed)) answer_additional;
};

#include "dns_flags.def"

#define QTYPE_A     0x0001
#define QTYPE_NS    0x0002
#define QTYPE_CNAME 0x0005
#define QTYPE_SOA   0x0006
#define QTYPE_WKS   0x000B
#define QTYPE_PTR   0x000C
#define QTYPE_MX    0x000F
#define QTYPE_SRV   0x0021
#define QTYPE_AAAA  0x001C
#define QCLASS_IN   0x0001

enum RCODES {
    /* There are DNS specifed response codes. */
    NOERROR  = 0,
    FORMERR  = 1,
    SERVFAIL = 2,
    NXDOMAIN = 3,
    NOTIMP   = 4,
    REFUSED  = 5,
    YXDOMAIN = 6,
    XRRSET   = 7,
    NOTAUTH  = 8,
    NOTZONE  = 9,

    /* And these are our custom error codes. */
    NOTRESPONSE = 10,
    WRONGIDENT = 11,
    UNEXNOANS = 12,
    WRONGANS = 13,
};

static const char *error_strings[] = {
    [NOERROR]     = "DNS Query completed successfully",
    [FORMERR]     = "DNS Query Format Error",
    [SERVFAIL]    = "Server failed to complete the DNS request",
    [NXDOMAIN]    = "Domain name does not exist",
    [NOTIMP]      = "Function not implemented",
    [REFUSED]     = "The server refused to answer for the query",
    [YXDOMAIN]    = "Name that should not exist, does exist",
    [XRRSET]      = "RRset that should not exist, does exist",
    [NOTAUTH]     = "Server not authoritative for the zone",
    [NOTZONE]     = "Name not in zone",
    [NOTRESPONSE] = "Response packet was not set as a response",
    [WRONGIDENT]  = "DNS response had incorrect identification",
    [UNEXNOANS]   = "Unexpected number of answer sections",
    [WRONGANS]    = "Unexpected answer record format",
};

static void dns_swap_question_endian(struct dns_question *question)
{
    swap_endian16(&question->question_addtional.QTYPE);
    swap_endian16(&question->question_addtional.QCLASS);
}

static void dns_swap_header_endian(struct dns_header *header)
{
    swap_endian16(&header->identification);
    swap_endian16(&header->flags);
    swap_endian16(&header->question_count);
    swap_endian16(&header->answer_count);
    swap_endian16(&header->authority_count);
    swap_endian16(&header->additional_count);
}

static void dns_swap_answer_endian(struct dns_answer *answer)
{
    swap_endian16(&answer->answer_additional.ATYPE);
    swap_endian16(&answer->answer_additional.ACLASS);
    swap_endian32(&answer->answer_additional.TTL);
    swap_endian16(&answer->answer_additional.DATA_LENGTH);
}

static int create_domain_label_from_hostname(const char *hostname,
                                             struct domain_label *ret)
{
    size_t hostname_sz = strlen(hostname);
    size_t domain_label_sz = hostname_sz + 2;
    char *buf = malloc(domain_label_sz);
    size_t i, label_sz = 0, label_ptr = 0;

    if (!buf)
        return ENOMEM;

    for (i = 0 ; i < strlen(hostname); i++)
    {
        if (hostname[i] == '.') {
            buf[label_ptr] = label_sz;
            label_ptr = i + 1;
            label_sz = 0;
        } else {
            buf[i + 1] = hostname[i];
            label_sz++;
        }
    }

    buf[label_ptr] = label_sz;
    buf[hostname_sz + 1] = 0;

    ret->buf = buf;
    ret->sz = domain_label_sz;

    return 0;
}

static void free_domain_label(struct domain_label *qname)
{
    free(qname->buf);
    qname->sz = 0;
}

static void consume_domain_label(void *udp_handle)
{
    uint8_t len;

    do
        udp_rx_data(udp_handle, &len, sizeof(len));
    while (len);
}

static void consume_question_section(void *udp_handle)
{
    uint32_t footer;

    consume_domain_label(udp_handle);

    udp_rx_data(udp_handle, &footer, sizeof(footer));
}

static int read_answer_section(void * udp_handle, void *dst_buf,
                               size_t buf_len)
{
    uint8_t byte;
    struct dns_answer answer;

    udp_rx_data(udp_handle, &byte, sizeof(byte));

    if ((byte >> 6) != 0x3)
        consume_domain_label(udp_handle);
    else
        udp_rx_data(udp_handle, &byte, sizeof(byte));

    udp_rx_data(udp_handle, &answer.answer_additional,
                sizeof(answer.answer_additional));

    dns_swap_answer_endian(&answer);

    if (buf_len < answer.answer_additional.DATA_LENGTH)
        return EINVAL;

    udp_rx_data(udp_handle, dst_buf,
                answer.answer_additional.DATA_LENGTH);

    return 0;
}

const char *dns_get_error(int ret)
{
    if (ret < NOERROR || ret > WRONGANS)
        return "Unknown return code\n";

    return error_strings[ret];
}

int dns_resolve_ipv4(const char *hostname, uint32_t *ipv4_address)
{
    int ret;
    struct dns_question question;
    struct packet_t *dns_packet;
    struct dns_header header;
    struct dns_header response_hdr;
    void *udp_handle;
    enum RCODES rcode;
    struct netinf *interface = netinf_get_for_ipv4_addr(DNS_SERVER);

    if (!interface)
        return -ENOENT;

    dns_packet = packet_tx_create(interface);

    if (!dns_packet)
        return -ENOMEM;

    ret = create_domain_label_from_hostname(hostname,
                                            &question.QNAME);

    if (ret)
        return ret;

    question.question_addtional.QTYPE = QTYPE_A;
    question.question_addtional.QCLASS = QCLASS_IN;

    memset(&header, 0, sizeof(header));

    header.identification = 0xdead;
    header.question_count = 1;
    set_flag_RD(&header);

    dns_swap_question_endian(&question);
    dns_swap_header_endian(&header);

    packet_tx_push_header(dns_packet, &question.question_addtional,
                          sizeof(question.question_addtional));
    packet_tx_push_header(dns_packet, question.QNAME.buf, question.QNAME.sz);
    packet_tx_push_header(dns_packet, &header, sizeof(header));

    udp_handle = udp_listen(35224);

    udp_xmit_packet_paylaod(35224, 53, DNS_SERVER, dns_packet);

    udp_rx_data(udp_handle, &response_hdr, sizeof(response_hdr));

    dns_swap_header_endian(&response_hdr);

    if (!get_flag_QR(&response_hdr)) {
        ret = NOTRESPONSE;
        goto out;
    }

    if (response_hdr.identification != 0xdead) {
        ret = WRONGIDENT;
        goto out;
    }

    rcode = response_hdr.flags &0xf;

    if (rcode != NOERROR) {
        ret = rcode;
        goto out;
    }

    if (response_hdr.answer_count != 1) {
        ret = UNEXNOANS;
        goto out;
    }

    consume_question_section(udp_handle);

    if (read_answer_section(udp_handle, ipv4_address,
                            sizeof(*ipv4_address))) {
        ret = WRONGANS;
        goto out;
    }

    swap_endian32(ipv4_address);

out:
    free_domain_label(&question.QNAME);
    udp_free(udp_handle);

    return ret;
}
