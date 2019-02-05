#include <stdio.h>
#include <lib/shell.h>
#include <lib/byteswap.h>
#include <network/dns.h>

#include "protocol.h"
#include "netshell.h"
#include "netinf.h"

static void print_ipv4_address(uint32_t address)
{
    swap_endian32(&address);

    for (size_t i = 0; i < 4; i++)
    {
        uint8_t octet = (address >> (i * 8)) & 0xff;

        printf("%d", octet);

        if (i != 3)
            printf(".");
    }
}

static void net_shell_resolve(int argc, char *argv[])
{
    uint32_t addr;
    int ret;

    if (argc != 2) {
        printf("Error: expected one argument, the hostname to resolve\n");
        return;
    }

    ret = dns_resolve_ipv4(argv[1], &addr);

    if (ret) {
        printf("Error: could not perform name resolution: %s\n",
               dns_get_error(ret));

        return;
    }

    printf("Resolved addr to: ");
    print_ipv4_address(addr);
    printf("\n");
}

static void print_interface_stats(struct netinf *interface)
{
    printf("  %s:\n", interface->name);
    printf("    RX packets: %lld TX packets: %lld\n",
           interface->rx_packets, interface->tx_packets);
    printf("    ipv4:\n      address: ");
    print_ipv4_address(interface->ipv4_data.addr);
    printf("\n      netmask: ");
    print_ipv4_address(interface->ipv4_data.netmask);
    printf("\n      gateway: ");
    print_ipv4_address(interface->ipv4_data.gateway);
    printf("\n");
    printf("    Dropped fragments: %lld\n",
           interface->dropped_fragments);
}

static void net_shell_netinf_list(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    printf("Interface List:\n");
    netinf_for_each_interface(print_interface_stats);
}

static void net_shell_stats(int argc, char *argv[])
{
    (void)argc;
    (void)argv;

    protocol_print_stats();
}

static struct shell_cmd net_shell_cmds[] = {
    SHELL_CMD_INITIALIZER("net_stats", net_shell_stats,
                          "net_stats",
                          "Print various networking statistics"),
    SHELL_CMD_INITIALIZER("net_resolve", net_shell_resolve,
                          "net_resolve HOSTNAME",
                          "Resolve HOSTNAME to a given IPv4 address"),
    SHELL_CMD_INITIALIZER("netinf_list", net_shell_netinf_list,
                          "netinf_list",
                          "Print a list of registered network interfaces"),
};

void net_shell_init(void)
{
    SHELL_REGISTER_CMDS(net_shell_cmds);
}
