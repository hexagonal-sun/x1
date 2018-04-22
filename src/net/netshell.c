#include <stdio.h>
#include <lib/shell.h>

#include "protocol.h"
#include "dns.h"
#include "netshell.h"

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

    printf("Resolved addr to: 0x%lX\n", addr);
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
};

void net_shell_init(void)
{
    SHELL_REGISTER_CMDS(net_shell_cmds);
}
