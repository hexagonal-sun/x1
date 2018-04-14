#include <stdio.h>
#include <lib/shell.h>

#include "protocol.h"
#include "netshell.h"

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
};

void net_shell_init(void)
{
    SHELL_REGISTER_CMDS(net_shell_cmds);
}
