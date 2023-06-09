// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <unistd.h>
#include <fcntl.h>
#include <libgen.h>

// #include "libbpf.h"
#include <bpf/bpf.h>

static void usage(const char *prog)
{
	printf("Usage: %s [...]\n", prog);
	printf("       -i <index> Interface index\n");
    printf("       -a Attach the XDP gtp5g_buf_kern\n");
    printf("       -d Detach the XDP gtp5g_buf_kern\n");
    printf("       -u Update an entry from XDP gtp5g_buf_kern\n");
    printf("       -x Delete an entry from XDP gtp5g_buf_kern\n");
    printf("       -s <seid> Session Endpoint identifier\n");
    printf("       -b <bar> Buffer Action Rule ID\n");
    printf("       -e <ip> UE IP address\n");
    printf("       -n <ip> NVMe IP address\n");
    printf("       -p <count> Packet count\n");
    printf("       -g Get the current packet count\n");
	printf("       -h Display this help\n");
}

int main(int argc, char **argv)
{
    int opt;

    while ((opt = getopt(argc, argv, ":iaduxsbenp")) != -1) {
		switch (opt) {
		case 'i':
            printf("Interface index\n");
			break;
		case 'a':
            printf("Attach XDP\n");
			break;
        case 'd':
            printf("Detach XDP\n");
			break;
        case 'u':
            printf("Update an entry on XDP\n");
			break;
        case 'x':
            printf("Delete an entry from XDP\n");
			break;
        case 's':
            printf("Session Identifier\n");
			break;
        case 'b':
            printf("Buffer Action Rule Identifier\n");
			break;
        case 'e':
            printf("UE IP Address\n");
			break;
        case 'n':
            printf("NVMe IP Address\n");
			break;
        case 'p':
            printf("Packet Count\n");
			break;
        case 'g':
            printf("Get the current packet Count\n");
			break;
		default:
			usage(basename(argv[0]));
            return 1;
		}
	}
    return 0;
}