// SPDX-License-Identifier: GPL-2.0-only

#include <linux/bpf.h>
#include <linux/if_link.h>
#include <linux/limits.h>
#include <net/if.h>
#include <errno.h>
#include <stdio.h>
#include <stdlib.h>
#include <stdbool.h>
#include <string.h>
#include <unistd.h>
#include <fcntl.h>
#include <sys/resource.h>
#include <libgen.h>
#include <arpa/inet.h>
#include <sys/socket.h>
#include <netdb.h>
#include <ifaddrs.h>
#include <sys/ioctl.h>
#include <getopt.h>

#include "libbpf.h"
#include <bpf/bpf.h>

#define GTP5G_BPF_SUCCESS     0
#define GTP5G_BPF_FAIL        1

// Key: NVMe IP address
struct nvme_entry {
    __be32 uip; /* UPF Buffer MAC address */
    __be64 umac; /* UPF Buffer MAC address */
    int uifindex; /* UPF Buffer link index */
    __be64 nmac; /* NVMe link index */
};

// Key: BAR ID
struct bar_entry {
    __u16 pktcnt; /* Current packet count */
};

// Key: UE IP address
struct buf_entry {
    __u16 bid; /* BAR ID */
    __u16 pktcnt; /* Total packet count */   
    __be32 nip; /* NVMe IP address */   
};

enum gtp5gbpf_mode {
    MODE_ATTACH = 0x00,
    MODE_DETACH = 0x01,
    MODE_RULE = 0x02,
};

enum gtp5gbpf_op {
    OP_NOOP = 0x00,
    OP_ADD = 0x01,
    OP_DELETE = 0x02,
    OP_UPDATE = 0x04,
    OP_GET = 0x08,
    OP_SHOW = 0x10,
};

typedef struct verify_mode_s {
    char *mode;
    char *allowed;
    int skip_m;
} verfiy_mode_t;

static const verfiy_mode_t mode_paras[] = {
    [MODE_ATTACH] = {"attach", "mpI", 0},
    [MODE_DETACH] = {"detach", "mpI", 0},
    [MODE_RULE] = {"rule", "mpIobuUnc", 0},
};

static struct option const long_options[] = 
{
    {"mode", required_argument, NULL, 'm'},
    {"program", required_argument, NULL, 'p'},
    {"interface", required_argument, NULL, 'I'},
    {"op", required_argument, NULL, 'o'},
    {"bar", required_argument, NULL, 'b'},
    {"ueip", required_argument, NULL, 'u'},
    {"upfip", required_argument, NULL, 'U'},
    {"nvmeip", required_argument, NULL, 'n'},
    {"count", required_argument, NULL, 'c'},
    {"help", no_argument, NULL, 'h'},
    {"version", no_argument, NULL, 'V'},
    {NULL, 0, NULL, 0},
};

static char *short_options = "hV:m:p:I:o:b:u:U:n:c";

static void usage(const char *prog)
{
	printf("Usage: %s [...]\n", prog);
    printf("       -m Mode [attach/detach/rule]\n");
    printf("       -p XDP program attach to the interface name\n");
	printf("       -I <name> Interface name\n");
    printf("       -o Operation [add/delete/update/get/show] for rule\n");
    printf("       -b <bar> Buffer Action Rule ID\n");
    printf("       -u <ip> UE IP address\n");
    printf("       -U <ip> UPF IP address\n");
    printf("       -n <ip> NVMe IP address\n");
    printf("       -c <count> Packet count\n");
	printf("       -h Display this help\n");
    printf("       -V Version number of this tool\n");
}

static int str_to_op(char *str)
{
	int op;

	if (!strcmp("add", str))
		op = OP_ADD;
	else if (!strcmp("delete", str))
		op = OP_DELETE;
	else if (!strcmp("update", str))
		op = OP_UPDATE;
	else if (!strcmp("get", str))
		op = OP_GET;
    else if (!strcmp("show", str))
		op = OP_SHOW;
	else
		op = OP_NOOP;

	return op;
}

static int str_to_mode(char *str)
{
	int mode;

	if (!strcmp("attach", str))
		mode = MODE_ATTACH;
	else if (!strcmp("detach", str))
		mode = MODE_DETACH;
	else if (!strcmp("rule", str))
		mode = MODE_RULE;
	else
		mode = -1;

	return mode;
}

static int convert_ifname_to_index(char *ifname)
{
    int idx;

    idx = if_nametoindex(ifname);
    if (!idx)
        idx = strtoul(ifname, NULL, 0);

    if (!idx) {
        fprintf(stderr, "Invalid arg\n");
        return -1;
    }

    return idx;
}

static int verify_mode_params(int argc, char **argv, enum gtp5gbpf_mode mode)
{
	int ch, longindex;
	int ret = GTP5G_BPF_SUCCESS;
	char *allowed;
	int tmp = optind/*, skip_m*/;


	allowed = mode_paras[mode].allowed;
	// skip_m = mode_paras[mode].skip_m;

	optind = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				 long_options, &longindex)) >= 0) {
		if (!strchr(allowed, ch)) {
			printf("%s mode: option '-%c' is not "
				  "allowed/supported",
				  mode_paras[mode].mode, ch);
			ret = GTP5G_BPF_FAIL;
			break;
		}
	}
	optind = tmp;

	return ret;
}

/* Get the hardware(MAC) address of the interface given interface name */
static __be64 get_hwaddress(char *ifname)
{
	struct ifreq ifr;
	__be64 mac = 0;
	int fd, i;

    printf("%s: Ifname: %s\n", __func__, ifname);
	fd = socket(AF_INET, SOCK_DGRAM, 0);
	ifr.ifr_addr.sa_family = AF_INET;
	strncpy(ifr.ifr_name, ifname, IFNAMSIZ - 1);
	if (ioctl(fd, SIOCGIFHWADDR, &ifr) < 0) {
		printf("%s: ioctl failed leaving....\n", __func__);
		return -1;
	}
	for (i = 0; i < 6 ; i++)
		*((__u8 *)&mac + i) = (__u8)ifr.ifr_hwaddr.sa_data[i];
	close(fd);
	return mac;
}

static int get_ifname_by_ip_str(char *ipstr, char *ifname)
{
    struct ifaddrs *ifaddr, *ifa;
    int family, s, ret = 0;
    char host[NI_MAXHOST];

   if (getifaddrs(&ifaddr) == -1) {
        perror("getifaddrs");
        exit(EXIT_FAILURE);
    }

   for (ifa = ifaddr; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL)
            continue;

       family = ifa->ifa_addr->sa_family;
      
       if (family == AF_INET || family == AF_INET6) {
            s = getnameinfo(ifa->ifa_addr,
                    (family == AF_INET) ? sizeof(struct sockaddr_in) :
                                          sizeof(struct sockaddr_in6),
                    host, NI_MAXHOST, NULL, 0, NI_NUMERICHOST);
            if (s != 0) {
                printf("getnameinfo() failed: %s\n", gai_strerror(s));
                exit(EXIT_FAILURE);
            }
            if (strcmp(host, ipstr) == 0) {
                printf("Iface name  %s \n", ifa->ifa_name);
                strcpy(ifname, ifa->ifa_name);
                ret = 0;
                goto out;
            }
        }
    }
out:
   freeifaddrs(ifaddr);
   return ret;
}

// static int inet_pton(int ip_addr_type, const char *ip_str, void *ip_addr)
// {
//     int ret = 0;

//     if (ip_addr_type == IP_ADDRESS_TYPE_V4)
//         ret = in4_pton(ip_str, -1, ip_addr, '\n', NULL);
//     else
//         ret = in6_pton(ip_str, -1, ip_addr, '\n', NULL);

//     return ret;
// }

static struct bpf_object * get_program_bpf_obj(const char *pname) 
{
    struct bpf_prog_load_attr prog_load_attr;
	char filename[PATH_MAX];
	struct bpf_object *obj = NULL;
    int prog_fd, err;

    prog_load_attr.prog_type = BPF_PROG_TYPE_XDP;
    snprintf(filename, sizeof(filename), "%s.o", pname);
	prog_load_attr.file = filename;

    if (access(filename, O_RDONLY) < 0) {
        printf("%s: Failed to accessing file %s: %s\n",
             __func__, filename, strerror(errno));
        return NULL;
    }

    err = bpf_prog_load_xattr(&prog_load_attr, &obj, &prog_fd);
    if (err) {
        printf("%s: Does kernel support devmap lookup? : %s\n",
             __func__, strerror(err));
        /* If not, the error message will be:
            *  "cannot pass map_type 14 into func bpf_map_lookup_elem#1"
            */
        return NULL;
    } 

    return obj;
}

static int get_program_fd(char *pname)
{
    struct bpf_object *obj = NULL;
    struct bpf_program *prog = NULL;
    int prog_fd;

    obj = get_program_bpf_obj(pname);
    if (obj == NULL) {
        printf("%s: Failed to get the bpf program obj: %s\n",
             __func__, pname);
        return -1;
    }

    prog = bpf_object__find_program_by_title(obj, pname);
    prog_fd = bpf_program__fd(prog);
    if (prog_fd < 0) {
        printf("%s: Failed to get the program fd: %s\n",
            __func__, strerror(prog_fd));
    }

    return prog_fd;
}

static int get_gtp5g_buf_table_map_fd(const char *pname)
{
    struct bpf_object *obj = NULL;
    int map_fd;

    obj = get_program_bpf_obj(pname);
    if (obj == NULL) {
        printf("%s: Failed to get bpf program obj %s\n",
            __func__, pname);
        return -1;
    }

    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj,
                        "gtp5g_buf_table"));
    if (map_fd < 0) {
        printf("%s: Failed to find buf table map: %s\n",
            __func__, strerror(map_fd));
        return -1;
    }

    return map_fd;
}

// static int get_gtp5g_bar_table_map_fd(const char *pname)
// {
//     struct bpf_object *obj = NULL;
//     int map_fd;

//     obj = get_program_bpf_obj(pname);
//     if (obj == NULL) {
//         printf("%s: Failed to get bpf program obj %s\n",
//             __func__, pname);
//         return -1;
//     }

//     map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj,
//                         "gtp5g_bar_table"));
//     if (map_fd < 0) {
//         printf("%s: Failed to find bar table map: %s\n",
//             __func__, strerror(map_fd));
//         return -1;
//     }
    
//     return map_fd;
// }

static int get_gtp5g_nvme_table_map_fd(const char *pname)
{
    struct bpf_object *obj = NULL;
    int map_fd;

    obj = get_program_bpf_obj(pname);
    if (obj == NULL) {
        printf("%s: Failed to get bpf program obj %s\n",
            __func__, pname);
        return -1;
    }

    map_fd = bpf_map__fd(bpf_object__find_map_by_name(obj,
                        "gtp5g_nvme_table"));
    if (map_fd < 0) {
        printf("%s: Failed to find nvme table map: %s\n",
            __func__, strerror(map_fd));
        return -1;
    }    

    return map_fd;
}

static int do_attach(char *pname, char *ifname)
{
	int prog_fd, idx, err;

    idx = convert_ifname_to_index(ifname);
    if (idx < 0) {
        printf("%s: Failed to convert the index %s\n",
            __func__, ifname);
		return -1;
    }
    printf("%s: ifname %s to index :%d\n", __func__,
        ifname, idx);

	prog_fd = get_program_fd(pname);
	if (prog_fd < 0) {
		printf("%s: Failed to get the program fd for %s: %s\n",
            __func__, pname, strerror(prog_fd));
		return -1;
	}

	err = bpf_set_link_xdp_fd(idx, prog_fd, 0);
	if (err < 0) {
		printf("%s: Failed to attach program to %s: %s\n",
            __func__, pname, strerror(err));
		return -1;
	}

	return 0;
}

static int do_detach(char *pname, char *ifname)
{
	int idx, err;

    idx = convert_ifname_to_index(ifname);

	err = bpf_set_link_xdp_fd(idx, -1, 0);
	if (err < 0) {
		printf("%s: Failed to detach program: %s\n",
            __func__, strerror(err));
        return -1;
    }

	/* TODO: Remember to cleanup map, when adding use of shared map
	 *  bpf_map_delete_elem((map_fd, &idx);
	 */
	return 0;
}

static int do_add_entry(char *pname, char *ifname,
    char *pUeip, int bar_id, char *pNvmeip, char *pUpfip, int count)
{
    struct buf_entry bentry = {0};
    // struct bar_entry baentry = {0};
    struct nvme_entry nentry = {0};
    int err, idx;
    int buf_fd, /*bar_fd,*/ nvme_fd;
    __u32 ueip = 0, nip = 0, upfip = 0;
    __be64 nmac = 0, upfmac = 0;
    char nip_iface[NI_MAXHOST], uip_iface[NI_MAXHOST];

    if (pname == NULL || ifname == NULL || pUeip == NULL ||
        pNvmeip == NULL || pUpfip == NULL) {
            return -1;
    }

    if (!inet_pton(AF_INET, pUeip, &ueip)) {
        printf("%s: Failed to convert ue ip\n", __func__);
        return -1;
    }
    printf("%s: UE IP: %s-%#x\n", __func__, pUeip, ueip);

    if (!inet_pton(AF_INET, pNvmeip, &nip)) {
        printf("%s: Failed to convert NVMe ip\n", __func__);
        return -1;
    }
    printf("%s: NVMe IP: %s-%#x\n", __func__, pNvmeip, nip);

    if (!inet_pton(AF_INET, pUpfip, &upfip)) {
        printf("%s: Failed to convert UPF ip\n", __func__);
        return -1;
    }
    printf("%s: UPF IP: %s-%#x\n", __func__, pUpfip, upfip);

    err = get_ifname_by_ip_str(pNvmeip, nip_iface);
    if (err < 0) {
        printf("%s: Failed to get NVMe ip iface name\n", __func__);
        return -1;
    }
    printf("%s: NVMe IP: %s-%s\n", __func__, pNvmeip, nip_iface);

    err = get_ifname_by_ip_str(pUpfip, uip_iface);
    if (err < 0) {
         printf("%s: Failed to get UPF ip iface name\n", __func__);
        return -1;
    }
    printf("%s: UPF IP: %s-%s\n", __func__, pUpfip, uip_iface);

    nmac = get_hwaddress(nip_iface);
    if (nmac < 0) {
        printf("%s: Failed to get NVMe MAC address\n", __func__);
        return -1;
    }
    printf("%s: NVMe IP: %s-%#llx\n", __func__, nip_iface, nmac);

    upfmac = get_hwaddress(uip_iface);
    if (upfmac < 0) {
        printf("%s: Failed to get UPF MAC address\n", __func__);
        return -1;
    }
    printf("%s: UPF IP: %s-%#llx\n", __func__, uip_iface, upfmac);

    idx = convert_ifname_to_index(uip_iface);
    if (idx < 0) {
        printf("%s: Failed to convert the index %s\n",
            __func__, uip_iface);
		return -1;
    }
    printf("%s: UPF IP: %s-%d\n", __func__, uip_iface, idx);

    buf_fd = get_gtp5g_buf_table_map_fd(pname);
    if (buf_fd < 0) {
        printf("%s: Failed to find the buf table fd for %s\n",
            __func__, pname);
        return -1;
    }

    // bar_fd = get_gtp5g_bar_table_map_fd(pname);
    // if (bar_fd < 0) {
    //     printf("%s: Failed to find the bar table fd for %s\n",
    //          __func__, pname);
    //     return -1;
    // }

    nvme_fd = get_gtp5g_nvme_table_map_fd(pname);
    if (nvme_fd < 0) {
        printf("%s: Failed to find the bar table fd for %s\n",
             __func__, pname);
        return -1;
    }

    // Buffer Table
    bentry.bid = (__u16)bar_id;
    bentry.nip = (__be32)nip;
    bentry.pktcnt = (__u16)count;
    err = bpf_map_update_elem(buf_fd, &ueip, &bentry, 0);
    if (err) {
        printf("%s: Failed to update buf table entry: %s\n",
            __func__, strerror(err));
        return -1;
    }

    // BAR Table
    // err = bpf_map_update_elem(bar_fd, &bid, &baentry, 0);
    // if (err) {
    //     printf("%s: Failed to update bar table entry: %s\n",
    //             __func__, strerror(err));
    //     return -1;
    // }

    // NVMe Table
    nentry.uip = (__be32)upfip;
    nentry.umac = upfmac;
    nentry.uifindex = idx;
    nentry.nmac = nmac;
    err = bpf_map_update_elem(nvme_fd, &nip, &nentry, 0);
    if (err) {
        printf("%s: failed to update nvme table entry: %s\n",
            __func__, strerror(err));
        return -1;
    }        
  
    return 0;
}

static int do_delete_entry(char *pname, char *ifname,
    char *ueip)
{
    // TODO: 
    return 0;
}

// static int do_get_entry(char *ifname, int argc, char **argv)
// {
//     // TODO:
//     return 0;
// }

int main(int argc, char **argv)
{
    char *pg_name = NULL, *ifname = NULL;
    char *ue_ip = NULL, *nvme_ip = NULL, *upf_ip = NULL;
   	int ret = -1, ch, longindex, mode = -1;
    int op = OP_NOOP, bar_id = 0, count = 0;

    optopt = 0;
	while ((ch = getopt_long(argc, argv, short_options,
				long_options, &longindex)) >= 0) {
		switch (ch) {
        case 'm':
            printf("Mode\n");
            mode = str_to_mode(optarg);
            if (mode < 0) {
                usage(basename(argv[0]));
                return -1;
            }
            ret = verify_mode_params(argc, argv, mode);
            if (ret) {
                goto out;
            }
            break;
        case 'o':
			op |= str_to_op(optarg);
			if (op == OP_NOOP) {
				printf("can not recognize operation: '%s'",
					optarg);
				goto out;
			}
            printf("Operation: %#x\n", op);
			break;
        case 'p':
            pg_name = optarg;
            printf("XDP Programe Name :%s\n", pg_name);
            break;
        case 'I':
            ifname = optarg;
            printf("Interface Name :%s\n", ifname);
            break;
        case 'b':
            bar_id = atoi(optarg);
            printf("BAR ID :%d\n", bar_id);
            break;
        case 'u':
            ue_ip = optarg;
            printf("UE IP :%s\n", ue_ip);
            break;
        case 'U':
            upf_ip = optarg;
            printf("UPF IP :%s\n", upf_ip);
            break;
        case 'n':
            nvme_ip = optarg;
            printf("NVMe IP :%s\n", nvme_ip);
            break;
        case 'c':
            count = atoi(optarg);
            printf("Packet count :%d\n", count);
            break;
        case 'V':
            printf("%s version 0.1\n", basename(argv[0]));
            return 0;
        case 'h':
            usage(basename(argv[0]));
            return 0;
        }
    }
	
    if (optopt) {
		printf("unrecognized character '%c'", optopt);
		ret  = -1;
		goto out;
	}

    if (mode < 0) {
        usage(basename(argv[0]));
        ret = -1;
        goto out;
    }

    switch (mode) {
    case MODE_ATTACH:
        printf("Attach XDP\n");
        ret = do_attach(pg_name, ifname);
        break;
    case MODE_DETACH:
        printf("Detach XDP\n");
        ret = do_detach(pg_name, ifname);
        break;
    case MODE_RULE:
        printf("Rule entry of XDP\n");
        switch (op) {
        case OP_ADD:
        case OP_UPDATE:
            printf("Selected operation: ADD/UPDATE\n");
            ret = do_add_entry(pg_name,
                ifname, ue_ip, bar_id, nvme_ip, upf_ip, count);
            break;
        case OP_DELETE:
         printf("Selected operation: DELETE\n");
            ret = do_delete_entry(pg_name,
                ifname, ue_ip);
            break;
        case OP_GET:
        case OP_SHOW:
        default:
            printf("Unsupported operation\n");
            /* fall-through*/
        }
        break;
    default:
        printf("Unsupported mode\n");
        /* fall-through */
    }

out:
    if (ret < 0) {
        return ret;
    }

    return ret;
}