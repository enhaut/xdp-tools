#define _GNU_SOURCE
#include <stdio.h>
#include <errno.h>
#include <string.h>

#include <xdp/libxdp.h>

#include "params.h"
#include "util.h"
#include "logging.h"
#include "compat.h"
#include <linux/rtnetlink.h>
#include <sys/socket.h>
#include <unistd.h>

#include "xdp_forward.skel.h"
#include "xdp_flowtable.skel.h"
#include "xdp_flowtable_sample.skel.h"

#define MAX_IFACE_NUM 32
#define PROG_NAME "xdp-forward"

int do_help(__unused const void *cfg, __unused const char *pin_root_path)
{
	fprintf(stderr,
		"Usage: xdp-forward COMMAND [options]\n"
		"\n"
		"COMMAND can be one of:\n"
		"       load           - Load the XDP forwarding plane\n"
		"       unload         - Unload the XDP forwarding plane\n"
		"       help           - show this help message\n"
		"\n"
		"Use 'xdp-forward COMMAND --help' to see options for each command\n");
	return -1;
}

/* struct vlan_info { */
/*     __u16 vlan_id;          // VLAN ID */
/*     int   phys_ifindex;     // Physical interface index */
/* }; */
#define MAX_VLANS_PER_IFACE 64
struct vlan_info {
    __u16 vlan_id;          // VLAN ID
    int   phys_ifindex;     // Physical interface index
    int   vlan_ifindex;        // VLAN interface index
};
int find_vlan_interfaces(int target_ifindex, struct vlan_info *vlan_list) {
    int sock;
    struct sockaddr_nl addr;
    struct nlmsghdr *nlmsg;
    struct ifinfomsg *ifinfo;
    struct rtattr *attr;
    int remaining;
    char buf[8192];
    int found_vlans = 0;
    
    // Create netlink socket
    sock = socket(AF_NETLINK, SOCK_RAW, NETLINK_ROUTE);
    if (sock < 0) {
        perror("Failed to open netlink socket");
        return -1;
    }
    
    // Initialize sockaddr_nl struct
    memset(&addr, 0, sizeof(addr));
    addr.nl_family = AF_NETLINK;
    addr.nl_groups = 0;
    
    // Bind the socket
    if (bind(sock, (struct sockaddr*)&addr, sizeof(addr)) < 0) {
        perror("Failed to bind netlink socket");
        close(sock);
        return -1;
    }
    
    // Prepare request message
    memset(buf, 0, sizeof(buf));
    nlmsg = (struct nlmsghdr*)buf;
    nlmsg->nlmsg_len = NLMSG_LENGTH(sizeof(struct ifinfomsg));
    nlmsg->nlmsg_type = RTM_GETLINK;
    nlmsg->nlmsg_flags = NLM_F_REQUEST | NLM_F_DUMP;
    nlmsg->nlmsg_seq = 1;
    nlmsg->nlmsg_pid = getpid();
    
    // Set interface family to AF_PACKET to get all interfaces
    ifinfo = NLMSG_DATA(nlmsg);
    ifinfo->ifi_family = AF_PACKET;
    
    // Send the request
    if (send(sock, nlmsg, nlmsg->nlmsg_len, 0) < 0) {
        perror("Failed to send netlink message");
        close(sock);
        return -1;
    }
    
    printf("VLAN interfaces using physical ifindex %d:\n", target_ifindex);
    printf("VLAN ID\tVLAN ifindex\n");
    
    // Receive and process response
    while (1) {
        int len = recv(sock, buf, sizeof(buf), 0);
        if (len < 0) {
            perror("Failed to receive netlink message");
            close(sock);
            return -1;
        }
        
        // Process all messages in the received data
        for (nlmsg = (struct nlmsghdr*)buf; NLMSG_OK(nlmsg, len); nlmsg = NLMSG_NEXT(nlmsg, len)) {
            // Check for end of messages
            if (nlmsg->nlmsg_type == NLMSG_DONE) {
                close(sock);
                return found_vlans;
            }
            
            // Check for error
            if (nlmsg->nlmsg_type == NLMSG_ERROR) {
                perror("Netlink error");
                close(sock);
                return -1;
            }
            
            // Extract interface info
            ifinfo = NLMSG_DATA(nlmsg);
            
            // Check if this is a VLAN interface
            int is_vlan = 0;
            int vlan_id = -1;
            int link_ifindex = -1;  // physical interface the VLAN is attached to
            
            // Parse interface attributes
            remaining = nlmsg->nlmsg_len - NLMSG_LENGTH(sizeof(struct ifinfomsg));
            for (attr = IFLA_RTA(ifinfo); RTA_OK(attr, remaining); attr = RTA_NEXT(attr, remaining)) {
                // Check for linkinfo attribute which contains VLAN info
                if (attr->rta_type == IFLA_LINKINFO) {
                    struct rtattr *li_attr;
                    int li_remaining;
                    
                    // Parse linkinfo attributes
                    li_remaining = RTA_PAYLOAD(attr);
                    for (li_attr = (struct rtattr*)RTA_DATA(attr); 
                         RTA_OK(li_attr, li_remaining); 
                         li_attr = RTA_NEXT(li_attr, li_remaining)) {
                        
                        // Check for link kind (e.g., "vlan")
                        if (li_attr->rta_type == IFLA_INFO_KIND) {
                            char *kind = RTA_DATA(li_attr);
                            if (strncmp(kind, "vlan", 4) == 0) {
                                is_vlan = 1;
                            }
                        }
                        
                        // Check for VLAN-specific data
                        if (li_attr->rta_type == IFLA_INFO_DATA) {
                            struct rtattr *vlan_attr;
                            int vlan_remaining;
                            
                            vlan_remaining = RTA_PAYLOAD(li_attr);
                            for (vlan_attr = (struct rtattr*)RTA_DATA(li_attr);
                                 RTA_OK(vlan_attr, vlan_remaining);
                                 vlan_attr = RTA_NEXT(vlan_attr, vlan_remaining)) {
                                
                                // Extract VLAN ID
                                if (vlan_attr->rta_type == IFLA_VLAN_ID) {
                                    vlan_id = *(uint16_t*)RTA_DATA(vlan_attr);
                                }
                            }
                        }
                    }
                }
                
                // Check if this VLAN is linked to our target interface
                if (attr->rta_type == IFLA_LINK) {
                    link_ifindex = *(int*)RTA_DATA(attr);
                }
            }
            
            // If this is a VLAN interface linked to our target interface, print the info
            if (is_vlan && link_ifindex == target_ifindex && vlan_id != -1) {
                printf("%d\t%d\n", vlan_id, ifinfo->ifi_index);
				vlan_list[found_vlans].vlan_id = vlan_id;
				vlan_list[found_vlans].phys_ifindex = link_ifindex;
				vlan_list[found_vlans].vlan_ifindex = ifinfo->ifi_index;

                found_vlans++;
            }
        }
    }
    
    close(sock);
    return found_vlans;
}


struct enum_val xdp_modes[] = { { "native", XDP_MODE_NATIVE },
				{ "skb", XDP_MODE_SKB },
				{ NULL, 0 } };

enum fwd_mode {
	FWD_FIB,
	FWD_FLOWTABLE,
};

struct enum_val fwd_modes[] = { { "fib", FWD_FIB },
				{ "flowtable", FWD_FLOWTABLE },
				{ NULL, 0 } };

enum fib_mode {
	FIB_DIRECT,
	FIB_FULL,
};

struct enum_val fib_modes[] = { { "direct", FIB_DIRECT },
				{ "full", FIB_FULL },
				{ NULL, 0 } };

static int find_prog(struct iface *iface, bool detach)
{
	struct xdp_program *prog = NULL;
	enum xdp_attach_mode mode;
	struct xdp_multiprog *mp;
	int ret = -ENOENT;

	mp = xdp_multiprog__get_from_ifindex(iface->ifindex);
	if (!mp)
		return ret;

	if (xdp_multiprog__is_legacy(mp)) {
		prog = xdp_multiprog__main_prog(mp);
		goto check;
	}

	while ((prog = xdp_multiprog__next_prog(prog, mp))) {
	check:
		if (!strcmp(xdp_program__name(prog), "xdp_fwd_fib_full") ||
		    !strcmp(xdp_program__name(prog), "xdp_fwd_fib_direct") ||
		    !strcmp(xdp_program__name(prog), "xdp_fwd_flow_full") ||
		    !strcmp(xdp_program__name(prog), "xdp_fwd_flow_direct")) {
			mode = xdp_multiprog__attach_mode(mp);
			ret = 0;
			if (detach) {
				ret = xdp_program__detach(prog, iface->ifindex,
							  mode, 0);
				if (ret)
					pr_warn("Couldn't detach XDP program from interface %s: %s\n",
						iface->ifname,
						strerror(errno));
				break;
			}
		}
	}

	xdp_multiprog__close(mp);
	return ret;
}

struct load_opts {
	enum fwd_mode fwd_mode;
	enum fib_mode fib_mode;
	enum xdp_attach_mode xdp_mode;
	struct iface *ifaces;
} defaults_load = { .fwd_mode = FWD_FIB, .fib_mode = FIB_FULL, };

struct prog_option load_options[] = {
	DEFINE_OPTION("fwd-mode", OPT_ENUM, struct load_opts, fwd_mode,
		      .short_opt = 'f',
		      .typearg = fwd_modes,
		      .metavar = "<fwd-mode>",
		      .help = "Forward mode to run in; see man page. Default fib"),
	DEFINE_OPTION("fib-mode", OPT_ENUM, struct load_opts, fib_mode,
		      .short_opt = 'F',
		      .typearg = fib_modes,
		      .metavar = "<fib-mode>",
		      .help = "Fib mode to run in; see man page. Default full"),
	DEFINE_OPTION("xdp-mode", OPT_ENUM, struct load_opts, xdp_mode,
		      .short_opt = 'm',
		      .typearg = xdp_modes,
		      .metavar = "<xdp_mode>",
		      .help = "Load XDP program in <xdp_mode>; default native"),
	DEFINE_OPTION("devs", OPT_IFNAME_MULTI, struct load_opts, ifaces,
		      .positional = true,
		      .metavar = "<ifname...>",
		      .min_num = 1,
		      .max_num = MAX_IFACE_NUM,
		      .required = 1,
		      .help = "Redirect from and to devices <ifname...>"),
	END_OPTIONS
};

static bool sample_probe_bpf_xdp_flow_lookup(void)
{
	struct xdp_flowtable_sample *skel;
	bool res;

	skel = xdp_flowtable_sample__open_and_load();
	res = !!skel;
	xdp_flowtable_sample__destroy(skel);

	return res;
}

static int do_load(const void *cfg, __unused const char *pin_root_path)
{
	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct xdp_program *xdp_prog = NULL;
	const struct load_opts *opt = cfg;
	struct bpf_program *prog = NULL;
	struct bpf_map *map = NULL;
	struct bpf_map *vlan_map_obj = NULL;
	struct bpf_object *obj;
	int ret = EXIT_FAILURE;
	struct iface *iface;
	void *skel;

	switch (opt->fwd_mode) {
	case FWD_FIB:
		opts.prog_name = opt->fib_mode == FIB_DIRECT
				 ? "xdp_fwd_fib_direct" : "xdp_fwd_fib_full";
		break;
	case FWD_FLOWTABLE:
		opts.prog_name = opt->fib_mode == FIB_DIRECT
				 ? "xdp_fwd_flow_direct"
				 : "xdp_fwd_flow_full";
		break;
	default:
		goto end;
	}

	if (opt->fwd_mode == FWD_FLOWTABLE) {
		struct xdp_flowtable *xdp_flowtable_skel;

		if (!sample_probe_bpf_xdp_flow_lookup()) {
			pr_warn("The kernel does not support the bpf_xdp_flow_lookup() kfunc\n");
			goto end;
		}

		xdp_flowtable_skel = xdp_flowtable__open();
		if (!xdp_flowtable_skel) {
			pr_warn("Failed to load skeleton: %s\n", strerror(errno));
			goto end;
		}
		map = xdp_flowtable_skel->maps.xdp_tx_ports;
		vlan_map_obj = xdp_flowtable_skel->maps.vlan_map;
		obj = xdp_flowtable_skel->obj;
		skel = (void *)xdp_flowtable_skel;
	} else {
		struct xdp_forward *xdp_forward_skel = xdp_forward__open();

		if (!xdp_forward_skel) {
			pr_warn("Failed to load skeleton: %s\n", strerror(errno));
			goto end;
		}
		map = xdp_forward_skel->maps.xdp_tx_ports;
		vlan_map_obj = xdp_forward_skel->maps.vlan_map;
		obj = xdp_forward_skel->obj;
		skel = (void *)xdp_forward_skel;
	}

	/* Make sure we only load the one XDP program we are interested in */
	while ((prog = bpf_object__next_program(obj, prog)) != NULL)
		if (bpf_program__type(prog) == BPF_PROG_TYPE_XDP &&
		    bpf_program__expected_attach_type(prog) == BPF_XDP)
			bpf_program__set_autoload(prog, false);

	opts.obj = obj;
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		pr_warn("Couldn't open XDP program: %s\n", strerror(errno));
		goto end_destroy;
	}

	/* We always set the frags support bit: nothing the program does is
	 * incompatible with multibuf, and it's perfectly fine to load a program
	 * with frags support on an interface with a small MTU. We don't risk
	 * setting any flags the kernel will balk at, either, since libxdp will
	 * do the feature probing for us and skip the flag if the kernel doesn't
	 * support it.
	 *
	 * The function below returns EOPNOTSUPP it libbpf is too old to support
	 * setting the flags, but we just ignore that, since in such a case the
	 * best we can do is just attempt to run without the frags support.
	 */
	xdp_program__set_xdp_frags_support(xdp_prog, true);


	for (iface = opt->ifaces; iface; iface = iface->next) {
		if (find_prog(iface, false) != -ENOENT) {
			pr_warn("Already attached to %s, not reattaching\n",
				iface->ifname);
			continue;
		}

		ret = xdp_program__attach(xdp_prog, iface->ifindex, opt->xdp_mode, 0);
		if (ret) {
			pr_warn("Failed to attach XDP program to iface %s: %s\n",
				iface->ifname, strerror(-ret));
			goto end_detach;
		}

		ret = bpf_map_update_elem(bpf_map__fd(map), &iface->ifindex,
					  &iface->ifindex, 0);
		if (ret) {
			pr_warn("Failed to update devmap value: %s\n",
				strerror(errno));
			goto end_detach;
		}
		pr_info("Loaded on interface %s\n", iface->ifname);

		struct vlan_info vlan_list[MAX_VLANS_PER_IFACE];
		int vlans = find_vlan_interfaces(iface->ifindex, vlan_list);
		if (vlan_map_obj) {
			for (int i = 0; i < vlans; i++) {
				ret = bpf_map_update_elem(bpf_map__fd(vlan_map_obj),
							  &(vlan_list[i].vlan_ifindex), &vlan_list[i], 0);
				if (ret) {
					pr_warn("Failed to update VLAN map value: %s\n",
						strerror(errno));
					goto end_detach;
				}
			}
		}

	}

	ret = EXIT_SUCCESS;

end_destroy:
	if (opt->fwd_mode == FWD_FLOWTABLE)
		xdp_flowtable__destroy(skel);
	else
		xdp_forward__destroy(skel);
end:
	return ret;

end_detach:
	ret = EXIT_FAILURE;
	for (iface = opt->ifaces; iface; iface = iface->next)
		xdp_program__detach(xdp_prog, iface->ifindex, opt->xdp_mode, 0);
	goto end_destroy;
}

struct unload_opts {
	struct iface *ifaces;
} defaults_unload = {};

struct prog_option unload_options[] = {
	DEFINE_OPTION("devs", OPT_IFNAME_MULTI, struct unload_opts, ifaces,
		      .positional = true,
		      .metavar = "<ifname...>",
		      .min_num = 1,
		      .max_num = MAX_IFACE_NUM,
		      .help = "Redirect from and to devices <ifname...>"),
	END_OPTIONS
};


static int do_unload(const void *cfg, __unused const char *pin_root_path)
{
	const struct unload_opts *opt = cfg;
	int ret = EXIT_SUCCESS;
	struct iface *iface;

	for (iface = opt->ifaces; iface; iface = iface->next) {
		if (find_prog(iface, true)) {
			pr_warn("Couldn't find program on interface %s\n",
				iface->ifname);
			ret = EXIT_FAILURE;
		}
		pr_info("Unloaded from interface %s\n", iface->ifname);
	}

	return ret;
}

static const struct prog_command cmds[] = {
	DEFINE_COMMAND(load, "Load XDP forwarding plane"),
	DEFINE_COMMAND(unload, "Unload XDP forwarding plane"),
	{ .name = "help", .func = do_help, .no_cfg = true },
	END_COMMANDS
};

union all_opts {
	struct load_opts load;
	struct unload_opts unload;
};

int main(int argc, char **argv)
{
	if (argc > 1)
		return dispatch_commands(argv[1], argc - 1, argv + 1, cmds,
					 sizeof(union all_opts), PROG_NAME, false);

	return do_help(NULL, NULL);
}
