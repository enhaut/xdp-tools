// SPDX-License-Identifier: GPL-2.0-only
/* Copyright(c) 2017 Jesper Dangaard Brouer, Red Hat, Inc.
 */

#include <errno.h>
#include <stdio.h>
#include <signal.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <sys/sysinfo.h>
#include <linux/if_link.h>
#include <xdp/libxdp.h>

#include "logging.h"

#include "xdp-bench.h"
#include "xdp_redirect_cpumap.skel.h"

#define EXIT_OK		 0
#define EXIT_FAIL	 1
#define EXIT_FAIL_OPTION 2
#define EXIT_FAIL_BPF	 4

const struct cpumap_opts defaults_redirect_cpumap = {
	.mode = XDP_MODE_NATIVE,
	.interval = 2,
	.qsize = 2048,
	.program_mode = CPUMAP_CPU_L4_HASH,
};

static volatile sig_atomic_t running = 1;

static void sig_handler(int sig)
{
	(void)sig;
	running = 0;
}

int do_redirect_cpumap(const void *cfg, __unused const char *pin_root_path)
{
	const struct cpumap_opts *opt = cfg;

	DECLARE_LIBBPF_OPTS(xdp_program_opts, opts);
	struct xdp_program *xdp_prog = NULL;
	struct xdp_redirect_cpumap *skel;
	struct bpf_cpumap_val value;
	int ret = EXIT_FAIL_OPTION;
	int n_cpus, cpu_map_fd;
	int cpumap_pass_fd;
	size_t i;

	if (opt->cpus.num_vals == 0 || opt->cpus.num_vals > 64) {
		pr_warn("Must specify between 1 and 64 CPUs with -c\n");
		goto end;
	}

	n_cpus = libbpf_num_possible_cpus();

	skel = xdp_redirect_cpumap__open();
	if (!skel) {
		pr_warn("Failed to xdp_redirect_cpumap__open: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end;
	}

	/* Set target CPUs via rodata (frozen before verification) */
	skel->rodata->nr_target_cpus = opt->cpus.num_vals;
	for (i = 0; i < opt->cpus.num_vals; i++)
		skel->rodata->target_cpus[i] = opt->cpus.vals[i];

	if (bpf_map__set_max_entries(skel->maps.cpu_map, n_cpus) < 0) {
		pr_warn("Failed to set max entries for cpu_map map: %s\n",
			strerror(errno));
		ret = EXIT_FAIL_BPF;
		goto end_destroy;
	}

	opts.obj = skel->obj;
	opts.prog_name = "cpumap_l4_hash";
	xdp_prog = xdp_program__create(&opts);
	if (!xdp_prog) {
		ret = -errno;
		pr_warn("Couldn't open XDP program: %s\n",
			strerror(-ret));
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

	ret = xdp_program__attach(xdp_prog, opt->iface_in.ifindex, opt->mode, 0);
	if (ret < 0) {
		pr_warn("Failed to attach XDP program: %s\n",
			strerror(-ret));
		goto end_destroy;
	}

	/* Populate cpu_map entries for each target CPU */
	cpu_map_fd = bpf_map__fd(skel->maps.cpu_map);
	cpumap_pass_fd = bpf_program__fd(skel->progs.cpumap_pass);

	value.qsize = opt->qsize;
	value.bpf_prog.fd = cpumap_pass_fd;

	for (i = 0; i < opt->cpus.num_vals; i++) {
		__u32 cpu_id = opt->cpus.vals[i];

		ret = bpf_map_update_elem(cpu_map_fd, &cpu_id, &value, 0);
		if (ret < 0) {
			pr_warn("Failed to add CPU %u to cpu_map: %s\n",
				cpu_id, strerror(errno));
			ret = EXIT_FAIL;
			goto end_detach;
		}
	}

	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	pr_info("Running on %s (cpus:", opt->iface_in.ifname);
	for (i = 0; i < opt->cpus.num_vals; i++)
		pr_info(" %u", opt->cpus.vals[i]);
	pr_info("). Hit Ctrl-C to exit.\n");

	while (running)
		pause();

	ret = EXIT_OK;
end_detach:
	xdp_program__detach(xdp_prog, opt->iface_in.ifindex, opt->mode, 0);
end_destroy:
	xdp_program__close(xdp_prog);
	xdp_redirect_cpumap__destroy(skel);
end:
	return ret;
}
