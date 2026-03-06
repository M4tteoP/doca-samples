/*
 * Copyright (c) 2022-2025 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
 *
 * Redistribution and use in source and binary forms, with or without modification, are permitted
 * provided that the following conditions are met:
 *     * Redistributions of source code must retain the above copyright notice, this list of
 *       conditions and the following disclaimer.
 *     * Redistributions in binary form must reproduce the above copyright notice, this list of
 *       conditions and the following disclaimer in the documentation and/or other materials
 *       provided with the distribution.
 *     * Neither the name of the NVIDIA CORPORATION nor the names of its contributors may be used
 *       to endorse or promote products derived from this software without specific prior written
 *       permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS" AND ANY EXPRESS OR
 * IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE IMPLIED WARRANTIES OF MERCHANTABILITY AND
 * FITNESS FOR A PARTICULAR PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL NVIDIA CORPORATION BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL DAMAGES (INCLUDING,
 * BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS;
 * OR BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT,
 * STRICT LIABILITY, OR TOR (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

/*
 * ==========================================================================
 * flow_drop — Block TCP traffic from specific source IPs to port 8443
 * ==========================================================================
 *
 * Build (inside DOCA 3.2.1 devel container):
 *   cd samples/doca_flow/flow_drop
 *   meson build && ninja -C build
 *
 * Run on BF-3 DPU:
 *   sudo ./doca_flow_drop -- -a pci/0000:03:00.0 -l 60
 *
 *   Only ONE port needed (no p1, no representors).
 *   Arguments after "--" are DOCA arguments:
 *     -a pci/0000:03:00.0   Physical uplink port p0 (Envoy's 199.48.128.30)
 *     -l 60                 DOCA log level (60 = DEBUG)
 *
 * Architecture — switch mode (isolated) with CONTROL pipes:
 *
 *   [External client: fortio curl -k https://199.48.128.30:8443]
 *          |
 *          v
 *   p0 (physical uplink, 199.48.128.30)
 *          |
 *          v
 *   eSwitch
 *          |
 *          v
 *   INGRESS CONTROL_PIPE (root pipe)
 *       |
 *       +-- Entry 1..N (priority 0): match IPv4+TCP+src_ip+dst_port=8443 --> DROP
 *       |   (one entry per blacklisted source IP — dropped in HW)
 *       |
 *       +-- Catch-all (priority 1): all other traffic --> KERNEL
 *           (ARP, SSH, ICMP, non-blacklisted traffic — delivered to Linux)
 *
 *   EGRESS CONTROL_PIPE
 *       |
 *       +-- Catch-all (priority 0): all kernel responses --> port 0 (wire)
 *           (TCP ACKs, SSH replies, ARP responses — sent to the network)
 *
 * Why isolated switch mode:
 *   In isolated mode, default FDB rules are removed. We explicitly program
 *   all traffic paths: ingress catch-all → kernel, egress catch-all → wire.
 *   This gives us full control. SSH must be via a management interface
 *   (oob_net0 or tmfifo_net0), not via p0.
 *
 * How to change the blocked IPs:
 *   Edit the blacklisted_ips[] array in flow_drop() below.
 *   Update NB_BLACKLISTED_IPS to match.
 */

#include <string.h>
#include <unistd.h>

#include <doca_log.h>
#include <doca_flow.h>

#include <flow_common.h>
#include "flow_switch_common.h"

DOCA_LOG_REGISTER(FLOW_DROP);

/*
 * Run flow_drop sample
 *
 * @nb_queues [in]: number of queues the sample will use
 * @nb_ports [in]: number of ports the sample will use
 * @ctx [in]: flow switch context
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t flow_drop(int nb_queues, int nb_ports, struct flow_switch_ctx *ctx)
{
	struct flow_resources resource = {0};
	uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};
	struct doca_flow_port *ports[nb_ports];
	uint32_t actions_mem_size[nb_ports];
	struct doca_flow_pipe *ctrl_pipe;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	doca_error_t result;
	int i;

	/*
	 * =========================================================================
	 * IP BLACKLIST — edit these entries to block specific source IPs.
	 *
	 * Each blacklisted IP gets a control pipe entry that matches:
	 *   IPv4 + TCP + src_ip == <IP> + dst_port == 8443 --> DROP
	 *
	 * Traffic from non-blacklisted IPs to port 8443 passes through.
	 * All other traffic (SSH, ARP, ICMP, ...) is unaffected.
	 *
	 * To add/remove IPs, edit this array and update NB_BLACKLISTED_IPS.
	 * =========================================================================
	 */
#define NB_BLACKLISTED_IPS 1
	static const doca_be32_t blacklisted_ips[NB_BLACKLISTED_IPS] = {
		BE_IPV4_ADDR(1, 2, 3, 4),   /* change to the IP you want to block */
	};

	resource.mode = DOCA_FLOW_RESOURCE_MODE_PORT;
	resource.nr_counters = NB_BLACKLISTED_IPS + 2; /* blacklist + ingress catch-all + egress catch-all */

	/*
	 * "switch,hws,isolated" — isolated switch mode.
	 * Default FDB rules are removed. We explicitly program:
	 *   - Ingress: blacklist → DROP, catch-all → kernel
	 *   - Egress: catch-all → wire (port 0)
	 */
	result = init_doca_flow(nb_queues, "switch,hws,isolated", &resource, nr_shared_resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_error_get_descr(result));
		return result;
	}

	ARRAY_INIT(actions_mem_size, ACTIONS_MEM_SIZE(NB_BLACKLISTED_IPS));
	result = init_doca_flow_switch_ports(ctx->devs_ctx.devs_manager,
					     ctx->devs_ctx.nb_devs,
					     ports,
					     nb_ports,
					     actions_mem_size,
					     &resource);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA ports: %s", doca_error_get_descr(result));
		doca_flow_destroy();
		return result;
	}

	/*
	 * Create a root CONTROL pipe on the switch port (ingress).
	 * Blacklist entries at priority 0, catch-all → kernel at priority 1.
	 */
	struct doca_flow_port *sw_port = doca_flow_port_switch_get(NULL);

	result = doca_flow_pipe_cfg_create(&pipe_cfg, sw_port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create pipe cfg: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	result = set_flow_pipe_cfg(pipe_cfg, "CONTROL_PIPE", DOCA_FLOW_PIPE_CONTROL, true);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set pipe cfg: %s", doca_error_get_descr(result));
		doca_flow_pipe_cfg_destroy(pipe_cfg);
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	result = doca_flow_pipe_create(pipe_cfg, NULL, NULL, &ctrl_pipe);
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create control pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	DOCA_LOG_INFO("Ingress control pipe created");

	/*
	 * Add one DROP entry per blacklisted source IP.
	 * Matched packets are dropped in HW. Everything else goes through
	 * the default FDB path to the kernel.
	 */
	for (i = 0; i < NB_BLACKLISTED_IPS; i++) {
		memset(&match, 0, sizeof(match));
		memset(&fwd, 0, sizeof(fwd));

		match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
		match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_TCP;
		match.outer.ip4.src_ip = blacklisted_ips[i];
		match.outer.tcp.l4_port.dst_port = DOCA_HTOBE16(8443);
		fwd.type = DOCA_FLOW_FWD_DROP;

		result = doca_flow_pipe_control_add_entry(0, 0, ctrl_pipe,
							  &match, NULL,
							  NULL, NULL, NULL, NULL, NULL,
							  &fwd, NULL, NULL);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add blacklist entry %d: %s",
				     i, doca_error_get_descr(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}

		DOCA_LOG_INFO("Blacklisted src IP %d.%d.%d.%d -> TCP :8443 -> DROP",
			      (blacklisted_ips[i]) & 0xff,
			      (blacklisted_ips[i] >> 8) & 0xff,
			      (blacklisted_ips[i] >> 16) & 0xff,
			      (blacklisted_ips[i] >> 24) & 0xff);
	}

	/*
	 * Catch-all entry (priority 1, lower than blacklist at 0):
	 * Forward all non-blacklisted ingress traffic to the kernel.
	 */
	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));
	fwd.type = DOCA_FLOW_FWD_TARGET;
	fwd.target.type = DOCA_FLOW_TARGET_KERNEL;

	result = doca_flow_pipe_control_add_entry(0, 1, ctrl_pipe,
						  &match, NULL,
						  NULL, NULL, NULL, NULL, NULL,
						  &fwd, NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add ingress catch-all → kernel: %s",
			     doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	DOCA_LOG_INFO("Ingress catch-all -> kernel installed (priority 1)");

	/*
	 * Egress CONTROL pipe: kernel responses → wire (port 0).
	 * Without this, TCP ACKs, SSH replies, ARP responses etc. from
	 * the kernel cannot reach the network.
	 */
	struct doca_flow_pipe *egress_pipe;
	struct doca_flow_pipe_cfg *egress_cfg;

	result = doca_flow_pipe_cfg_create(&egress_cfg, sw_port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create egress pipe cfg: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	result = set_flow_pipe_cfg(egress_cfg, "EGRESS_PIPE", DOCA_FLOW_PIPE_CONTROL, true);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set egress pipe cfg: %s", doca_error_get_descr(result));
		doca_flow_pipe_cfg_destroy(egress_cfg);
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	result = doca_flow_pipe_cfg_set_domain(egress_cfg, DOCA_FLOW_PIPE_DOMAIN_EGRESS);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set egress domain: %s", doca_error_get_descr(result));
		doca_flow_pipe_cfg_destroy(egress_cfg);
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	result = doca_flow_pipe_create(egress_cfg, NULL, NULL, &egress_pipe);
	doca_flow_pipe_cfg_destroy(egress_cfg);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create egress pipe: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	DOCA_LOG_INFO("Egress control pipe created");

	/* Egress catch-all: forward everything from kernel to wire (port 0) */
	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));
	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = 0;

	result = doca_flow_pipe_control_add_entry(0, 0, egress_pipe,
						  &match, NULL,
						  NULL, NULL, NULL, NULL, NULL,
						  &fwd, NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add egress catch-all: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	DOCA_LOG_INFO("Egress catch-all -> wire installed");

	DOCA_LOG_INFO("IP blacklist installed (%d IPs) -- waiting 60 s for packets...",
		      NB_BLACKLISTED_IPS);
	flow_wait_for_packets(60, NULL, NULL);

	result = stop_doca_flow_ports(nb_ports, ports);
	doca_flow_destroy();
	return result;
}
