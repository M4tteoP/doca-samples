/*
 * Copyright (c) 2023-2025 NVIDIA CORPORATION AND AFFILIATES.  All rights reserved.
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

#include <string.h>
#include <unistd.h>

#include <doca_log.h>
#include <doca_flow.h>

#include <flow_common.h>
#include "flow_switch_common.h"

DOCA_LOG_REGISTER(FLOW_SWITCH);

/* Changed from 2 to 1: we only need a single drop rule (TCP dst-port 8443) */
/* #define NB_ENTRIES 2 */
#define NB_ENTRIES 1
#define TOTAL_ENTRIES (NB_ENTRIES + 2)

static struct doca_flow_pipe_entry *entries[NB_ENTRIES]; /* array for storing created entries */
static struct doca_flow_pipe_entry *to_kernel_entry;
static struct doca_flow_pipe_entry *rss_entry;
static struct doca_flow_pipe *pipe_rss;
static struct doca_flow_pipe *switch_pipe;

/*
 * Create DOCA Flow pipe for ipv4 and forward RSS
 *
 * @port [in]: port of the pipe
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t create_rss_pipe(struct doca_flow_port *port, struct doca_flow_pipe **pipe)
{
	struct doca_flow_match match;
	struct doca_flow_monitor monitor;
	struct doca_flow_fwd fwd;
	struct doca_flow_pipe_cfg *pipe_cfg;
	uint16_t rss_queues[1];
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));
	memset(&monitor, 0, sizeof(monitor));

	monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

	/* L3 match */
	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "RSS_META_PIPE", DOCA_FLOW_PIPE_BASIC, false);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	/* RSS queue - send matched traffic to queue 0  */
	rss_queues[0] = 0;
	fwd.type = DOCA_FLOW_FWD_RSS;
	fwd.rss_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;
	fwd.rss.queues_array = rss_queues;
	fwd.rss.inner_flags = DOCA_FLOW_RSS_IPV4 | DOCA_FLOW_RSS_TCP;
	fwd.rss.nr_queues = 1;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, NULL, pipe);
destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

/*
 * Add DOCA Flow pipe entry
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise
 */
static doca_error_t add_rss_pipe_entry(struct doca_flow_pipe *pipe, struct entries_status *status)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));

	result = doca_flow_pipe_add_entry(0, pipe, &match, 0, &actions, NULL, NULL, 0, status, &rss_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Create DOCA Flow pipe with to_kernel match that forwards the matched traffic to kernel
 *
 * @miss_pipe [in]: miss pipe for forward miss
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t create_to_kernel_pipe(struct doca_flow_pipe *miss_pipe, struct doca_flow_pipe **pipe)
{
	struct doca_flow_match match;
	struct doca_flow_monitor monitor;
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_port *port = doca_flow_port_switch_get(NULL);
	struct doca_flow_target *kernel_target;
	doca_error_t result;

	if (!port) {
		DOCA_LOG_ERR("Failed to create pipe: port=NULL");
		return DOCA_ERROR_INVALID_VALUE;
	}

	memset(&match, 0, sizeof(match));
	memset(&monitor, 0, sizeof(monitor));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));

	/*
	 * Removed ALL L3/L4 constraints so this pipe forwards every packet
	 * to the kernel — including ARP, ICMP, IPv6, etc.
	 * Original: matched IPv4+UDP only, which dropped TCP (SSH) and ARP.
	 */
	/* match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4; */
	/* match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP; */

	monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "TO_KERNEL_IPv4_PIPE", DOCA_FLOW_PIPE_BASIC, false);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_get_target(DOCA_FLOW_TARGET_KERNEL, &kernel_target);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get kernel target: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	/* forwarding traffic to kernel */
	fwd.type = DOCA_FLOW_FWD_TARGET;
	fwd.target = kernel_target;

	/* Unmatched packets will be forwarded to miss_pipe */
	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = miss_pipe;

	result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

/*
 * Add DOCA Flow pipe entry to the to_kernel pipe
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t add_to_kernel_pipe_entry(struct doca_flow_pipe *pipe, struct entries_status *status)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions;
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));

	/* Removed: pipe no longer filters on L3 type */
	/* match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4; */

	result = doca_flow_pipe_add_entry(0, pipe, &match, 0, &actions, NULL, NULL, 0, status, &to_kernel_entry);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Create DOCA Flow pipe with 5 tuple match on the switch port.
 * Matched traffic will be forwarded to the port defined per entry.
 * Unmatched traffic will be dropped.
 *
 * @miss_pipe [in]: miss pipe for forward miss
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t create_switch_pipe(struct doca_flow_pipe *miss_pipe, struct doca_flow_pipe **pipe)
{
	struct doca_flow_match match;
	struct doca_flow_monitor monitor;
	struct doca_flow_fwd fwd;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_port *port = doca_flow_port_switch_get(NULL);
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&monitor, 0, sizeof(monitor));
	memset(&fwd, 0, sizeof(fwd));
	memset(&fwd_miss, 0, sizeof(fwd_miss));

	/*
	 * Removed ALL L3/L4 constraints from the root pipe.
	 *
	 * In switch/isolated mode with fdb_def_rule_en=0, packets that don't
	 * enter the root pipe are silently dropped by the eSwitch — there is
	 * no default FDB rule.  The original template matched IPv4+TCP only,
	 * so non-TCP traffic and, critically, ARP packets never entered the
	 * pipe and were dropped.  Without ARP the kernel can't resolve MACs,
	 * and SSH dies once the ARP cache entry expires.
	 *
	 * By removing the L3/L4 filter, ALL traffic enters this root pipe.
	 * The per-entry match on dst_port == 8443 still drops the target
	 * traffic; everything else falls through the miss path to TO_KERNEL
	 * and reaches the Linux kernel normally (ARP, SSH, ICMP, …).
	 */
	/* match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4; */
	/* match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_TCP; */

	/*
	 * Removed full 5-tuple match: we don't need to match src/dst IP and src port.
	 * We only care about TCP destination port so we can drop traffic to 8443.
	 */
	/* match.outer.l4_type_ext = DOCA_FLOW_L4_TYPE_EXT_TCP; */
	/* match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4; */
	/* match.outer.ip4.src_ip = 0xffffffff; */
	/* match.outer.ip4.dst_ip = 0xffffffff; */
	/* match.outer.tcp.l4_port.src_port = 0xffff; */

	/* Only TCP destination port is matched per entry */
	match.outer.tcp.l4_port.dst_port = 0xffff;

	/*
	 * Changed from FWD_PORT to FWD_DROP: instead of forwarding matched
	 * traffic to a representor port, we drop it (block TCP 8443).
	 */
	/* fwd.type = DOCA_FLOW_FWD_PORT; */
	/* fwd.port_id = 0xffff; */
	fwd.type = DOCA_FLOW_FWD_DROP;

	/* Unmatched packets will be forwarded to miss_pipe */
	fwd_miss.type = DOCA_FLOW_FWD_PIPE;
	fwd_miss.next_pipe = miss_pipe;

	monitor.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "SWITCH_PIPE", DOCA_FLOW_PIPE_BASIC, true);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, NB_ENTRIES);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg monitor: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_create(pipe_cfg, &fwd, &fwd_miss, pipe);
destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

/*
 * Add DOCA Flow pipe entry to the pipe
 *
 * @pipe [in]: pipe of the entry
 * @status [in]: user context for adding entry
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
static doca_error_t add_switch_pipe_entries(struct doca_flow_pipe *pipe, struct entries_status *status)
{
	struct doca_flow_match match;
	/*
	 * Removed per-entry fwd and loop variables: we use a single entry with
	 * the pipe-level DROP action instead of forwarding each entry to a
	 * different representor port.
	 */
	/* struct doca_flow_fwd fwd; */
	/* enum doca_flow_flags_type flags = DOCA_FLOW_WAIT_FOR_BATCH; */
	doca_error_t result;
	/* int entry_index = 0; */
	/* doca_be32_t dst_ip_addr; */
	/* doca_be32_t src_ip_addr; */
	/* doca_be16_t dst_port; */
	/* doca_be16_t src_port; */

	/* memset(&fwd, 0, sizeof(fwd)); */
	memset(&match, 0, sizeof(match));

	/*
	 * Original code looped over NB_ENTRIES=2, creating a full 5-tuple match
	 * per entry and forwarding to representor ports.  Replaced with a single
	 * entry that only sets TCP destination port = 8443.  The pipe-level
	 * fwd is DROP, so no per-entry fwd is needed (NULL below).
	 */
	/* for (entry_index = 0; entry_index < NB_ENTRIES; entry_index++) { */
	/*     dst_ip_addr = BE_IPV4_ADDR(8, 8, 8, 8 + entry_index); */
	/*     src_ip_addr = BE_IPV4_ADDR(1, 2, 3, 4 + entry_index); */
	/*     dst_port = DOCA_HTOBE16(80); */
	/*     src_port = DOCA_HTOBE16(1234); */
	/*     match.outer.ip4.dst_ip = dst_ip_addr; */
	/*     match.outer.ip4.src_ip = src_ip_addr; */
	/*     match.outer.tcp.l4_port.dst_port = dst_port; */
	/*     match.outer.tcp.l4_port.src_port = src_port; */
	/*     fwd.type = DOCA_FLOW_FWD_PORT; */
	/*     fwd.port_id = entry_index + 1; */
	/*     if (entry_index == NB_ENTRIES - 1) */
	/*         flags = DOCA_FLOW_NO_WAIT; */
	/*     result = doca_flow_pipe_add_entry(0, pipe, &match, 0, NULL, NULL, */
	/*                                       &fwd, flags, status,           */
	/*                                       &entries[entry_index]);         */
	/*     if (result != DOCA_SUCCESS) { ... }                               */
	/* } */

	/* Drop TCP traffic to destination port 8443 */
	match.outer.tcp.l4_port.dst_port = DOCA_HTOBE16(8443);

	result = doca_flow_pipe_add_entry(0, pipe, &match, 0, NULL, NULL, NULL,
					  DOCA_FLOW_NO_WAIT, status, &entries[0]);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Run flow_switch_single sample
 *
 * @nb_queues [in]: number of queues the sample will use
 * @nb_ports [in]: number of ports the sample will use
 * @ctx [in]: flow switch context the sample will use
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */

/* Context structure for statistics printing */
struct switch_single_stats_context {
	struct doca_flow_pipe_entry **entries;
	struct doca_flow_pipe_entry *to_kernel_entry;
	struct doca_flow_pipe_entry *rss_entry;
};

/*
 * Print switch single statistics
 *
 * @entries [in]: array of flow entries
 * @to_kernel_entry [in]: to kernel entry
 * @rss_entry [in]: RSS entry
 */
static void print_switch_single_stats(struct doca_flow_pipe_entry *entries[],
				      struct doca_flow_pipe_entry *to_kernel_entry,
				      struct doca_flow_pipe_entry *rss_entry)
{
	doca_error_t result;
	struct doca_flow_resource_query query_stats;
	int entry_idx;

	/* dump entries counters */
	for (entry_idx = 0; entry_idx < NB_ENTRIES; entry_idx++) {
		result = doca_flow_resource_query_entry(entries[entry_idx], &query_stats);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to query entry: %s", doca_error_get_descr(result));
			return;
		}
		DOCA_LOG_INFO("Entry in index: %d", entry_idx);
		DOCA_LOG_INFO("Total bytes: %ld", query_stats.counter.total_bytes);
		DOCA_LOG_INFO("Total packets: %ld", query_stats.counter.total_pkts);
	}
	result = doca_flow_resource_query_entry(to_kernel_entry, &query_stats);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to query entry: %s", doca_error_get_descr(result));
		return;
	}
	DOCA_LOG_INFO("To kernel Entry:");
	DOCA_LOG_INFO("Total bytes: %ld", query_stats.counter.total_bytes);
	DOCA_LOG_INFO("Total packets: %ld", query_stats.counter.total_pkts);

	result = doca_flow_resource_query_entry(rss_entry, &query_stats);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to query entry: %s", doca_error_get_descr(result));
		return;
	}
	DOCA_LOG_INFO("RSS Entry:");
	DOCA_LOG_INFO("Total bytes: %ld", query_stats.counter.total_bytes);
	DOCA_LOG_INFO("Total packets: %ld", query_stats.counter.total_pkts);
}

/*
 * Wrapper function for statistics printing compatible with flow_wait_for_packets
 *
 * @context [in]: switch_single_stats_context structure
 */
static void print_switch_single_stats_wrapper(void *context)
{
	struct switch_single_stats_context *ctx = (struct switch_single_stats_context *)context;
	print_switch_single_stats(ctx->entries, ctx->to_kernel_entry, ctx->rss_entry);
}

/*
 * Run this sample on the DPU with:
 *
 *   sudo ./binaries/doca_flow_switch_single -- -a pci/0000:03:00.0 -l 60
 *
 * No representors (-r) are needed: since we use FWD_DROP (not FWD_PORT),
 * only the physical uplink port is required (nb_ports = 1 in main).
 *
 * ---------------------------------------------------------------------------
 * What the sample does
 * ---------------------------------------------------------------------------
 *
 * It programs the eSwitch (hardware packet processor inside the DPU) in
 * SWITCH mode ("switch,isolated,hws").  Unlike VNF mode, switch mode does
 * NOT take the physical ports away from the Linux kernel — SSH and all
 * other kernel-owned traffic keep flowing normally.
 *
 * Traffic flow:
 *
 *   fortio client (or any external host)
 *       |  e.g. fortio curl -k https://<DPU-IP>:8443
 *       v
 *   [wire / network]
 *       |
 *       v
 *   p0 (physical uplink port)
 *       |
 *       v
 *   eSwitch
 *       |
 *       v
 *   CONTROL_PIPE  (root pipe, accepts ALL traffic)
 *       |
 *       +-- Entries 1..N (pri 1): IPv4 + TCP + src_ip==<blacklisted> + dst_port==8443 --> DROP
 *       |                         (one entry per blacklisted source IP;
 *       |                          packet discarded in HW, never reaches Linux)
 *       |
 *       +-- Entry N+1 (pri 2): catch-all (no match fields) --> kernel
 *                               (ARP, SSH, ICMP, non-blacklisted traffic to 8443,
 *                                everything else — delivered to Linux network stack)
 *
 * Why a CONTROL pipe instead of a BASIC pipe?
 *   A basic pipe's template implicitly filters on the field types it
 *   declares.  If the template includes tcp.dst_port, only TCP packets
 *   match the template.  In switch/isolated mode with fdb_def_rule_en=0,
 *   packets that don't match the root pipe template are silently dropped
 *   — killing ARP and therefore SSH.
 *   A control pipe has no template: every entry specifies its own match
 *   independently, so the catch-all entry truly catches everything.
 *
 * Result:
 *   - TCP traffic to port 8443 FROM BLACKLISTED IPs is dropped in hardware.
 *   - TCP traffic to port 8443 from non-blacklisted IPs passes through.
 *   - All other traffic (SSH, HTTP, ICMP, ARP, …) is forwarded to the
 *     Linux kernel by the catch-all entry.
 *   - After 60 seconds the sample exits and the drop rule is removed;
 *     port 8443 becomes reachable again.
 *
 * Test procedure:
 *   1. Verify Envoy is reachable:
 *        fortio curl -k https://<DPU-IP>:8443   --> 200 OK
 *   2. Start this sample on the DPU.
 *   3. Retry the curl:
 *        fortio curl -k https://<DPU-IP>:8443   --> timeout (dropped in HW)
 *   4. Confirm SSH still works (it does — not matched by the drop rule).
 *   5. Wait 60 s for the sample to exit, then retry curl --> 200 OK again.
 */
doca_error_t flow_switch(int nb_queues, int nb_ports, struct flow_switch_ctx *ctx)
{
	struct flow_resources resource = {0};
	uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};
	struct doca_flow_port *ports[nb_ports];
	uint32_t actions_mem_size[nb_ports];
	struct doca_flow_pipe *ctrl_pipe;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	struct doca_flow_target *kernel_target;
	doca_error_t result;
	int i;

	/*
	 * =========================================================================
	 * IP BLACKLIST — edit these entries to block specific source IPs.
	 *
	 * Each blacklisted IP will get a control pipe entry that matches:
	 *   src_ip == <IP>  AND  IPv4  AND  TCP  AND  dst_port == 8443 → DROP
	 *
	 * Traffic from non-blacklisted IPs to port 8443 passes through normally.
	 * All other traffic (SSH, ARP, ICMP, …) is always forwarded to the kernel.
	 *
	 * To add/remove IPs, simply edit this array and update NB_BLACKLISTED_IPS.
	 * =========================================================================
	 */
#define NB_BLACKLISTED_IPS 1  /* must match the number of entries below */
	/* Previous single-rule approach blocked ALL traffic to port 8443:
	 *   match.outer.tcp.l4_port.dst_port = DOCA_HTOBE16(8443);
	 *   fwd.type = DOCA_FLOW_FWD_DROP;
	 * Now we only drop traffic from specific source IPs to port 8443.
	 */
	static const doca_be32_t blacklisted_ips[NB_BLACKLISTED_IPS] = {
		BE_IPV4_ADDR(10, 0, 0, 100),   /* example: block 10.0.0.100 → :8443 */
	};

	resource.mode = DOCA_FLOW_RESOURCE_MODE_PORT;
	resource.nr_counters = NB_BLACKLISTED_IPS + 1; /* one per blacklist entry + catch-all */

	/*
	 * Use "switch,hws" without "isolated".
	 * With "isolated", the eSwitch drops ALL traffic that doesn't match
	 * an explicit flow rule.  Between creating the root pipe and installing
	 * our catch-all entry, there's a brief window where no rules exist
	 * and all traffic (including SSH) is dropped.  This race condition
	 * randomly kills SSH connections.
	 *
	 * Without "isolated", the default forwarding rules stay active,
	 * so traffic keeps flowing to the kernel even during initialization.
	 */
	/* result = init_doca_flow(nb_queues, "switch,isolated,hws", ...); */
	result = init_doca_flow(nb_queues, "switch,hws", &resource, nr_shared_resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_error_get_descr(result));
		return result;
	}

	ARRAY_INIT(actions_mem_size, ACTIONS_MEM_SIZE(NB_BLACKLISTED_IPS + 1));
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

	/* Create a CONTROL pipe as root — accepts ALL traffic */
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

	/*
	 * IMPORTANT: Install the catch-all kernel entry FIRST, before any
	 * blacklist entries.  Once the root control pipe is created, the
	 * eSwitch sends all traffic through it.  Without any entries,
	 * traffic is dropped.  By installing the catch-all immediately,
	 * we minimize the window where SSH can be disrupted.
	 *
	 * Priority 2 is lower than the blacklist entries (priority 1),
	 * so once the blacklist entries are added they'll match first.
	 */
	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));

	result = doca_flow_get_target(DOCA_FLOW_TARGET_KERNEL, &kernel_target);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to get kernel target: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	fwd.type = DOCA_FLOW_FWD_TARGET;
	fwd.target = kernel_target;

	result = doca_flow_pipe_control_add_entry(0, 2, ctrl_pipe,
						  &match, NULL,
						  NULL, NULL, NULL, NULL, NULL,
						  &fwd, NULL, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add kernel entry: %s", doca_error_get_descr(result));
		stop_doca_flow_ports(nb_ports, ports);
		doca_flow_destroy();
		return result;
	}
	DOCA_LOG_INFO("Catch-all kernel entry installed — SSH is safe");

	/*
	 * Now add one DROP entry per blacklisted source IP (priority 1 = highest).
	 * Match: IPv4 + TCP + src_ip == blacklisted + dst_port == 8443 → DROP
	 * These take priority over the catch-all (pri 2) installed above.
	 */
	for (i = 0; i < NB_BLACKLISTED_IPS; i++) {
		memset(&match, 0, sizeof(match));
		memset(&fwd, 0, sizeof(fwd));

		match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
		match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_TCP;
		match.outer.ip4.src_ip = blacklisted_ips[i];
		match.outer.tcp.l4_port.dst_port = DOCA_HTOBE16(8443);
		fwd.type = DOCA_FLOW_FWD_DROP;

		result = doca_flow_pipe_control_add_entry(0, 1, ctrl_pipe,
							  &match, NULL,
							  NULL, NULL, NULL, NULL, NULL,
							  &fwd, NULL, NULL);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add blacklist entry %d: %s", i, doca_error_get_descr(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}

		DOCA_LOG_INFO("Blacklisted src IP %d.%d.%d.%d → TCP :8443 → DROP",
			      (blacklisted_ips[i]) & 0xff,
			      (blacklisted_ips[i] >> 8) & 0xff,
			      (blacklisted_ips[i] >> 16) & 0xff,
			      (blacklisted_ips[i] >> 24) & 0xff);
	}

	DOCA_LOG_INFO("IP blacklist installed (%d IPs) — waiting for packets (60 s)...",
		      NB_BLACKLISTED_IPS);
	flow_wait_for_packets(60, NULL, NULL);

	result = stop_doca_flow_ports(nb_ports, ports);
	doca_flow_destroy();
	return result;
}
