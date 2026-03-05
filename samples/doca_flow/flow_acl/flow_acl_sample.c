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

DOCA_LOG_REGISTER(FLOW_ACL);

#define ACL_MEM_REQ_PER_ENTRY (32)

#define ACL_ACTIONS_MEM_SIZE(entries) \
	rte_align32pow2((uint32_t)(entries * ACL_MEM_REQ_PER_ENTRY * DOCA_FLOW_MAX_ENTRY_ACTIONS_MEM_SIZE))

/* for egress use domain = DOCA_FLOW_PIPE_DOMAIN_EGRESS*/
static enum doca_flow_pipe_domain domain = DOCA_FLOW_PIPE_DOMAIN_DEFAULT;

/*
 * Create DOCA Flow control pipe
 *
 * @port [in]: port of the pipe
 * @port_id [in]: port ID of the pipe
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t create_rx_pipe(struct doca_flow_port *port, int port_id, struct doca_flow_pipe **pipe)
{
	doca_error_t result;

	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;

	memset(&match, 0, sizeof(match));
	memset(&fwd, 0, sizeof(fwd));

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "CONTROL_PIPE", DOCA_FLOW_PIPE_CONTROL, true);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_create(pipe_cfg, NULL, NULL, pipe);
	if (result != DOCA_SUCCESS)
		goto destroy_pipe_cfg;
	doca_flow_pipe_cfg_destroy(pipe_cfg);

	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;

	/* forwarding traffic to other port */
	fwd.type = DOCA_FLOW_FWD_PORT;
	fwd.port_id = port_id ^ 1;

	return doca_flow_pipe_control_add_entry(0,
						0,
						*pipe,
						&match,
						NULL,
						NULL,
						NULL,
						NULL,
						NULL,
						NULL,
						&fwd,
						NULL,
						NULL);
destroy_pipe_cfg:
	doca_flow_pipe_cfg_destroy(pipe_cfg);
	return result;
}

/*
 * Add DOCA Flow ACL pipe that matched IPV4 addresses
 *
 * @port [in]: port of the pipe
 * @is_root [in]: pipeline is root or not.
 * @pipe [out]: created pipe pointer
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t create_acl_pipe(struct doca_flow_port *port, bool is_root, struct doca_flow_pipe **pipe)
{
	struct doca_flow_match match;
	struct doca_flow_actions actions, *actions_arr[NB_ACTIONS_ARR];
	struct doca_flow_monitor monitor_counter;
	struct doca_flow_pipe_cfg *pipe_cfg;
	struct doca_flow_fwd fwd_miss;
	struct doca_flow_fwd fwd = {.type = DOCA_FLOW_FWD_CHANGEABLE};
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&actions, 0, sizeof(actions));
	memset(&monitor_counter, 0, sizeof(monitor_counter));
	memset(&fwd_miss, 0, sizeof(fwd_miss));

	match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.src_ip = 0xffffffff;
	match.outer.ip4.dst_ip = 0xffffffff;

	match.outer.tcp.l4_port.src_port = 0xffff;
	match.outer.tcp.l4_port.dst_port = 0xffff;

	actions_arr[0] = &actions;

	monitor_counter.counter_type = DOCA_FLOW_RESOURCE_TYPE_NON_SHARED;

	/* ACL pipes only support DOCA_FLOW_FWD_DROP as miss policy.
	 * To allow all traffic by default, we add a low-priority catch-all
	 * ALLOW entry in the ACL pipe (see flow_acl below). */
	fwd_miss.type = DOCA_FLOW_FWD_DROP;

	result = doca_flow_pipe_cfg_create(&pipe_cfg, port);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to create doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		return result;
	}

	result = set_flow_pipe_cfg(pipe_cfg, "ACL_PIPE", DOCA_FLOW_PIPE_ACL, is_root);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_nr_entries(pipe_cfg, 10);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg nr_entries: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_domain(pipe_cfg, domain);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg domain: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_match(pipe_cfg, &match, NULL);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg match: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}
	result = doca_flow_pipe_cfg_set_actions(pipe_cfg, actions_arr, NULL, NULL, NB_ACTIONS_ARR);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to set doca_flow_pipe_cfg actions: %s", doca_error_get_descr(result));
		goto destroy_pipe_cfg;
	}

	result = doca_flow_pipe_cfg_set_monitor(pipe_cfg, &monitor_counter);
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
 * Add DOCA Flow pipe entry to the ACL pipe.
 *
 * @pipe [in]: pipe of the entry
 * @port_id [in]: port ID of the entry
 * @status [in]: the entries status struct that monitors the entries in this specific port
 * @src_ip_addr [in]: src ip address
 * @dst_ip_addr [in]: dst ip address
 * @src_port [in]: src port
 * @dst_port [in]: dst port
 * @l4_type [in]: l4 protocol
 * @src_ip_addr_mask [in]: src ip mask
 * @dst_ip_addr_mask [in]: dst ip mask
 * @src_port_mask [in]: src port mask.
 *	if src_port_mask is equal to src_port, ACL adds rule with exact src port : src_port with mask 0xffff
 *	if src_port_mask is 0, ACL adds rule with any src port : src_port with mask 0x0
 *	if src_port_mask > src_port, ACL adds rule with port range : src_port_from = src_port, src_port_to =
 *src_port_mask  with mask 0xffff if src_port_mask < src_port, ACL will return with the error
 * @dst_port_mask [in]: dst port mask
 *	if dst_port_mask is equal to dst_port, ACL adds rule with exact dst port : dst_port with mask 0xffff
 *	if dst_port_mask is 0, ACL adds rule with any dst port : dst_port with mask 0x0
 *	if dst_port_mask > dst_port, ACL adds rule with port range : dst_port_from = dst_port, dst_port_to =
 *dst_port_mask  with mask 0xffff if dst_port_mask < dst_port, ACL will return with the error
 * @priority [in]: priority of the entry. 0 <= priority <= 1024. the lowest parameter value is used as the highest
 *priority
 * @is_allow [in]: allow or deny the entry
 * @flag [in]: Flow entry will be pushed to hw immediately or not. enum doca_flow_flags_type.
 *	flag DOCA_FLOW_WAIT_FOR_BATCH is using for collecting entries by ACL module
 *	flag DOCA_FLOW_NO_WAIT is using for adding the entry and starting building and offloading
 * @param[out] entry The entry inserted.
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
doca_error_t add_acl_specific_entry(struct doca_flow_pipe *pipe,
				    int port_id,
				    struct entries_status *status,
				    doca_be32_t src_ip_addr,
				    doca_be32_t dst_ip_addr,
				    doca_be16_t src_port,
				    doca_be16_t dst_port,
				    uint8_t l4_type,
				    doca_be32_t src_ip_addr_mask,
				    doca_be32_t dst_ip_addr_mask,
				    doca_be16_t src_port_mask,
				    doca_be16_t dst_port_mask,
				    uint16_t priority,
				    bool is_allow,
				    enum doca_flow_flags_type flag,
				    struct doca_flow_pipe_entry **entry)
{
	struct doca_flow_match match;
	struct doca_flow_match match_mask;
	struct doca_flow_fwd fwd;
	doca_error_t result;

	memset(&match, 0, sizeof(match));
	memset(&match_mask, 0, sizeof(match_mask));
	memset(&fwd, 0, sizeof(fwd));

	match_mask.outer.ip4.src_ip = src_ip_addr_mask;
	match_mask.outer.ip4.dst_ip = dst_ip_addr_mask;

	match.outer.l3_type = DOCA_FLOW_L3_TYPE_IP4;
	match.outer.ip4.src_ip = src_ip_addr;
	match.outer.ip4.dst_ip = dst_ip_addr;

	if (l4_type == DOCA_FLOW_L4_TYPE_EXT_TCP) {
		match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_TCP;
		match_mask.parser_meta.outer_l4_type = UINT32_MAX;
		match.outer.tcp.l4_port.src_port = src_port;
		match.outer.tcp.l4_port.dst_port = dst_port;
		match_mask.outer.tcp.l4_port.src_port = src_port_mask;
		match_mask.outer.tcp.l4_port.dst_port = dst_port_mask;
	} else {
		match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_UDP;
		match_mask.parser_meta.outer_l4_type = UINT32_MAX;
		match.outer.udp.l4_port.src_port = src_port;
		match.outer.udp.l4_port.dst_port = dst_port;
		match_mask.outer.udp.l4_port.src_port = src_port_mask;
		match_mask.outer.udp.l4_port.dst_port = dst_port_mask;
	}
	match.outer.l4_type_ext = l4_type;

	if (is_allow) {
		if (domain == DOCA_FLOW_PIPE_DOMAIN_DEFAULT) {
			fwd.type = DOCA_FLOW_FWD_PORT;
			fwd.port_id = port_id ^ 1;
		} else { // domain == DOCA_FLOW_PIPE_DOMAIN_EGRESS
			fwd.type = DOCA_FLOW_FWD_PORT;
			fwd.port_id = port_id;
		}
	} else
		fwd.type = DOCA_FLOW_FWD_DROP;

	result =
		doca_flow_pipe_acl_add_entry(0, pipe, &match, &match_mask, 0, NULL, priority, &fwd, flag, status, entry);

	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to add acl pipe entry: %s", doca_error_get_descr(result));
		return result;
	}

	return DOCA_SUCCESS;
}

/*
 * Add DOCA Flow pipe entries to the ACL pipe.
 *
 * @pipe [in]: pipe of the entry
 * @port_id [in]: port ID of the entry
 * @status [in]: user context for adding entry
 * @entries [out]: array of pointers to created entries
 * @return: DOCA_SUCCESS on success and DOCA_ERROR otherwise.
 */
/*
 * TO CUSTOMIZE ACL RULES: modify the entries below.
 * Each add_acl_specific_entry() call defines one ACL rule with these parameters:
 *
 *   add_acl_specific_entry(pipe, port_id, status,
 *       src_ip,          <-- source IP:       BE_IPV4_ADDR(a, b, c, d)
 *       dst_ip,          <-- destination IP:   BE_IPV4_ADDR(a, b, c, d)
 *       src_port,        <-- source port:      DOCA_HTOBE16(port)
 *       dst_port,        <-- destination port:  DOCA_HTOBE16(port)
 *       l4_type,         <-- protocol:         DOCA_FLOW_L4_TYPE_EXT_TCP or _UDP
 *       src_ip_mask,     <-- src IP mask:      0xffffffff = exact, 0xffffff00 = /24, etc.
 *       dst_ip_mask,     <-- dst IP mask:      same as above
 *       src_port_mask,   <-- 0x0 = any port, same as src_port = exact, > src_port = range [src_port, mask]
 *       dst_port_mask,   <-- 0x0 = any port, same as dst_port = exact, > dst_port = range [dst_port, mask]
 *       priority,        <-- 0-1024, lower value = higher priority
 *       is_allow,        <-- true = forward, false = drop
 *       flag,            <-- DOCA_FLOW_WAIT_FOR_BATCH or DOCA_FLOW_NO_WAIT (use NO_WAIT on last entry)
 *       &entry)
 *
 * When adding/removing entries, update num_of_entries in flow_acl() accordingly
 * (num_of_entries = 1 for main pipe + number of ACL entries).
 * Packets not matching any entry hit the miss policy (DROP).
 */
 // Currently unused in flow_acl()
doca_error_t add_acl_pipe_entries(struct doca_flow_pipe *pipe,
				  int port_id,
				  struct entries_status *status,
				  struct doca_flow_pipe_entry **entries)
{
	doca_error_t result;
	int i_entry = 0;

	/* DENY TCP from 1.2.3.4 -> 8.8.8.8, exact IPs, any ports, priority 10 */
	result = add_acl_specific_entry(pipe,
					port_id,
					status,
					BE_IPV4_ADDR(1, 2, 3, 4),       /* src_ip */
					BE_IPV4_ADDR(8, 8, 8, 8),       /* dst_ip */
					DOCA_HTOBE16(1234),              /* src_port */
					DOCA_HTOBE16(80),                /* dst_port */
					DOCA_FLOW_L4_TYPE_EXT_TCP,       /* protocol */
					DOCA_HTOBE32(0xffffffff),        /* src_ip_mask: exact */
					DOCA_HTOBE32(0xffffffff),        /* dst_ip_mask: exact */
					DOCA_HTOBE16(0x00),              /* src_port_mask: any */
					DOCA_HTOBE16(0x0),               /* dst_port_mask: any */
					10,                              /* priority */
					false,                           /* is_allow: DENY */
					DOCA_FLOW_WAIT_FOR_BATCH,
					&entries[i_entry++]);
	if (result != DOCA_SUCCESS)
		return result;

	/* ALLOW UDP from 172.20.1.4 -> 192.168.3.4, exact IPs, any src port, dst port range [80, 3000] */
	result = add_acl_specific_entry(pipe,
					port_id,
					status,
					BE_IPV4_ADDR(172, 20, 1, 4),    /* src_ip */
					BE_IPV4_ADDR(192, 168, 3, 4),   /* dst_ip */
					DOCA_HTOBE16(1234),              /* src_port */
					DOCA_HTOBE16(80),                /* dst_port */
					DOCA_FLOW_L4_TYPE_EXT_UDP,       /* protocol */
					DOCA_HTOBE32(0xffffffff),        /* src_ip_mask: exact */
					DOCA_HTOBE32(0xffffffff),        /* dst_ip_mask: exact */
					DOCA_HTOBE16(0x0),               /* src_port_mask: any */
					DOCA_HTOBE16(3000),              /* dst_port_mask: range [80, 3000] */
					50,                              /* priority */
					true,                            /* is_allow: ALLOW */
					DOCA_FLOW_WAIT_FOR_BATCH,
					&entries[i_entry++]);

	if (result != DOCA_SUCCESS)
		return result;

	/* ALLOW TCP from 172.20.1.4 -> 192.168.3.4, exact IPs, exact src port 1234, any dst port */
	result = add_acl_specific_entry(pipe,
					port_id,
					status,
					BE_IPV4_ADDR(172, 20, 1, 4),    /* src_ip */
					BE_IPV4_ADDR(192, 168, 3, 4),   /* dst_ip */
					DOCA_HTOBE16(1234),              /* src_port */
					DOCA_HTOBE16(80),                /* dst_port */
					DOCA_FLOW_L4_TYPE_EXT_TCP,       /* protocol */
					DOCA_HTOBE32(0xffffffff),        /* src_ip_mask: exact */
					DOCA_HTOBE32(0xffffffff),        /* dst_ip_mask: exact */
					DOCA_HTOBE16(1234),              /* src_port_mask: exact (== src_port) */
					DOCA_HTOBE16(0x0),               /* dst_port_mask: any */
					40,                              /* priority */
					true,                            /* is_allow: ALLOW */
					DOCA_FLOW_WAIT_FOR_BATCH,
					&entries[i_entry++]);

	if (result != DOCA_SUCCESS)
		return result;

	/* ALLOW TCP from 1.2.3.0/24 -> 8.8.8.0/24, any src port, exact dst port 80 */
	result = add_acl_specific_entry(pipe,
					port_id,
					status,
					BE_IPV4_ADDR(1, 2, 3, 5),       /* src_ip */
					BE_IPV4_ADDR(8, 8, 8, 6),       /* dst_ip */
					DOCA_HTOBE16(1234),              /* src_port */
					DOCA_HTOBE16(80),                /* dst_port */
					DOCA_FLOW_L4_TYPE_EXT_TCP,       /* protocol */
					DOCA_HTOBE32(0xffffff00),        /* src_ip_mask: /24 subnet */
					DOCA_HTOBE32(0xffffff00),        /* dst_ip_mask: /24 subnet */
					DOCA_HTOBE16(0xffff),            /* src_port_mask: any */
					DOCA_HTOBE16(80),                /* dst_port_mask: exact (== dst_port) */
					20,                              /* priority */
					true,                            /* is_allow: ALLOW */
					DOCA_FLOW_NO_WAIT,
					&entries[i_entry++]);

	if (result != DOCA_SUCCESS)
		return result;

	return DOCA_SUCCESS;
}

/*
Run this sample on the DPU with:

sudo ./binaries/doca_flow_acl -- -a pci/0000:03:00.0 -a pci/0000:03:00.1 -l 60

 *
 * Traffic flow (request path):
 *
 *   fortio client
 *       |  fortio curl -k https://199.48.128.30:8443
 *       v
 *   [wire / network]
 *       |
 *       v
 *   p0 (physical uplink port, IP 199.48.128.30)
 *       |
 *       v
 *   eSwitch (hardware packet processor inside the DPU)
 *       |
 *       v
 *   DOCA Flow pipeline:
 *       Main pipe (matches IPv4) --> ACL pipe (checks rules: IP, port, protocol)
 *           |                            |
 *           |                         [ALLOW] --> DPU network stack (Linux kernel) --> Envoy (:8443)
 *           |                            |
 *           |                         [DROP]  --> packet discarded in HW, never reaches Linux
 *           |                            |
 *           |                      [NO MATCH] --> miss policy (DROP)
 *
 * Response path: Envoy --> kernel --> eSwitch --> p0 --> wire --> fortio client
 *
 * Current behavior:
 *   - Two ACL rules are installed:
 *     1. Priority 10 (high): DENY TCP to dst port 8443 --> DROP
 *     2. Priority 1000 (low): ALLOW all TCP traffic --> FORWARD
 *   - TCP to port 8443 matches rule 1 first and is dropped in HW.
 *   - All other TCP traffic matches rule 2 and passes through.
 *   - fortio curl -k https://199.48.128.30:8443 will be dropped.
 *   - ACL miss policy is DROP (required by HW), but the catch-all
 *     ALLOW rule ensures non-matching traffic is forwarded.
 *
 * Notes:
 *   - p0 is where external traffic arrives; p1 is needed by VNF mode but not
 *     actively used for Envoy traffic.
 *   - ACL rules are enforced in hardware. Dropped packets never reach the
 *     DPU's Linux kernel or Envoy.
 */
doca_error_t flow_acl(int nb_queues)
{
	const int nb_ports = 2;
	/*
	 * Using a control pipe instead of ACL pipe.
	 * ACL pipes require all entries to have the same mask pattern, which
	 * prevents combining a deny-specific-port rule with a catch-all allow.
	 * A control pipe supports different match patterns per entry.
	 *
	 * Control pipe entries are added synchronously — no
	 * doca_flow_entries_process() call is needed.
	 */
	struct flow_resources resource = {.mode = DOCA_FLOW_RESOURCE_MODE_PORT, .nr_counters = 2};
	uint32_t nr_shared_resources[SHARED_RESOURCE_NUM_VALUES] = {0};
	struct doca_flow_port *ports[nb_ports];
	uint32_t actions_mem_size[nb_ports];
	struct doca_flow_pipe *ctrl_pipe;
	struct doca_flow_match match;
	struct doca_flow_fwd fwd;
	doca_error_t result;
	int port_id;

	result = init_doca_flow(nb_queues, "vnf,hws", &resource, nr_shared_resources);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA Flow: %s", doca_error_get_descr(result));
		return result;
	}

	ARRAY_INIT(actions_mem_size, ACL_ACTIONS_MEM_SIZE(2));
	result = init_doca_flow_vnf_ports(nb_ports, ports, actions_mem_size, &resource);
	if (result != DOCA_SUCCESS) {
		DOCA_LOG_ERR("Failed to init DOCA ports: %s", doca_error_get_descr(result));
		doca_flow_destroy();
		return result;
	}

	for (port_id = 0; port_id < nb_ports; port_id++) {
		struct doca_flow_pipe_cfg *pipe_cfg;

		/* Create a control pipe (root pipe) on this port */
		result = doca_flow_pipe_cfg_create(&pipe_cfg, ports[port_id]);
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
		 * Entry 1 (high priority): DROP TCP to dst port 8443.
		 * Blocks fortio requests to Envoy in hardware.
		 */
		memset(&match, 0, sizeof(match));
		memset(&fwd, 0, sizeof(fwd));
		match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
		match.parser_meta.outer_l4_type = DOCA_FLOW_L4_META_TCP;
		match.outer.tcp.l4_port.dst_port = DOCA_HTOBE16(8443);
		fwd.type = DOCA_FLOW_FWD_DROP;

		result = doca_flow_pipe_control_add_entry(0,
							  1,           /* priority: 1 (highest) */
							  ctrl_pipe,
							  &match,
							  NULL,        /* match_mask */
							  NULL, NULL, NULL, NULL, NULL,
							  &fwd,
							  NULL,        /* status */
							  NULL);       /* entry */
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add drop entry: %s", doca_error_get_descr(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}

		/*
		 * Entry 2 (low priority): FORWARD all other IPv4 traffic.
		 * Acts as a catch-all so non-8443 traffic passes through.
		 */
		memset(&match, 0, sizeof(match));
		memset(&fwd, 0, sizeof(fwd));
		match.parser_meta.outer_l3_type = DOCA_FLOW_L3_META_IPV4;
		fwd.type = DOCA_FLOW_FWD_PORT;
		fwd.port_id = port_id ^ 1;

		result = doca_flow_pipe_control_add_entry(0,
							  2,           /* priority: 2 (lower) */
							  ctrl_pipe,
							  &match,
							  NULL,
							  NULL, NULL, NULL, NULL, NULL,
							  &fwd,
							  NULL,
							  NULL);
		if (result != DOCA_SUCCESS) {
			DOCA_LOG_ERR("Failed to add forward entry: %s", doca_error_get_descr(result));
			stop_doca_flow_ports(nb_ports, ports);
			doca_flow_destroy();
			return result;
		}
	}

	DOCA_LOG_INFO("Control pipe entries installed — waiting for packets (60 s)...");
	flow_wait_for_packets(60, NULL, NULL);

	result = stop_doca_flow_ports(nb_ports, ports);
	doca_flow_destroy();
	return result;
}
