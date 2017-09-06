/*
 * Copyright (c) 2015-2017, Broadcom. All rights reserved.  The term
 * Broadcom refers to Broadcom Limited and/or its subsidiaries.
 *
 * This software is available to you under a choice of one of two
 * licenses.  You may choose to be licensed under the terms of the GNU
 * General Public License (GPL) Version 2, available from the file
 * COPYING in the main directory of this source tree, or the
 * BSD license below:
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions
 * are met:
 *
 * 1. Redistributions of source code must retain the above copyright
 *    notice, this list of conditions and the following disclaimer.
 * 2. Redistributions in binary form must reproduce the above copyright
 *    notice, this list of conditions and the following disclaimer in
 *    the documentation and/or other materials provided with the
 *    distribution.
 *
 * THIS SOFTWARE IS PROVIDED BY THE AUTHOR AND CONTRIBUTORS ``AS IS''
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO,
 * THE IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR
 * PURPOSE ARE DISCLAIMED. IN NO EVENT SHALL THE AUTHOR OR CONTRIBUTORS
 * BE LIABLE FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR
 * CONSEQUENTIAL DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF
 * SUBSTITUTE GOODS OR SERVICES; LOSS OF USE, DATA, OR PROFITS; OR
 * BUSINESS INTERRUPTION) HOWEVER CAUSED AND ON ANY THEORY OF LIABILITY,
 * WHETHER IN CONTRACT, STRICT LIABILITY, OR TORT (INCLUDING NEGLIGENCE
 * OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE OF THIS SOFTWARE, EVEN
 * IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 * Author: Eddie Wai <eddie.wai@broadcom.com>
 *
 * Description: Compat file for compilation
 */

#ifndef __BNXT_RE_COMPAT_H__
#define __BNXT_RE_COMPAT_H__

#include <linux/interrupt.h>
#include "bnxt_qplib_res.h"
#include "bnxt_qplib_sp.h"
#include "bnxt_qplib_fp.h"

/* Defined in include/linux/kconfig.h */
#ifndef IS_ENABLED
#define IS_ENABLED(option)	defined(option)
#endif

/* include/rdma/ib_verbs.h */
#ifndef HAVE_IB_MR_INIT_ATTR
struct ib_mr_init_attr {
	int		max_reg_descriptors;
	u32		flags;
};
#endif

#ifndef HAVE_IB_MW_TYPE
enum ib_mw_type {
	IB_MW_TYPE_1 = 1,
	IB_MW_TYPE_2 = 2
};

#endif

#ifdef NO_IB_DEVICE
/* Temp workaround to bypass the ib_core vermagic mismatch */
#define ib_register_device(a, b)	0
#define ib_unregister_device(a)
#define ib_alloc_device(a)		kzalloc(a, GFP_KERNEL)
#define ib_dealloc_device(a)		kfree(a)
#endif

#ifndef HAVE_IB_MEM_WINDOW_TYPE
#define IB_DEVICE_MEM_WINDOW_TYPE_2A	(1 << 23)
#define IB_DEVICE_MEM_WINDOW_TYPE_2B	(1 << 24)
#endif

#ifndef HAVE_IP_BASED_GIDS
#define IB_PORT_IP_BASED_GIDS		(1 << 26)
#endif

#ifndef IB_MTU_8192
#define IB_MTU_8192 8192
#endif

#ifndef SPEED_20000
#define SPEED_20000		20000
#endif

#ifndef SPEED_25000
#define SPEED_25000		25000
#endif

#ifndef SPEED_40000
#define SPEED_40000		40000
#endif

#ifndef SPEED_50000
#define SPEED_50000		50000
#endif

#ifndef IB_SPEED_HDR
#define IB_SPEED_HDR		64
#endif
#ifndef RDMA_NETWORK_ROCE_V1
#define RDMA_NETWORK_ROCE_V1	0
#endif

#ifndef RDMA_NETWORK_IPV4
#define RDMA_NETWORK_IPV4	1
#endif

#ifndef RDMA_NETWORK_IPV6
#define RDMA_NETWORK_IPV6	2
#endif

#ifndef HAVE_RDMA_ADDR_FIND_L2_ETH_BY_GRH
#define rdma_addr_find_l2_eth_by_grh(sgid, dgid, dmac, vlan_id, if_index, hoplimit )\
	rdma_addr_find_dmac_by_grh(sgid, dgid, dmac, vlan_id, if_index)
#endif

#ifndef ETHTOOL_GEEE
struct ethtool_eee {
        __u32   cmd;
        __u32   supported;
        __u32   advertised;
        __u32   lp_advertised;
        __u32   eee_active;
        __u32   eee_enabled;
        __u32   tx_lpi_enabled;
        __u32   tx_lpi_timer;
        __u32   reserved[2];
};
#endif

#if !defined(NETDEV_RX_FLOW_STEER) || !defined(HAVE_FLOW_KEYS) || (LINUX_VERSION_CODE < 0x030300)
#undef CONFIG_RFS_ACCEL
#endif

#ifndef HAVE_IB_GID_ATTR
#define ib_query_gid(device, port_num, index, gid, attr)       \
	ib_query_gid(device, port_num, index, gid)
#endif

#ifndef HAVE_RDMA_ADDR_FIND_DMAC_BY_GRH_V2
#define rdma_addr_find_dmac_by_grh(sgid, dgid, smac, vlan, if_index)   \
	rdma_addr_find_dmac_by_grh(sgid, dgid, smac, vlan)
#endif

#ifndef smp_mp__before_atomic
#define smp_mp__before_atomic() smp_mb()
#endif

struct ib_mw_bind_info *get_bind_info(struct ib_send_wr *wr);
struct ib_mw *get_ib_mw(struct ib_send_wr *wr);

struct scatterlist *get_ib_umem_sgl(struct ib_umem *umem, u32 *nmap);

int bnxt_re_register_netdevice_notifier(struct notifier_block *nb);
int bnxt_re_unregister_netdevice_notifier(struct notifier_block *nb);
void bnxt_re_set_fence_flag(struct ib_send_wr *wr, struct bnxt_qplib_swqe *wqe);

#ifndef HAVE_SKB_HASH_TYPE
enum pkt_hash_types {
	PKT_HASH_TYPE_NONE,
	PKT_HASH_TYPE_L2,
	PKT_HASH_TYPE_L3,
	PKT_HASH_TYPE_L4,
};
#endif
#endif
