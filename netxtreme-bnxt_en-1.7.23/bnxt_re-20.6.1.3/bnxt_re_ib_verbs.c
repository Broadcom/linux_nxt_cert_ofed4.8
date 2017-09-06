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
 * Description: IB Verbs interpreter
 */

#include <linux/interrupt.h>
#include <linux/types.h>
#include <linux/pci.h>
#include <linux/netdevice.h>

#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_addr.h>
#include <rdma/ib_mad.h>
#include <rdma/ib_cache.h>

#include "bnxt_re_compat.h"
#include "bnxt_ulp.h"
#include "roce_hsi.h"
#include "bnxt_qplib_res.h"
#include "bnxt_qplib_sp.h"
#include "bnxt_qplib_fp.h"
#include "bnxt_qplib_rcfw.h"

#include "bnxt_re.h"
#include "bnxt_re_ib_verbs.h"
#include "bnxt_re_uverbs_abi.h"

#ifdef ENABLE_ROCE_TOS
extern unsigned int tos_ecn;
extern unsigned int tos_dscp;
#endif

static u8 __from_ib_qp_state(enum ib_qp_state state)
{
	switch (state) {
	case IB_QPS_RESET:
		return CMDQ_MODIFY_QP_NEW_STATE_RESET;
	case IB_QPS_INIT:
		return CMDQ_MODIFY_QP_NEW_STATE_INIT;
	case IB_QPS_RTR:
		return CMDQ_MODIFY_QP_NEW_STATE_RTR;
	case IB_QPS_RTS:
		return CMDQ_MODIFY_QP_NEW_STATE_RTS;
	case IB_QPS_SQD:
		return CMDQ_MODIFY_QP_NEW_STATE_SQD;
	case IB_QPS_SQE:
		return CMDQ_MODIFY_QP_NEW_STATE_SQE;
	case IB_QPS_ERR:
	default:
		return CMDQ_MODIFY_QP_NEW_STATE_ERR;
	}
}

static enum ib_qp_state __to_ib_qp_state(u8 state)
{
	switch (state) {
	case CMDQ_MODIFY_QP_NEW_STATE_RESET:
		return IB_QPS_RESET;
	case CMDQ_MODIFY_QP_NEW_STATE_INIT:
		return IB_QPS_INIT;
	case CMDQ_MODIFY_QP_NEW_STATE_RTR:
		return IB_QPS_RTR;
	case CMDQ_MODIFY_QP_NEW_STATE_RTS:
		return IB_QPS_RTS;
	case CMDQ_MODIFY_QP_NEW_STATE_SQD:
		return IB_QPS_SQD;
	case CMDQ_MODIFY_QP_NEW_STATE_SQE:
		return IB_QPS_SQE;
	case CMDQ_MODIFY_QP_NEW_STATE_ERR:
	default:
		return IB_QPS_ERR;
	}
}

static u32 __from_ib_mtu(enum ib_mtu mtu)
{
	switch (mtu) {
	case IB_MTU_256:
		return CMDQ_MODIFY_QP_PATH_MTU_MTU_256;
	case IB_MTU_512:
		return CMDQ_MODIFY_QP_PATH_MTU_MTU_512;
	case IB_MTU_1024:
		return CMDQ_MODIFY_QP_PATH_MTU_MTU_1024;
	case IB_MTU_2048:
		return CMDQ_MODIFY_QP_PATH_MTU_MTU_2048;
	case IB_MTU_4096:
		return CMDQ_MODIFY_QP_PATH_MTU_MTU_4096;
//	case IB_MTU_8192:
//		return CMDQ_MODIFY_QP_PATH_MTU_MTU_8192;
	default:
		return CMDQ_MODIFY_QP_PATH_MTU_MTU_2048;
	}
}

static enum ib_mtu __to_ib_mtu(u32 mtu)
{
	switch (mtu & CREQ_QUERY_QP_RESP_SB_PATH_MTU_MASK) {
	case CMDQ_MODIFY_QP_PATH_MTU_MTU_256:
		return IB_MTU_256;
	case CMDQ_MODIFY_QP_PATH_MTU_MTU_512:
		return IB_MTU_512;
	case CMDQ_MODIFY_QP_PATH_MTU_MTU_1024:
		return IB_MTU_1024;
	case CMDQ_MODIFY_QP_PATH_MTU_MTU_2048:
		return IB_MTU_2048;
	case CMDQ_MODIFY_QP_PATH_MTU_MTU_4096:
		return IB_MTU_4096;
	case CMDQ_MODIFY_QP_PATH_MTU_MTU_8192:
		return IB_MTU_8192;
	default:
		return IB_MTU_2048;
	}
}

static int __from_ib_access_flags(int iflags)
{
	int qflags = 0;

	if (iflags & IB_ACCESS_LOCAL_WRITE)
		qflags |= BNXT_QPLIB_ACCESS_LOCAL_WRITE;
	if (iflags & IB_ACCESS_REMOTE_READ)
		qflags |= BNXT_QPLIB_ACCESS_REMOTE_READ;
	if (iflags & IB_ACCESS_REMOTE_WRITE)
		qflags |= BNXT_QPLIB_ACCESS_REMOTE_WRITE;
	if (iflags & IB_ACCESS_REMOTE_ATOMIC)
		qflags |= BNXT_QPLIB_ACCESS_REMOTE_ATOMIC;
	if (iflags & IB_ACCESS_MW_BIND)
		qflags |= BNXT_QPLIB_ACCESS_MW_BIND;
#ifdef HAVE_IB_ZERO_BASED
	if (iflags & IB_ZERO_BASED)
		qflags |= BNXT_QPLIB_ACCESS_ZERO_BASED;
#endif
#ifdef HAVE_IB_ACCESS_ON_DEMAND
	if (iflags & IB_ACCESS_ON_DEMAND)
		qflags |= BNXT_QPLIB_ACCESS_ON_DEMAND;
#endif
	return qflags;
};

static enum ib_access_flags __to_ib_access_flags(int qflags)
{
	enum ib_access_flags iflags = 0;

	if (qflags & BNXT_QPLIB_ACCESS_LOCAL_WRITE)
		iflags |= IB_ACCESS_LOCAL_WRITE;
	if (qflags & BNXT_QPLIB_ACCESS_REMOTE_WRITE)
		iflags |= IB_ACCESS_REMOTE_WRITE;
	if (qflags & BNXT_QPLIB_ACCESS_REMOTE_READ)
		iflags |= IB_ACCESS_REMOTE_READ;
	if (qflags & BNXT_QPLIB_ACCESS_REMOTE_ATOMIC)
		iflags |= IB_ACCESS_REMOTE_ATOMIC;
	if (qflags & BNXT_QPLIB_ACCESS_MW_BIND)
		iflags |= IB_ACCESS_MW_BIND;
#ifdef HAVE_IB_ZERO_BASED
	if (qflags & BNXT_QPLIB_ACCESS_ZERO_BASED)
		iflags |= IB_ZERO_BASED;
#endif
#ifdef HAVE_IB_ACCESS_ON_DEMAND
	if (qflags & BNXT_QPLIB_ACCESS_ON_DEMAND)
		iflags |= IB_ACCESS_ON_DEMAND;
#endif
	return iflags;
};

static int bnxt_re_copy_to_udata(struct bnxt_re_dev *rdev, void *data, int len,
				 struct ib_udata *udata)
{
	int rc;

	rc = ib_copy_to_udata(udata, data, len);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "ucontext copy failed!");
		return -EFAULT;
	}
	return 0;
}

static int bnxt_re_build_sgl(struct ib_sge *ib_sg_list,
			     struct bnxt_qplib_sge *sg_list, int num)
{
	int i, total = 0;

	for (i = 0; i < num; i++) {
		sg_list[i].addr = ib_sg_list[i].addr;
		sg_list[i].lkey = ib_sg_list[i].lkey;
		sg_list[i].size = ib_sg_list[i].length;
		total += sg_list[i].size;
	}
	return total;
}

/* Device */
#ifdef HAVE_IB_GET_NETDEV
struct net_device *bnxt_re_get_netdev(struct ib_device *ibdev, u8 port_num)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct net_device *netdev = NULL;

	rcu_read_lock();
	if (rdev)
		netdev = rdev->netdev;
	if (netdev)
		dev_hold(netdev);

	rcu_read_unlock();
	return netdev;
}
#endif

#ifdef HAVE_IB_QUERY_DEVICE_UDATA
int bnxt_re_query_device(struct ib_device *ibdev,
			 struct ib_device_attr *ib_attr,
			 struct ib_udata *udata)
#else
int bnxt_re_query_device(struct ib_device *ibdev,
			 struct ib_device_attr *ib_attr)
#endif
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct bnxt_qplib_dev_attr *dev_attr = &rdev->dev_attr;

	memset(ib_attr, 0, sizeof(*ib_attr));

	ib_attr->fw_ver = (u64)dev_attr->fw_ver;
	bnxt_qplib_get_guid(rdev->netdev->dev_addr,
			    (u8 *)&ib_attr->sys_image_guid);
	ib_attr->max_mr_size = BNXT_RE_MAX_MR_SIZE;
	ib_attr->page_size_cap = BNXT_RE_PAGE_SIZE_4K;
#if 0
	BNXT_RE_PAGE_SIZE_8K |
	BNXT_RE_PAGE_SIZE_64K | BNXT_RE_PAGE_SIZE_2M |
	BNXT_RE_PAGE_SIZE_8M | BNXT_RE_PAGE_SIZE_1G;
#endif
	ib_attr->vendor_id = rdev->en_dev->pdev->vendor;
	ib_attr->vendor_part_id = rdev->en_dev->pdev->device;
	ib_attr->hw_ver = rdev->en_dev->pdev->subsystem_device;
	ib_attr->max_qp = dev_attr->max_qp;
	ib_attr->max_qp_wr = dev_attr->max_qp_wqes;
	ib_attr->device_cap_flags =
				    IB_DEVICE_CURR_QP_STATE_MOD
				    | IB_DEVICE_RC_RNR_NAK_GEN
				    | IB_DEVICE_SHUTDOWN_PORT
				    | IB_DEVICE_SYS_IMAGE_GUID
				    | IB_DEVICE_LOCAL_DMA_LKEY
				    | IB_DEVICE_RESIZE_MAX_WR
				    | IB_DEVICE_PORT_ACTIVE_EVENT
				    | IB_DEVICE_N_NOTIFY_CQ
				    | IB_DEVICE_MEM_WINDOW
				    | IB_DEVICE_MEM_WINDOW_TYPE_2B
#ifdef USE_SIGNATURE_HANDOVER
				    | IB_DEVICE_SIGNATURE_HANDOVER
#endif
				    | IB_DEVICE_MEM_MGT_EXTENSIONS;
	ib_attr->max_sge = dev_attr->max_qp_sges;
	ib_attr->max_sge_rd = dev_attr->max_qp_sges;
	ib_attr->max_cq = dev_attr->max_cq;
	ib_attr->max_cqe = dev_attr->max_cq_wqes;
	ib_attr->max_mr = dev_attr->max_mr;
	ib_attr->max_pd = dev_attr->max_pd;
	ib_attr->max_qp_rd_atom = dev_attr->max_qp_rd_atom;
	ib_attr->max_qp_init_rd_atom = dev_attr->max_qp_init_rd_atom;
	if (dev_attr->is_atomic) {
		ib_attr->atomic_cap = IB_ATOMIC_HCA;
		ib_attr->masked_atomic_cap = IB_ATOMIC_HCA;
	}

	ib_attr->max_ee_rd_atom = 0;
	ib_attr->max_res_rd_atom = 0;
	ib_attr->max_ee_init_rd_atom = 0;
	ib_attr->max_ee = 0;
	ib_attr->max_rdd = 0;
	ib_attr->max_mw = dev_attr->max_mw;
	ib_attr->max_raw_ipv6_qp = 0;
	ib_attr->max_raw_ethy_qp = dev_attr->max_raw_ethy_qp;
	ib_attr->max_mcast_grp = 0;
	ib_attr->max_mcast_qp_attach = 0;
	ib_attr->max_total_mcast_qp_attach = 0;
	ib_attr->max_ah = dev_attr->max_ah;
#ifdef USE_IB_FMR
	ib_attr->max_fmr = dev_attr->max_fmr;
	ib_attr->max_map_per_fmr = 1;
#endif

	ib_attr->max_srq = dev_attr->max_srq;
	ib_attr->max_srq_wr = dev_attr->max_srq_wqes;
	ib_attr->max_srq_sge = dev_attr->max_srq_sges;

	ib_attr->max_fast_reg_page_list_len = MAX_PBL_LVL_1_PGS;
	/* TODO: Chip allows up to MAX_PBL_LVL_2_PGS for fast_reg page list */
	//ib_attr->max_fast_reg_page_list_len = MAX_PBL_LVL_2_PGS;

	/* TODO: Support 1 pkey for now */
	//ib_attr->max_pkeys = dev_attr->max_pkey;
	ib_attr->max_pkeys = 1;
	ib_attr->local_ca_ack_delay = 0;
#ifdef HAVE_IB_ODP_CAPS
	ib_attr->sig_prot_cap = 0;
	ib_attr->sig_guard_cap = 0;
	ib_attr->odp_caps.general_caps = 0;
#endif
	return 0;
}

int bnxt_re_modify_device(struct ib_device *ibdev,
			  int device_modify_mask,
			  struct ib_device_modify *device_modify)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);

	dev_dbg(rdev_to_dev(rdev), "Modify device with mask 0x%x",
		device_modify_mask);

	switch (device_modify_mask) {
	case IB_DEVICE_MODIFY_SYS_IMAGE_GUID:
		/* Modify the GUID requires the modification of the GID table */
		/* GUID should be made as READ-ONLY */
		break;
	case IB_DEVICE_MODIFY_NODE_DESC:
		/* Node Desc should be made as READ-ONLY */
		break;
	default:
		break;
	}
	return 0;
}

static void __to_ib_speed_width(u32 espeed, u8 *speed, u8 *width)
{
	switch (espeed) {
	case SPEED_1000:
		*speed = IB_SPEED_SDR;
		*width = IB_WIDTH_1X;
		break;
	case SPEED_10000:
		*speed = IB_SPEED_QDR;
		*width = IB_WIDTH_1X;
		break;
	case SPEED_20000:
		*speed = IB_SPEED_DDR;
		*width = IB_WIDTH_4X;
		break;
	case SPEED_25000:
		*speed = IB_SPEED_EDR;
		*width = IB_WIDTH_1X;
		break;
	case SPEED_40000:
		*speed = IB_SPEED_QDR;
		*width = IB_WIDTH_4X;
		break;
	case SPEED_50000:
		*speed = IB_SPEED_HDR;
		*width = IB_WIDTH_1X;
		break;
	default:
		*speed = IB_SPEED_SDR;
		*width = IB_WIDTH_1X;
		break;
	}
}

/* Port */
int bnxt_re_query_port(struct ib_device *ibdev, u8 port_num,
		       struct ib_port_attr *port_attr)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct bnxt_qplib_dev_attr *dev_attr = &rdev->dev_attr;

	dev_dbg(rdev_to_dev(rdev), "QUERY PORT with port_num 0x%x", port_num);
	memset(port_attr, 0, sizeof(*port_attr));

	if (netif_running(rdev->netdev) && netif_carrier_ok(rdev->netdev)) {
		port_attr->state = IB_PORT_ACTIVE;
		port_attr->phys_state = 5;
	} else {
		port_attr->state = IB_PORT_DOWN;
		port_attr->phys_state = 3;
	}
	port_attr->max_mtu = IB_MTU_4096;
	port_attr->active_mtu = iboe_get_mtu(rdev->netdev->mtu);
	port_attr->gid_tbl_len = dev_attr->max_sgid;
	/* TODO: port_cap_flags needs to be revisited */
	port_attr->port_cap_flags = IB_PORT_CM_SUP | IB_PORT_REINIT_SUP |
				    IB_PORT_DEVICE_MGMT_SUP |
				    IB_PORT_VENDOR_CLASS_SUP |
				    IB_PORT_IP_BASED_GIDS;

	/* TODO: Max MSG size set to 64K for now */
	port_attr->max_msg_sz = 1 << 16;
	port_attr->bad_pkey_cntr = 0;
	port_attr->qkey_viol_cntr = 0;
	port_attr->pkey_tbl_len = dev_attr->max_pkey;
	port_attr->lid = 0;
	port_attr->sm_lid = 0;
	port_attr->lmc = 0;
	port_attr->max_vl_num = 4;
	port_attr->sm_sl = 0;
	port_attr->subnet_timeout = 0;
	port_attr->init_type_reply = 0;

	if (test_bit(BNXT_RE_FLAG_IBDEV_REGISTERED, &rdev->flags))
		__to_ib_speed_width(rdev->espeed, &port_attr->active_speed,
				    &port_attr->active_width);
	return 0;
}

int bnxt_re_modify_port(struct ib_device *ibdev, u8 port_num,
			int port_modify_mask,
			struct ib_port_modify *port_modify)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);

	dev_dbg(rdev_to_dev(rdev), "Modify port with mask 0x%x",
		port_modify_mask);

	switch (port_modify_mask) {
	case IB_PORT_SHUTDOWN:
		break;
	case IB_PORT_INIT_TYPE:
		break;
	case IB_PORT_RESET_QKEY_CNTR:
		break;
	default:
		break;
	}
	return 0;
}

#ifdef HAVE_IB_GET_PORT_IMMUTABLE
int bnxt_re_get_port_immutable(struct ib_device *ibdev, u8 port_num,
			       struct ib_port_immutable *immutable)
{
	struct ib_port_attr port_attr;

	if (bnxt_re_query_port(ibdev, port_num, &port_attr))
		return -EINVAL;

	immutable->pkey_tbl_len = port_attr.pkey_tbl_len;
	immutable->gid_tbl_len = port_attr.gid_tbl_len;
	immutable->core_cap_flags = RDMA_CORE_PORT_IBA_ROCE;
#ifdef RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP
	immutable->core_cap_flags |= RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP;
#endif
	immutable->max_mad_size = IB_MGMT_MAD_SIZE;
	return 0;
}
#endif

int bnxt_re_query_pkey(struct ib_device *ibdev, u8 port_num,
		       u16 index, u16 *pkey)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);

	/* Ignore port_num */

	memset(pkey, 0, sizeof(*pkey));
	return bnxt_qplib_get_pkey(&rdev->qplib_res,
				   &rdev->qplib_res.pkey_tbl, index, pkey);
}

int bnxt_re_query_gid(struct ib_device *ibdev, u8 port_num,
		      int index, union ib_gid *gid)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	int rc = 0;

	/* Ignore port_num */
	memset(gid, 0, sizeof(*gid));
#ifdef USE_ROCE_GID_CACHE
	if (ib_cache_use_roce_gid_cache(ibdev, port_num)) {
		rc = bnxt_qplib_get_sgid(&rdev->qplib_res,
					 &rdev->qplib_res.sgid_tbl, index,
					 (struct bnxt_qplib_gid *)gid);
		goto out;
	}
	rc = ib_get_cached_gid(ibdev, port_num, index, gid, NULL);
	if (rc == -EAGAIN) {
		dev_err(rdev_to_dev(rdev),
			"GID not found in the gid cache table!");
		memcpy(gid, &zgid, sizeof(*gid));
		rc = 0;
	}
out:
#else
	rc = bnxt_qplib_get_sgid(&rdev->qplib_res,
				 &rdev->qplib_res.sgid_tbl, index,
				 (struct bnxt_qplib_gid *)gid);
#endif
	return rc;
}

#ifdef HAVE_IB_ADD_DEL_GID
int bnxt_re_del_gid(struct ib_device *ibdev, u8 port_num,
		    unsigned int index, void **context)
{
	int rc = 0;
	struct bnxt_re_gid_ctx *ctx, **ctx_tbl;
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct bnxt_qplib_sgid_tbl *sgid_tbl = &rdev->qplib_res.sgid_tbl;

	/* Delete the entry from the hardware */
	ctx = *context;
	if (!ctx) {
		dev_err(rdev_to_dev(rdev), "GID entry has no ctx?!");
		return -EINVAL;
	}
	if (sgid_tbl && sgid_tbl->active) {
		if (ctx->idx >= sgid_tbl->max) {
			dev_dbg(rdev_to_dev(rdev), "GID index out of range?!");
			return -EINVAL;
		}
		ctx->refcnt--;
		if (!ctx->refcnt) {
			rc = bnxt_qplib_del_sgid(sgid_tbl,
						 &sgid_tbl->tbl[ctx->idx],
						 true);
			if (!rc) {
				dev_dbg(rdev_to_dev(rdev), "GID remove success");
				ctx_tbl = sgid_tbl->ctx;
				ctx_tbl[ctx->idx] = NULL;
				kfree(ctx);
			}
			else {
				dev_err(rdev_to_dev(rdev),
					"Remove GID failed rc = 0x%x", rc);
			}
		}
	} else {
		dev_dbg(rdev_to_dev(rdev), "GID sgid_tbl does not exist!");
		return -EINVAL;
	}
	return rc;
}

int bnxt_re_add_gid(struct ib_device *ibdev, u8 port_num,
		    unsigned int index, const union ib_gid *gid,
		    const struct ib_gid_attr *attr, void **context)
{
	int rc;
	u32 tbl_idx = 0;
	u16 vlan_id = 0xFFFF;
	struct bnxt_re_gid_ctx *ctx, **ctx_tbl;
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct bnxt_qplib_sgid_tbl *sgid_tbl = &rdev->qplib_res.sgid_tbl;

	if ((attr->ndev) && is_vlan_dev(attr->ndev))
		vlan_id = vlan_dev_vlan_id(attr->ndev);

	rc = bnxt_qplib_add_sgid(sgid_tbl, (struct bnxt_qplib_gid *)gid,
				 rdev->qplib_res.netdev->dev_addr,
				 vlan_id, true, &tbl_idx);
	if (rc == -EALREADY) {
		dev_dbg(rdev_to_dev(rdev), "GID %pI6 is already present", gid);
		ctx_tbl = sgid_tbl->ctx;
		ctx_tbl[tbl_idx]->refcnt++;
		*context = ctx_tbl[tbl_idx];
		return 0;
	} else if (rc < 0) {
		dev_err(rdev_to_dev(rdev), "Add GID failed rc = 0x%x", rc);
		return rc;
	} else {
		ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
		if (!ctx) {
			dev_err(rdev_to_dev(rdev), "Add GID ctx failed");
			return -ENOMEM;
		}
		ctx_tbl = sgid_tbl->ctx;
		ctx->idx = tbl_idx;
		ctx->refcnt = 1;
		ctx_tbl[tbl_idx] = ctx;
		*context = ctx;
	}
	return rc;
}
#endif

#ifdef HAVE_IB_MODIFY_GID
int bnxt_re_modify_gid(struct ib_device *ibdev, u8 port_num,
		    unsigned int index, const union ib_gid *gid,
		    const struct ib_gid_attr *attr, void **context)
{
	int rc = 0;
	u16 vlan_id = 0xFFFF;

#ifdef USE_ROCE_GID_CACHE
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct bnxt_qplib_sgid_tbl *sgid_tbl = &rdev->qplib_res.sgid_tbl;
	struct bnxt_re_gid_ctx *ctx, **ctx_tbl;

	if (ib_cache_use_roce_gid_cache(ibdev, port_num))
		return -EINVAL;
	if (!memcmp(&zgid, gid, sizeof(*gid))) {
		/* Delete the entry from the hardware */
		ctx = *context;
		if (!ctx) {
			dev_err(rdev_to_dev(rdev), "GID entry has no ctx?!");
			return -EINVAL;
		}
		if (sgid_tbl && sgid_tbl->active) {
			if (ctx->idx >= sgid_tbl->max) {
				dev_dbg(rdev_to_dev(rdev),
					"GID index out of range?!");
				return -EINVAL;
			}
			rc = bnxt_qplib_del_sgid(&rdev->qplib_res, sgid_tbl,
					&sgid_tbl->tbl[ctx->idx], true);
			if (!rc)
				dev_dbg(rdev_to_dev(rdev),
					"GID removed successfully");
			else
				dev_err(rdev_to_dev(rdev),
					"Remove GID failed rc = 0x%x", rc);
			ctx_tbl = sgid_tbl->ctx;
			ctx_tbl[ctx->idx] = NULL;
			kfree(ctx);
		} else {
			dev_dbg(rdev_to_dev(rdev),
				"GID sgid_tbl does not exist!");
			return -EINVAL;
		}
	} else {
		ctx = kmalloc(sizeof(*ctx), GFP_KERNEL);
		if (!ctx) {
			dev_err(rdev_to_dev(rdev), "Add GID ctx failed");
			return -ENOMEM;
		}
		rc = bnxt_qplib_add_sgid(sgid_tbl, (struct bnxt_qplib_gid *)gid,
					 rdev->qplib_res.netdev->dev_addr,
					 vlan_id, true, &ctx->idx);
		if (rc == -EALREADY) {
			dev_dbg(rdev_to_dev(rdev),
				"GID is already present at index %d", ctx->idx);
			ctx_tbl = sgid_tbl->ctx;
			*context = ctx_tbl[ctx->idx];
			kfree(ctx);
			rc = 0;
		} else if (rc < 0) {
			dev_err(rdev_to_dev(rdev), "Add GID failed rc = 0x%x",
				rc);
			kfree(ctx);
		} else {
			dev_dbg(rdev_to_dev(rdev),
				"GID added to index sgid_idx %d", ctx->idx);
			ctx_tbl = sgid_tbl->ctx;
			ctx_tbl[ctx->idx] = ctx;
			*context = ctx;
		}
	}
#endif
	return rc;
}
#endif

enum rdma_link_layer bnxt_re_get_link_layer(struct ib_device *ibdev,
					    u8 port_num)
{
	return IB_LINK_LAYER_ETHERNET;
}

#ifdef BIND_MW_FENCE_WQE

#define BNXT_RE_FENCE_BYTES	64
#define	BNXT_RE_FENCE_PBL_SIZE	DIV_ROUND_UP(BNXT_RE_FENCE_BYTES, PAGE_SIZE)

static void bnxt_re_create_fence_wqe(struct bnxt_re_pd *pd)
{
	struct bnxt_re_fence_data *fence = &pd->fence;
	struct ib_mr *ib_mr = &fence->mr->ib_mr;
	struct bnxt_qplib_swqe *wqe = &fence->bind_wqe;

	memset(wqe, 0, sizeof(*wqe));
	wqe->type = BNXT_QPLIB_SWQE_TYPE_BIND_MW;
	wqe->wr_id = BNXT_QPLIB_FENCE_WRID;
	wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP;
	wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
	wqe->bind.zero_based = false;
	wqe->bind.parent_l_key = ib_mr->lkey;
	wqe->bind.va = (u64)fence->va;
	wqe->bind.length = fence->size;
	wqe->bind.access_cntl = __from_ib_access_flags(IB_ACCESS_REMOTE_READ);
	wqe->bind.mw_type = SQ_BIND_MW_TYPE_TYPE1;

	/* Save the initial rkey in fence structure for now;
	 * wqe->bind.r_key will be set at (re)bind time.
	 */
	fence->bind_rkey = ib_inc_rkey(fence->mw->rkey);
}

int bnxt_re_bind_fence_mw(struct bnxt_qplib_qp *qplib_qp)
{
	struct bnxt_re_qp *qp = container_of(qplib_qp, struct bnxt_re_qp,
					     qplib_qp);
	struct ib_pd *ib_pd = qp->ib_qp.pd;
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_fence_data *fence = &pd->fence;
	struct bnxt_qplib_swqe *fence_wqe = &fence->bind_wqe;
	struct bnxt_qplib_swqe wqe;
	int rc;

	/* TODO: Need SQ locking here when Fence WQE
	 * posting moves up into bnxt_re from bnxt_qplib.
	 */
	memcpy(&wqe, fence_wqe, sizeof(wqe));
	wqe.bind.r_key = fence->bind_rkey;
	fence->bind_rkey = ib_inc_rkey(fence->bind_rkey);

	dev_dbg(rdev_to_dev(qp->rdev),
		"Posting bind fence-WQE: rkey: %#x QP: %d PD: %p\n",
		wqe.bind.r_key, qp->qplib_qp.id, pd);
	rc = bnxt_qplib_post_send(&qp->qplib_qp, &wqe);
	if (rc) {
		dev_err(rdev_to_dev(qp->rdev), "Failed to bind fence-WQE\n");
		return rc;
	}
	bnxt_qplib_post_send_db(&qp->qplib_qp);

	return rc;
}

static void bnxt_re_destroy_fence_mr(struct bnxt_re_pd *pd)
{
	struct bnxt_re_fence_data *fence = &pd->fence;
	struct bnxt_re_dev *rdev = pd->rdev;
	struct device *dev = rdev->ibdev.dma_device;
	struct bnxt_re_mr *mr = fence->mr;

	if (fence->mw) {
		bnxt_re_dealloc_mw(fence->mw);
		fence->mw = NULL;
	}
	if (mr) {
		if (mr->ib_mr.rkey)
			bnxt_qplib_dereg_mrw(&rdev->qplib_res, &mr->qplib_mr,
					     true);
		if (mr->ib_mr.lkey)
			bnxt_qplib_free_mrw(&rdev->qplib_res, &mr->qplib_mr);
		kfree(mr);
		fence->mr = NULL;
	}
	if (fence->dma_addr) {
		dma_unmap_single(dev, fence->dma_addr, BNXT_RE_FENCE_BYTES,
				 DMA_BIDIRECTIONAL);
		fence->dma_addr = 0;
	}
	if (fence->va) {
		kfree(fence->va);
		fence->va = NULL;
	}
}

static int bnxt_re_create_fence_mr(struct bnxt_re_pd *pd)
{
	int mr_access_flags = IB_ACCESS_LOCAL_WRITE | IB_ACCESS_MW_BIND;
	struct bnxt_re_fence_data *fence = &pd->fence;
	struct bnxt_re_dev *rdev = pd->rdev;
	struct device *dev = rdev->ibdev.dma_device;
	struct bnxt_re_mr *mr = NULL;
	dma_addr_t dma_addr = 0;
	struct ib_mw *mw;
	void *va = NULL;
	u64 pbl_tbl;
	int rc;

	/* Allocate a small chunk of memory and dma-map it */
	fence->va = kzalloc(BNXT_RE_FENCE_BYTES, GFP_KERNEL);
	dma_addr = dma_map_single(dev, va, BNXT_RE_FENCE_BYTES,
				  DMA_BIDIRECTIONAL);
	rc = dma_mapping_error(dev, dma_addr);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Failed to dma-map fence-MR-mem\n");
		rc = -EIO;
		fence->dma_addr = 0;
		goto fail;
	}
	fence->dma_addr = dma_addr;

	/* Allocate a MR */
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	fence->mr = mr;
	mr->rdev = rdev;
	mr->qplib_mr.pd = &pd->qplib_pd;
	mr->qplib_mr.type = CMDQ_ALLOCATE_MRW_MRW_FLAGS_PMR;
	mr->qplib_mr.flags = __from_ib_access_flags(mr_access_flags);
	rc = bnxt_qplib_alloc_mrw(&rdev->qplib_res, &mr->qplib_mr);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Failed to alloc fence-HW-MR\n");
		goto fail;
	}

	/* Register MR */
	mr->ib_mr.lkey = mr->qplib_mr.lkey;
	mr->qplib_mr.va         = (u64)va;
	mr->qplib_mr.total_size = BNXT_RE_FENCE_BYTES;
	pbl_tbl = dma_addr;
	rc = bnxt_qplib_reg_mr(&rdev->qplib_res, &mr->qplib_mr, &pbl_tbl,
			       BNXT_RE_FENCE_PBL_SIZE, false);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Failed to register fence-MR\n");
		goto fail;
	}
	mr->ib_mr.rkey = mr->qplib_mr.rkey;

	/* Create a fence MW only for kernel consumers */
#ifdef HAVE_IB_MW_TYPE
	mw = bnxt_re_alloc_mw(&pd->ib_pd, IB_MW_TYPE_1
#ifdef HAVE_ALLOW_MW_WITH_UDATA
			      , NULL
#endif
			      );
#else
	mw = bnxt_re_alloc_mw(&pd->ib_pd);
#endif
	if (!mw) {
		dev_err(rdev_to_dev(rdev),
			"Failed to create fence-MW for PD: %p\n", pd);
		rc = -EINVAL;
		goto fail;
	}
	fence->mw = mw;

	bnxt_re_create_fence_wqe(pd);
	return 0;

fail:
	bnxt_re_destroy_fence_mr(pd);
	return rc;
}

#endif

/* Protection Domains */
int bnxt_re_dealloc_pd(struct ib_pd *ib_pd)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	int rc;

#ifdef BIND_MW_FENCE_WQE
	bnxt_re_destroy_fence_mr(pd);
#endif
	if (pd->qplib_pd.id) { /* prevent double free */
		rc = bnxt_qplib_dealloc_pd(&rdev->qplib_res,
					   &rdev->qplib_res.pd_tbl,
					   &pd->qplib_pd);
		if (rc)
			dev_err(rdev_to_dev(rdev),
				"Deallocate HW Protection Domain failed!");
	}

	kfree(pd);
	return 0;
}

struct ib_pd *bnxt_re_alloc_pd(struct ib_device *ibdev,
			       struct ib_ucontext *ucontext,
			       struct ib_udata *udata)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct bnxt_re_ucontext *ucntx = to_bnxt_re(ucontext,
						    struct bnxt_re_ucontext,
						    ib_uctx);
	struct bnxt_re_pd *pd;
	int rc;

	pd = kzalloc(sizeof(*pd), GFP_KERNEL);
	if (!pd) {
		dev_err(rdev_to_dev(rdev),
			"Allocate Protection Domain failed!");
		return ERR_PTR(-ENOMEM);
	}
	pd->rdev = rdev;
	if (bnxt_qplib_alloc_pd(&rdev->qplib_res.pd_tbl, &pd->qplib_pd)) {
		dev_err(rdev_to_dev(rdev),
			"Allocate HW Protection Domain failed!");
		rc = -ENOMEM;
		goto fail;
	}

	if (udata) {
		struct bnxt_re_pd_resp resp;

		if (!ucntx->dpi.dbr) {
			/* Allocate DPI in alloc_pd to avoid failing of
			 * ibv_devinfo and family of application when DPIs
			 * are depleted.
			 */
			if (bnxt_qplib_alloc_dpi(&rdev->qplib_res.dpi_tbl,
						 &ucntx->dpi, ucntx)) {
				dev_err(rdev_to_dev(rdev),
					"Alloc Doorbell page failed!");
				rc = -ENOMEM;
				goto dbfail;
			}
		}

		resp.pdid = pd->qplib_pd.id;
		/* Still allow mapping this DBR to the new user PD. */
		resp.dpi = ucntx->dpi.dpi;
		resp.dbr = (u64)ucntx->dpi.umdbr;

		if ((rc = ib_copy_to_udata(udata, &resp, sizeof(resp)))) {
			dev_err(rdev_to_dev(rdev),
				"Failed to copy user response\n");
			goto dbfail;
		}
	}

#ifdef BIND_MW_FENCE_WQE
	if (!udata)
		if (bnxt_re_create_fence_mr(pd))
			dev_warn(rdev_to_dev(rdev),
				 "Failed to create Fence-MR\n");
#endif
	return &pd->ib_pd;
dbfail:
	(void)bnxt_qplib_dealloc_pd(&rdev->qplib_res, &rdev->qplib_res.pd_tbl,
				    &pd->qplib_pd);
fail:
	kfree(pd);
	return ERR_PTR(rc);
}

/* Address Handles */
int bnxt_re_destroy_ah(struct ib_ah *ib_ah)
{
	struct bnxt_re_ah *ah = to_bnxt_re(ib_ah, struct bnxt_re_ah, ib_ah);
	struct bnxt_re_dev *rdev = ah->rdev;
	int rc;

	rc = bnxt_qplib_destroy_ah(&rdev->qplib_res, &ah->qplib_ah);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Destroy HW Address Handle failed!");
		return rc;
	}
	kfree(ah);
	return 0;
}

#ifndef HAVE_IB_AH_DMAC
static void bnxt_re_resolve_dmac(struct bnxt_re_dev *rdev, u8 *dmac,
				 struct bnxt_qplib_gid *dgid)
{
	struct in6_addr in6;

	memcpy(&in6, dgid->data, sizeof(in6));
	if (rdma_is_multicast_addr(&in6))
		rdma_get_mcast_mac(&in6, dmac);
	else if (rdma_link_local_addr(&in6))
		rdma_get_ll_mac(&in6, dmac);
	else
		dev_err(rdev_to_dev(rdev),
			"Unable to resolve Dest MAC from the provided dgid");
}
#endif

struct ib_ah *bnxt_re_create_ah(struct ib_pd *ib_pd,
				struct ib_ah_attr *ah_attr)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_ah *ah;
	int rc;
#ifdef RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP
	u16 vlan_tag;
	u8 nw_type;
#endif
#ifdef HAVE_IB_GID_ATTR
	struct ib_gid_attr sgid_attr;
#endif

	if (!(ah_attr->ah_flags & IB_AH_GRH)) {
		dev_err(rdev_to_dev(rdev),
			"Allocate AH failed, ah_attr->ah_flags GRH is not set");
//		return ERR_PTR(-EINVAL);
	}
	ah = kzalloc(sizeof(*ah), GFP_ATOMIC);
	if (!ah) {
		dev_err(rdev_to_dev(rdev), "Allocate Address Handle failed!");
		return ERR_PTR(-ENOMEM);
	}
	ah->rdev = rdev;
	ah->qplib_ah.pd = &pd->qplib_pd;

	/* Supply the configuration for the HW */
	memcpy(ah->qplib_ah.dgid.data, ah_attr->grh.dgid.raw,
	       sizeof(union ib_gid));
#ifdef RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP
	/*
	 * TODO If RoCE V2 is enabled, stack will have two entries for
	 * each GID entry. Avoiding this duplicte entry in HW. Dividing
	 * the GID index by 2 for RoCE V2
	 */
	ah->qplib_ah.sgid_index = ah_attr->grh.sgid_index / 2;
#else
	ah->qplib_ah.sgid_index = ah_attr->grh.sgid_index;
#endif
	ah->qplib_ah.host_sgid_index = ah_attr->grh.sgid_index;
	ah->qplib_ah.traffic_class = ah_attr->grh.traffic_class;
	ah->qplib_ah.flow_label = ah_attr->grh.flow_label;
	ah->qplib_ah.hop_limit = ah_attr->grh.hop_limit;
	ah->qplib_ah.sl = ah_attr->sl;
#ifdef ENABLE_ROCE_TOS
	ah->qplib_ah.enable_cc = tos_ecn != 0;
#endif
#ifdef HAVE_IB_AH_DMAC
	if (ib_pd->uobject &&
	    !rdma_is_multicast_addr((struct in6_addr *)
				    ah_attr->grh.dgid.raw) &&
	    !rdma_link_local_addr((struct in6_addr *)
				  ah_attr->grh.dgid.raw)) {
		union ib_gid sgid;
#ifdef RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP
		rc = ib_get_cached_gid(&rdev->ibdev, 1,
				       ah_attr->grh.sgid_index, &sgid,
				       &sgid_attr);
		if (rc) {
			dev_err(rdev_to_dev(rdev),
				"Failed to query gid at index %d",
				ah_attr->grh.sgid_index);
			goto fail;
		}
		if (sgid_attr.ndev) {
			if (is_vlan_dev(sgid_attr.ndev))
				vlan_tag = vlan_dev_vlan_id(sgid_attr.ndev);
			dev_put(sgid_attr.ndev);
		}
		/* Get network header type for this GID */
		nw_type = ib_gid_to_network_type(sgid_attr.gid_type, &sgid);
		switch (nw_type) {
			case RDMA_NETWORK_IPV4:
				ah->qplib_ah.nw_type = CMDQ_CREATE_AH_TYPE_V2IPV4;
				break;
			case RDMA_NETWORK_IPV6:
				ah->qplib_ah.nw_type = CMDQ_CREATE_AH_TYPE_V2IPV6;
				break;
			default:
				ah->qplib_ah.nw_type = CMDQ_CREATE_AH_TYPE_V1;
				break;
		}
		rc = rdma_addr_find_l2_eth_by_grh(&sgid, &ah_attr->grh.dgid,
						  ah_attr->dmac, &vlan_tag,
						  &sgid_attr.ndev->ifindex,
                                                  NULL);
		if (rc) {
			dev_err(rdev_to_dev(rdev), "Failed to get dmac\n");
			goto fail;
		}
#else
		rc = ib_query_gid(&rdev->ibdev, 1,
				  ah_attr->grh.sgid_index, &sgid, &sgid_attr);
		if (rc) {
			dev_err(rdev_to_dev(rdev),
				"Failed to query gid at index %d",
				ah_attr->grh.sgid_index);
			goto fail;
		}
		rc = rdma_addr_find_dmac_by_grh(&sgid, &ah_attr->grh.dgid,
					ah_attr->dmac, NULL, 0);
		if (rc) {
			dev_err(rdev_to_dev(rdev),
				"Failed to resolve dmac from gid. status = %d",
				rc);
			goto fail;
		}
		ah->qplib_ah.nw_type = CMDQ_CREATE_AH_TYPE_V1;
#endif
	}

	memcpy(ah->qplib_ah.dmac, ah_attr->dmac, ETH_ALEN);
#else
	bnxt_re_resolve_dmac(ah->qplib_ah.dmac, ah->qplib_ah.dgid.data);
#endif
	rc = bnxt_qplib_create_ah(&rdev->qplib_res, &ah->qplib_ah);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Allocate HW Address Handle failed!");
		goto fail;
	}

	/* Write AVID to shared page. */
	if (ib_pd->uobject) {
		struct ib_ucontext *ib_uctx = ib_pd->uobject->context;
		struct bnxt_re_ucontext *uctx;
		unsigned long flag;
		u32 *wrptr;

		uctx = to_bnxt_re(ib_uctx, struct bnxt_re_ucontext, ib_uctx);
		spin_lock_irqsave(&uctx->sh_lock, flag);
		wrptr = (u32 *)(uctx->shpg + BNXT_RE_AVID_OFFT);
		*wrptr = ah->qplib_ah.id;
		wmb(); /* make sure cache is updated. */
		spin_unlock_irqrestore(&uctx->sh_lock, flag);
	}

	return &ah->ib_ah;

fail:
	kfree(ah);
	return ERR_PTR(rc);
}

int bnxt_re_modify_ah(struct ib_ah *ib_ah, struct ib_ah_attr *ah_attr)
{

	return 0;
}

int bnxt_re_query_ah(struct ib_ah *ib_ah, struct ib_ah_attr *ah_attr)
{
	struct bnxt_re_ah *ah = to_bnxt_re(ib_ah, struct bnxt_re_ah, ib_ah);

	memcpy(ah_attr->grh.dgid.raw, ah->qplib_ah.dgid.data,
	       sizeof(union ib_gid));
	ah_attr->grh.sgid_index = ah->qplib_ah.host_sgid_index;
	ah_attr->grh.traffic_class = ah->qplib_ah.traffic_class;
	ah_attr->sl = ah->qplib_ah.sl;
#ifdef HAVE_IB_AH_DMAC
	memcpy(ah_attr->dmac, ah->qplib_ah.dmac, ETH_ALEN);
#endif
	ah_attr->ah_flags = IB_AH_GRH;
	ah_attr->port_num = 1;
	ah_attr->static_rate = 0;
	return 0;
}

/* Shared Receive Queues */
int bnxt_re_destroy_srq(struct ib_srq *ib_srq)
{
	struct bnxt_re_srq *srq = to_bnxt_re(ib_srq, struct bnxt_re_srq, ib_srq);
	struct bnxt_re_dev *rdev = srq->rdev;
	int rc;

	rc = bnxt_qplib_destroy_srq(&rdev->qplib_res, &srq->qplib_srq);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Destroy HW SRQ failed!");
		return rc;
	}

	if (srq->umem && !IS_ERR(srq->umem))
		ib_umem_release(srq->umem);
	/* TODO: Must free the actual SRQ DMA memory */
	kfree(srq);
	atomic_dec(&rdev->srq_count);
	rdev->nq.budget--;
	return 0;
}

static int bnxt_re_init_user_srq(struct bnxt_re_dev *rdev,
				 struct bnxt_re_pd *pd,
				 struct bnxt_re_srq *srq,
				 struct ib_udata *udata)
{
	struct bnxt_re_srq_req ureq;
	struct bnxt_qplib_srq *qplib_srq = &srq->qplib_srq;
	struct ib_umem *umem;
	int bytes = 0;
	struct ib_ucontext *context = pd->ib_pd.uobject->context;
	struct bnxt_re_ucontext *cntx = to_bnxt_re(context,
						  struct bnxt_re_ucontext,
						  ib_uctx);
	if (ib_copy_from_udata(&ureq, udata, sizeof(ureq)))
		return -EFAULT;

	bytes = (qplib_srq->max_wqe * BNXT_QPLIB_MAX_RQE_ENTRY_SIZE);
	bytes = PAGE_ALIGN(bytes);
	umem = ib_umem_get(context, ureq.srqva, bytes,
			   IB_ACCESS_LOCAL_WRITE, 1);
	if (IS_ERR(umem))
		return PTR_ERR(umem);

	srq->umem = umem;
	qplib_srq->sglist = get_ib_umem_sgl(umem, &qplib_srq->nmap);
	qplib_srq->srq_handle = ureq.srq_handle;
	qplib_srq->dpi = &cntx->dpi;

	return 0;
}

struct ib_srq *bnxt_re_create_srq(struct ib_pd *ib_pd,
				  struct ib_srq_init_attr *srq_init_attr,
				  struct ib_udata *udata)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_qplib_dev_attr *dev_attr = &rdev->dev_attr;
	struct bnxt_re_srq *srq;
	struct bnxt_re_cq *cq;
	int rc, entries;

	if (srq_init_attr->attr.max_wr >= dev_attr->max_srq_wqes) {
		dev_err(rdev_to_dev(rdev), "Create CQ failed - max exceeded");
		rc = -EINVAL;
		goto exit;
	}
	srq = kzalloc(sizeof(*srq), GFP_KERNEL);
	if (!srq) {
		dev_err(rdev_to_dev(rdev), "Allocate SRQ failed!");
		rc = -ENOMEM;
		goto exit;
	}
	srq->rdev = rdev;
	srq->qplib_srq.pd = &pd->qplib_pd;
	srq->qplib_srq.dpi = &rdev->dpi_privileged;

	/* Allocate 1 more than what's provided so posting max doesn't
	   mean empty */
	entries = roundup_pow_of_two(srq_init_attr->attr.max_wr + 1);
	if (entries > dev_attr->max_srq_wqes + 1)
		entries = dev_attr->max_srq_wqes + 1;

	srq->qplib_srq.max_wqe = entries;
	srq->qplib_srq.max_sge = srq_init_attr->attr.max_sge;
	srq->qplib_srq.threshold = srq_init_attr->attr.srq_limit;
	srq->srq_limit = srq_init_attr->attr.srq_limit;
	if (srq_init_attr->srq_type != IB_SRQT_BASIC) {
		cq = to_bnxt_re(srq_init_attr->ext.xrc.cq, struct bnxt_re_cq,
				ib_cq);
		srq->qplib_srq.cq = &cq->qplib_cq;
	}

	srq->qplib_srq.eventq_hw_ring_id = rdev->nq.ring_id;

	if (udata) {
		rc = bnxt_re_init_user_srq(rdev, pd, srq, udata);
		if (rc)
			goto fail;
	}

	rc = bnxt_qplib_create_srq(&rdev->qplib_res, &srq->qplib_srq);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Create HW SRQ failed!");
		goto fail;
	}

	if (udata) {
		struct bnxt_re_srq_resp resp;

		resp.srqid = srq->qplib_srq.id;
		rc = bnxt_re_copy_to_udata(rdev, &resp, sizeof(resp), udata);
		if (rc) {
			dev_err(rdev_to_dev(rdev), "SRQ copy to udata failed!");
			bnxt_qplib_destroy_srq(&rdev->qplib_res, &srq->qplib_srq);
			goto exit;
		}
	}
	rdev->nq.budget++;
	atomic_inc(&rdev->srq_count);

	return &srq->ib_srq;

fail:
	if (udata && srq->umem && !IS_ERR(srq->umem)) {
		ib_umem_release(srq->umem);
		srq->umem = NULL;
	}

	kfree(srq);
exit:
	return ERR_PTR(rc);
}

int bnxt_re_modify_srq(struct ib_srq *ib_srq, struct ib_srq_attr *srq_attr,
		       enum ib_srq_attr_mask srq_attr_mask,
		       struct ib_udata *udata)
{
	struct bnxt_re_srq *srq = to_bnxt_re(ib_srq, struct bnxt_re_srq,
					     ib_srq);
	struct bnxt_re_dev *rdev = srq->rdev;
	int rc;

	switch (srq_attr_mask) {
	case IB_SRQ_MAX_WR:
		/* SRQ resize is not supported */
		break;
	case IB_SRQ_LIMIT:
		/* Change the SRQ threshold */
		if (srq_attr->srq_limit > srq->qplib_srq.max_wqe)
			return -EINVAL;

		srq->qplib_srq.threshold = srq_attr->srq_limit;
		rc = bnxt_qplib_modify_srq(&rdev->qplib_res, &srq->qplib_srq);
		if (rc) {
			dev_err(rdev_to_dev(rdev), "Modify HW SRQ failed!");
			return rc;
		}
		/* On success, update the shadow */
		srq->srq_limit = srq_attr->srq_limit;

		if (udata) {
			/* Build and send response back to udata */
			rc = bnxt_re_copy_to_udata(rdev, srq, 0, udata);
			if (rc) {
				dev_err(rdev_to_dev(rdev),
					"SRQ copy to udata failed!");
				return rc;
			}
		}
		break;
	default:
		dev_err(rdev_to_dev(rdev),
			"Unsupported srq_attr_mask 0x%x", srq_attr_mask);
		return -EINVAL;
	}
	return 0;
}

int bnxt_re_query_srq(struct ib_srq *ib_srq, struct ib_srq_attr *srq_attr)
{
	struct bnxt_re_srq *srq = to_bnxt_re(ib_srq, struct bnxt_re_srq,
					     ib_srq);
	struct bnxt_re_dev *rdev = srq->rdev;
	int rc;

	/* Get live SRQ attr */
	/*TODO: qplib query_srq is incomplete. */
	rc = bnxt_qplib_query_srq(&rdev->qplib_res, &srq->qplib_srq);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Query HW SRQ failed!");
		return rc;
	}
	srq_attr->max_wr = srq->qplib_srq.max_wqe;
	srq_attr->max_sge = srq->qplib_srq.max_sge;
	srq_attr->srq_limit = srq->qplib_srq.threshold;

	return 0;
}

int bnxt_re_post_srq_recv(struct ib_srq *ib_srq, struct ib_recv_wr *wr,
			  struct ib_recv_wr **bad_wr)
{
	struct bnxt_re_srq *srq = to_bnxt_re(ib_srq, struct bnxt_re_srq,
					     ib_srq);
	struct bnxt_qplib_swqe wqe;
	int rc = 0, payload_sz = 0;

	while (wr) {
		/* Transcribe each ib_recv_wr to qplib_swqe */
		wqe.num_sge = wr->num_sge;
		payload_sz = bnxt_re_build_sgl(wr->sg_list, wqe.sg_list,
					       wr->num_sge);
		wqe.wr_id = wr->wr_id;
		wqe.type = BNXT_QPLIB_SWQE_TYPE_RECV;

		rc = bnxt_qplib_post_srq_recv(&srq->qplib_srq, &wqe);
		if (rc) {
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}
	return rc;
}

/* Queue Pairs */
int bnxt_re_destroy_qp(struct ib_qp *ib_qp)
{
	struct bnxt_re_qp *qp = to_bnxt_re(ib_qp, struct bnxt_re_qp, ib_qp);
	struct bnxt_re_dev *rdev = qp->rdev;
	int rc;

	bnxt_qplib_del_flush_qp(&qp->qplib_qp);
	rc = bnxt_qplib_destroy_qp(&rdev->qplib_res, &qp->qplib_qp);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Destroy HW QP failed!");
		return rc;
	}
#ifdef ENABLE_SHADOW_QP
	if (ib_qp->qp_type == IB_QPT_GSI && rdev->qp1_sqp) {
		dev_dbg(rdev_to_dev(rdev), "Destroy the shadow QP also\n");
		rc = bnxt_qplib_destroy_ah(&rdev->qplib_res,
					   &rdev->sqp_ah->qplib_ah);
		if (rc) {
			dev_err(rdev_to_dev(rdev),
				"Destroy HW AH for shadow QP failed!");
			return rc;
		}

		bnxt_qplib_del_flush_qp(&qp->qplib_qp);
		rc = bnxt_qplib_destroy_qp(&rdev->qplib_res,
					   &rdev->qp1_sqp->qplib_qp);
		if (rc) {
			dev_err(rdev_to_dev(rdev), "Destroy Shadow QP failed");
			return rc;
		}
		mutex_lock(&rdev->qp_lock);
		list_del(&rdev->qp1_sqp->list);
		atomic_dec(&rdev->qp_count);
		mutex_unlock(&rdev->qp_lock);

		kfree(rdev->sqp_ah);
		kfree(rdev->qp1_sqp);
	}
#endif

	if (qp->rumem && !IS_ERR(qp->rumem))
		ib_umem_release(qp->rumem);
	if (qp->sumem && !IS_ERR(qp->sumem))
		ib_umem_release(qp->sumem);

	mutex_lock(&rdev->qp_lock);
	list_del(&qp->list);
	atomic_dec(&rdev->qp_count);
	mutex_unlock(&rdev->qp_lock);
	kfree(qp);
	return 0;
}

static u8 __from_ib_qp_type(enum ib_qp_type type)
{
	switch (type) {
	case IB_QPT_GSI:
		return CMDQ_CREATE_QP1_TYPE_GSI;
	case IB_QPT_RC:
		return CMDQ_CREATE_QP_TYPE_RC;
	case IB_QPT_UD:
		return CMDQ_CREATE_QP_TYPE_UD;
	case IB_QPT_RAW_ETHERTYPE:
		return CMDQ_CREATE_QP_TYPE_RAW_ETHERTYPE;
	default:
		return IB_QPT_MAX;
	}
}

int bnxt_re_init_user_qp(struct bnxt_re_dev *rdev, struct bnxt_re_pd *pd,
			 struct bnxt_re_qp *qp, struct ib_udata *udata)
{
	struct bnxt_re_qp_req ureq;
	struct bnxt_qplib_qp *qplib_qp = &qp->qplib_qp;
	struct ib_umem *umem;
	int bytes = 0;
	struct ib_ucontext *context = pd->ib_pd.uobject->context;
	struct bnxt_re_ucontext *cntx = to_bnxt_re(context,
						  struct bnxt_re_ucontext,
						  ib_uctx);
	if (ib_copy_from_udata(&ureq, udata, sizeof(ureq)))
		return -EFAULT;

	bytes = (qplib_qp->sq.max_wqe * BNXT_QPLIB_MAX_SQE_ENTRY_SIZE);
	/* Consider mapping PSN search memory only for RC QPs. */
	if (qplib_qp->type == CMDQ_CREATE_QP_TYPE_RC)
		bytes += (qplib_qp->sq.max_wqe * sizeof(struct sq_psn_search));
	bytes = PAGE_ALIGN(bytes);
	umem = ib_umem_get(context, ureq.qpsva, bytes,
			   IB_ACCESS_LOCAL_WRITE, 1);
	if (IS_ERR(umem))
		return PTR_ERR(umem);

	qp->sumem = umem;
	qplib_qp->sq.sglist = get_ib_umem_sgl(umem, &qplib_qp->sq.nmap);
	qplib_qp->qp_handle = ureq.qp_handle;

	if (!qp->qplib_qp.srq) {
		bytes = (qplib_qp->rq.max_wqe * BNXT_QPLIB_MAX_RQE_ENTRY_SIZE);
		bytes = PAGE_ALIGN(bytes);
		umem = ib_umem_get(context, ureq.qprva, bytes,
				   IB_ACCESS_LOCAL_WRITE, 1);
		if (IS_ERR(umem))
			goto rqfail;
		qp->rumem = umem;
		qplib_qp->rq.sglist = get_ib_umem_sgl(umem, &qplib_qp->rq.nmap);
	} /* TODO: Add srq. */

	qplib_qp->dpi = &cntx->dpi;

	return 0;

rqfail:
	ib_umem_release(qp->sumem);
	qp->sumem = NULL;
	qplib_qp->sq.sglist = NULL;
	qplib_qp->sq.nmap = 0;

	return PTR_ERR(umem);
}

#ifdef ENABLE_SHADOW_QP
struct bnxt_re_ah *bnxt_re_create_shadow_qp_ah(struct bnxt_re_pd *pd,
					       struct bnxt_qplib_res *qp1_res,
					       struct bnxt_qplib_qp *qp1_qp)
{
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_ah *ah;
	union ib_gid sgid;
	int rc;

	ah = kzalloc(sizeof(*ah), GFP_KERNEL);
	if (!ah) {
		dev_err(rdev_to_dev(rdev), "Allocate Address Handle failed!");
		return NULL;
	}
	memset(ah, 0, sizeof(*ah));
	ah->rdev = rdev;
	ah->qplib_ah.pd = &pd->qplib_pd;

	rc = bnxt_re_query_gid(&rdev->ibdev, 1, 0, &sgid);
	if (rc)
		goto fail;

	/* supply the dgid data same as sgid */
	memcpy(ah->qplib_ah.dgid.data, &sgid.raw,
	       sizeof(union ib_gid));
	ah->qplib_ah.sgid_index = 0;

	ah->qplib_ah.traffic_class = 0;
	ah->qplib_ah.flow_label = 0;
	ah->qplib_ah.hop_limit = 1;
	ah->qplib_ah.sl = 0;
	/* Have DMAC same as SMAC */
	memcpy(ah->qplib_ah.dmac, rdev->netdev->dev_addr, ETH_ALEN);

	rc = bnxt_qplib_create_ah(&rdev->qplib_res, &ah->qplib_ah);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Allocate HW AH for Shadow QP failed!");
		goto fail;
	}
	dev_dbg(rdev_to_dev(rdev), "AH ID = %d\n", ah->qplib_ah.id);

	return ah;

fail:
	kfree(ah);
	return NULL;
}

struct bnxt_re_qp *bnxt_re_create_shadow_qp(struct bnxt_re_pd *pd,
					    struct bnxt_qplib_res *qp1_res,
					    struct bnxt_qplib_qp *qp1_qp)
{
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_qp *qp;
	int rc;

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		dev_err(rdev_to_dev(rdev), "Allocate internal UD QP  failed!");
		return NULL;
	}
	memset(qp, 0, sizeof(*qp));
	qp->rdev = rdev;

	/* Initialize the shadow QP structure from the QP1 values */
	memcpy(qp->qplib_qp.smac, rdev->netdev->dev_addr, ETH_ALEN);

	qp->qplib_qp.pd = &pd->qplib_pd;
	qp->qplib_qp.qp_handle = (u64)&qp->qplib_qp;
	qp->qplib_qp.type = IB_QPT_UD;

	qp->qplib_qp.max_inline_data = 0;
	qp->qplib_qp.sig_type = true;

	/* Shadow QP SQ depth should be same as QP1 RQ depth */
	qp->qplib_qp.sq.max_wqe = qp1_qp->rq.max_wqe;
	qp->qplib_qp.sq.max_sge = 2;
	/* Q full delta can be 1 since it is internal QP */
	qp->qplib_qp.sq.q_full_delta = 1;

	qp->qplib_qp.scq = qp1_qp->scq;
	qp->qplib_qp.rcq = qp1_qp->rcq;

	qp->qplib_qp.rq.max_wqe = qp1_qp->rq.max_wqe;
	qp->qplib_qp.rq.max_sge = qp1_qp->rq.max_sge;
	/* Q full delta can be 1 since it is internal QP */
	qp->qplib_qp.rq.q_full_delta = 1;

	qp->qplib_qp.mtu = qp1_qp->mtu;

	qp->qplib_qp.sq_hdr_buf_size = 0;
	qp->qplib_qp.rq_hdr_buf_size = BNXT_QPLIB_MAX_GRH_HDR_SIZE_IPV6;
	qp->qplib_qp.dpi = &rdev->dpi_privileged;

	rc = bnxt_qplib_create_qp(qp1_res, &qp->qplib_qp);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "create HW QP failed!");
		goto fail;
	}

	rdev->sqp_id = qp->qplib_qp.id;
	dev_dbg(rdev_to_dev(rdev), "Created shadow QP with ID = %d\n",
		 rdev->sqp_id);

	spin_lock_init(&qp->sq_lock);
	INIT_LIST_HEAD(&qp->list);
	mutex_lock(&rdev->qp_lock);
	list_add_tail(&qp->list, &rdev->qp_list);
	atomic_inc(&rdev->qp_count);
	mutex_unlock(&rdev->qp_lock);
	return qp;
fail:
	kfree(qp);
	return NULL;
}
#endif

struct ib_qp *bnxt_re_create_qp(struct ib_pd *ib_pd,
				struct ib_qp_init_attr *qp_init_attr,
				struct ib_udata *udata)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_qplib_dev_attr *dev_attr = &rdev->dev_attr;
	struct bnxt_re_qp *qp;
	struct bnxt_re_srq *srq;
	struct bnxt_re_cq *cq;
	int rc, entries;

	if ((qp_init_attr->cap.max_send_wr > dev_attr->max_qp_wqes) ||
	    (qp_init_attr->cap.max_recv_wr > dev_attr->max_qp_wqes) ||
	    (qp_init_attr->cap.max_send_sge > dev_attr->max_qp_sges) ||
	    (qp_init_attr->cap.max_recv_sge > dev_attr->max_qp_sges) ||
	    (qp_init_attr->cap.max_inline_data > dev_attr->max_inline_data)) {
		dev_err(rdev_to_dev(rdev), "Create QP failed - max exceeded! "
			"0x%x/0x%x 0x%x/0x%x 0x%x/0x%x "
			"0x%x/0x%x 0x%x/0x%x",
			qp_init_attr->cap.max_send_wr, dev_attr->max_qp_wqes,
			qp_init_attr->cap.max_recv_wr, dev_attr->max_qp_wqes,
			qp_init_attr->cap.max_send_sge, dev_attr->max_qp_sges,
			qp_init_attr->cap.max_recv_sge, dev_attr->max_qp_sges,
			qp_init_attr->cap.max_inline_data,
			dev_attr->max_inline_data);
		rc = -EINVAL;
		goto exit;
	}
	/* TODO: Must qualify all other QP attributes */

	qp = kzalloc(sizeof(*qp), GFP_KERNEL);
	if (!qp) {
		dev_err(rdev_to_dev(rdev), "Allocate QP failed!");
		rc = -ENOMEM;
		goto exit;
	}
	qp->rdev = rdev;
	memcpy(qp->qplib_qp.smac, rdev->netdev->dev_addr, ETH_ALEN);
	qp->qplib_qp.pd = &pd->qplib_pd;
	qp->qplib_qp.qp_handle = (u64)&qp->qplib_qp;
	qp->qplib_qp.type = __from_ib_qp_type(qp_init_attr->qp_type);
	if (qp->qplib_qp.type == IB_QPT_MAX) {
		dev_err(rdev_to_dev(rdev), "QP type 0x%x not supported",
			qp->qplib_qp.type);
		rc = -EINVAL;
		goto fail;
	}
	qp->qplib_qp.max_inline_data = qp_init_attr->cap.max_inline_data;
	qp->qplib_qp.sig_type = ((qp_init_attr->sq_sig_type ==
				  IB_SIGNAL_ALL_WR) ? true : false);

	qp->qplib_qp.sq.max_sge = qp_init_attr->cap.max_send_sge;
	if (qp->qplib_qp.sq.max_sge > dev_attr->max_qp_sges)
		qp->qplib_qp.sq.max_sge = dev_attr->max_qp_sges;

	if (qp_init_attr->send_cq) {
		cq = to_bnxt_re(qp_init_attr->send_cq, struct bnxt_re_cq, ib_cq);
		if (!cq) {
			dev_err(rdev_to_dev(rdev), "Send CQ not found");
			rc = -EINVAL;
			goto fail;
		}
		qp->qplib_qp.scq = &cq->qplib_cq;
	}

	if (qp_init_attr->recv_cq) {
		cq = to_bnxt_re(qp_init_attr->recv_cq, struct bnxt_re_cq, ib_cq);
		if (!cq) {
			dev_err(rdev_to_dev(rdev), "Receive CQ not found");
			rc = -EINVAL;
			goto fail;
		}
		qp->qplib_qp.rcq = &cq->qplib_cq;
	}

	if (qp_init_attr->srq) {
		srq = to_bnxt_re(qp_init_attr->srq, struct bnxt_re_srq, ib_srq);
		if (!srq) {
			dev_err(rdev_to_dev(rdev), "SRQ not found");
			rc = -EINVAL;
			goto fail;
		}
		qp->qplib_qp.srq = &srq->qplib_srq;
		qp->qplib_qp.rq.max_wqe = 0;
	} else {
		/* Allocate 1 more than what's provided so posting max doesn't
		   mean empty */
		entries = roundup_pow_of_two(qp_init_attr->cap.max_recv_wr + 1);
		qp->qplib_qp.rq.max_wqe = min_t(u32, entries,
						dev_attr->max_qp_wqes + 1);

		qp->qplib_qp.rq.q_full_delta = qp->qplib_qp.rq.max_wqe -
						qp_init_attr->cap.max_recv_wr;
		qp->qplib_qp.rq.max_sge = qp_init_attr->cap.max_recv_sge;
		if (qp->qplib_qp.rq.max_sge > dev_attr->max_qp_sges)
			qp->qplib_qp.rq.max_sge = dev_attr->max_qp_sges;
	}
	if (qp_init_attr->create_flags)
		dev_dbg(rdev_to_dev(rdev),
			"QP create flags 0x%x not supported",
			qp_init_attr->create_flags);

	qp->qplib_qp.mtu = ib_mtu_enum_to_int(iboe_get_mtu(rdev->netdev->mtu));

	if (qp_init_attr->qp_type == IB_QPT_GSI) {
		//qp->qplib_qp.rq.max_sge += 4;
		/* Allocate 1 more than what's provided */
		entries = roundup_pow_of_two(qp_init_attr->cap.max_send_wr + 1);
		qp->qplib_qp.sq.max_wqe = min_t(u32, entries,
						dev_attr->max_qp_wqes + 1);
		qp->qplib_qp.sq.q_full_delta = qp->qplib_qp.sq.max_wqe -
						qp_init_attr->cap.max_send_wr;
		qp->qplib_qp.rq.max_sge = dev_attr->max_qp_sges;
		if (qp->qplib_qp.rq.max_sge > dev_attr->max_qp_sges)
			qp->qplib_qp.rq.max_sge = dev_attr->max_qp_sges;
		qp->qplib_qp.sq.max_sge++;
		if (qp->qplib_qp.sq.max_sge > dev_attr->max_qp_sges)
			qp->qplib_qp.sq.max_sge = dev_attr->max_qp_sges;

#ifdef ENABLE_SHADOW_QP
		qp->qplib_qp.rq_hdr_buf_size =
					BNXT_QPLIB_MAX_QP1_RQ_HDR_SIZE_V2;
#else
		qp->qplib_qp.rq_hdr_buf_size = BNXT_QPLIB_MAX_QP1_RQ_HDR_SIZE;
#endif

#ifdef ENABLE_ROCEV2_QP1
		qp->qplib_qp.sq_hdr_buf_size =
					BNXT_QPLIB_MAX_QP1_SQ_HDR_SIZE_V2;
#else
		qp->qplib_qp.sq_hdr_buf_size = BNXT_QPLIB_MAX_QP1_SQ_HDR_SIZE;
#endif
		qp->qplib_qp.dpi = &rdev->dpi_privileged;
		rc = bnxt_qplib_create_qp1(&rdev->qplib_res, &qp->qplib_qp);
		if (rc) {
			dev_err(rdev_to_dev(rdev), "create HW QP1 failed!");
			goto fail;
		}
#ifdef ENABLE_SHADOW_QP
		/* Create a shadow QP to handle the QP1 traffic */
		rdev->qp1_sqp = bnxt_re_create_shadow_qp(pd, &rdev->qplib_res,
							 &qp->qplib_qp);
		if (!rdev->qp1_sqp) {
			rc = -EINVAL;
			dev_err(rdev_to_dev(rdev),
				"Failed to create Shadow QP for QP1");
			goto qp_destroy;
		}
		rdev->sqp_ah = bnxt_re_create_shadow_qp_ah(pd, &rdev->qplib_res,
							   &qp->qplib_qp);
		if (!rdev->sqp_ah) {
			bnxt_qplib_destroy_qp(&rdev->qplib_res,
					      &rdev->qp1_sqp->qplib_qp);
			rc = -EINVAL;
			dev_err(rdev_to_dev(rdev),
				"Failed to create AH entry for ShadowQP");
			goto qp_destroy;
		}

		/* TODO: Allocate table for storing receive descriptors */
#endif
	} else {
		/* Allocate 128 + 1 more than what's provided */
		entries = roundup_pow_of_two(qp_init_attr->cap.max_send_wr +
					     BNXT_QPLIB_RESERVED_QP_WRS + 1);
		qp->qplib_qp.sq.max_wqe = min_t(u32, entries,
						dev_attr->max_qp_wqes +
						BNXT_QPLIB_RESERVED_QP_WRS + 1);
		qp->qplib_qp.sq.q_full_delta = BNXT_QPLIB_RESERVED_QP_WRS + 1;

		/*
 		 * Reserving one slot for Phantom WQE. Application can
 		 * post one extra entry in this case. But allowing this to avoid
 		 * unexpected Queue full condition
 		 */

		qp->qplib_qp.sq.q_full_delta -= 1;

		qp->qplib_qp.max_rd_atomic = dev_attr->max_qp_rd_atom;
		qp->qplib_qp.max_dest_rd_atomic = dev_attr->max_qp_init_rd_atom;
		if (udata) {
			rc = bnxt_re_init_user_qp(rdev, pd, qp, udata);
			if (rc)
				goto fail;
		} else {
			qp->qplib_qp.dpi = &rdev->dpi_privileged;
		}

		rc = bnxt_qplib_create_qp(&rdev->qplib_res, &qp->qplib_qp);
		if (rc) {
			dev_err(rdev_to_dev(rdev), "create HW QP failed!");
			goto fail;
		}
	}

	qp->ib_qp.qp_num = qp->qplib_qp.id;
	spin_lock_init(&qp->sq_lock);
	spin_lock_init(&qp->rq_lock);

	if (udata) {
		struct bnxt_re_qp_resp resp;

		resp.qpid = qp->ib_qp.qp_num;
		rc = bnxt_re_copy_to_udata(rdev, &resp, sizeof(resp), udata);
		if (rc) {
			dev_err(rdev_to_dev(rdev), "QP copy to udata failed!");
			goto qp_destroy;
		}
	}
	INIT_LIST_HEAD(&qp->list);
	mutex_lock(&rdev->qp_lock);
	list_add_tail(&qp->list, &rdev->qp_list);
	atomic_inc(&rdev->qp_count);
	mutex_unlock(&rdev->qp_lock);

	return &qp->ib_qp;
qp_destroy:
	bnxt_qplib_destroy_qp(&rdev->qplib_res, &qp->qplib_qp);
fail:
	/* TODO: Must free the actual CQ DMA memory */
	kfree(qp);
exit:
	return ERR_PTR(rc);
}

#ifdef ENABLE_SHADOW_QP
int bnxt_re_modify_shadow_qp(struct bnxt_re_dev *rdev,
			     struct bnxt_re_qp *qp1_qp,
			     int qp_attr_mask)
{
	struct bnxt_re_qp *qp = rdev->qp1_sqp;
	int rc = 0;

	if (qp_attr_mask & IB_QP_STATE) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_STATE;
		qp->qplib_qp.state = qp1_qp->qplib_qp.state;
	}
	if (qp_attr_mask & IB_QP_PKEY_INDEX) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_PKEY;
		qp->qplib_qp.pkey_index = qp1_qp->qplib_qp.pkey_index;
	}

	if (qp_attr_mask & IB_QP_QKEY) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_QKEY;
		/* Using a Random  QKEY */
		qp->qplib_qp.qkey = 0x81818181;
	}
	if (qp_attr_mask & IB_QP_SQ_PSN) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_SQ_PSN;
		qp->qplib_qp.sq.psn = qp1_qp->qplib_qp.sq.psn;
	}
#ifdef ENABLE_ROCE_TOS
	qp->qplib_qp.tos_ecn = (u8)tos_ecn;
	qp->qplib_qp.tos_dscp = (u8)tos_dscp;
#endif
	rc = bnxt_qplib_modify_qp(&rdev->qplib_res, &qp->qplib_qp);
	if (rc)
		dev_err(rdev_to_dev(rdev), "Modify Shadow QP for QP1 failed");
	return rc;
}
#endif

int bnxt_re_modify_qp(struct ib_qp *ib_qp, struct ib_qp_attr *qp_attr,
		      int qp_attr_mask, struct ib_udata *udata)
{
	struct bnxt_re_qp *qp = to_bnxt_re(ib_qp, struct bnxt_re_qp, ib_qp);
	struct bnxt_re_dev *rdev = qp->rdev;
	struct bnxt_qplib_dev_attr *dev_attr = &rdev->dev_attr;
	int rc, entries;
	enum ib_qp_state curr_qp_state, new_qp_state;
#ifdef RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP
	int status;
	union ib_gid sgid;
	struct ib_gid_attr sgid_attr;
	u8 nw_type;
#endif

	qp->qplib_qp.modify_flags = 0;
	if (qp_attr_mask & IB_QP_STATE) {
		curr_qp_state = __to_ib_qp_state(qp->qplib_qp.cur_qp_state);
		new_qp_state = qp_attr->qp_state;
		if (!ib_modify_qp_is_ok(curr_qp_state, new_qp_state,
				        ib_qp->qp_type, qp_attr_mask,
					IB_LINK_LAYER_ETHERNET)) {
			dev_err(rdev_to_dev(rdev),"invalid attribute mask=0x%x"
				" specified for qpn=0x%x of type=0x%x"
				" current_qp_state=0x%x, new_qp_state=0x%x\n",
				qp_attr_mask, ib_qp->qp_num, ib_qp->qp_type,
				curr_qp_state, new_qp_state);
			return -EINVAL;
		}
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_STATE;
		qp->qplib_qp.state = __from_ib_qp_state(qp_attr->qp_state);

		if (!qp->sumem &&
		    qp->qplib_qp.state == CMDQ_MODIFY_QP_NEW_STATE_ERR) {
			dev_dbg(rdev_to_dev(rdev),
				"Move QP = %p to flush list\n",
				qp);
			bnxt_qplib_add_flush_qp(&qp->qplib_qp);
		}
		if (!qp->sumem &&
		    qp->qplib_qp.state == CMDQ_MODIFY_QP_NEW_STATE_RESET) {
			dev_dbg(rdev_to_dev(rdev),
				"Move QP = %p out of flush list\n",
				qp);
			bnxt_qplib_del_flush_qp(&qp->qplib_qp);
		}
	}
	if (qp_attr_mask & IB_QP_EN_SQD_ASYNC_NOTIFY) {
		qp->qplib_qp.modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_EN_SQD_ASYNC_NOTIFY;
		qp->qplib_qp.en_sqd_async_notify = true;
	}
	if (qp_attr_mask & IB_QP_ACCESS_FLAGS) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_ACCESS;
		qp->qplib_qp.access =
			__from_ib_access_flags(qp_attr->qp_access_flags);
		/* LOCAL_WRITE access must be set to allow RC receive */
		qp->qplib_qp.access |= BNXT_QPLIB_ACCESS_LOCAL_WRITE;
	}
	if (qp_attr_mask & IB_QP_PKEY_INDEX) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_PKEY;
		qp->qplib_qp.pkey_index = qp_attr->pkey_index;
	}
	if (qp_attr_mask & IB_QP_QKEY) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_QKEY;
		qp->qplib_qp.qkey = qp_attr->qkey;
	}
	if (qp_attr_mask & IB_QP_AV) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_DGID |
				     CMDQ_MODIFY_QP_MODIFY_MASK_FLOW_LABEL |
				     CMDQ_MODIFY_QP_MODIFY_MASK_SGID_INDEX |
				     CMDQ_MODIFY_QP_MODIFY_MASK_HOP_LIMIT |
				     CMDQ_MODIFY_QP_MODIFY_MASK_TRAFFIC_CLASS |
				     CMDQ_MODIFY_QP_MODIFY_MASK_DEST_MAC |
				     CMDQ_MODIFY_QP_MODIFY_MASK_VLAN_ID;
		memcpy(qp->qplib_qp.ah.dgid.data, qp_attr->ah_attr.grh.dgid.raw,
		       sizeof(qp->qplib_qp.ah.dgid.data));
		qp->qplib_qp.ah.flow_label = qp_attr->ah_attr.grh.flow_label;
#ifdef RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP
		/*
		 *  TODO If RoCE V2 is enabled, stack will have two entries for
		 *   each GID entry. Avoiding this duplicte entry in HW. Dividing
		 *    the GID index by 2 for RoCE V2
		 */
		qp->qplib_qp.ah.sgid_index = qp_attr->ah_attr.grh.sgid_index / 2;
#else
		qp->qplib_qp.ah.sgid_index = qp_attr->ah_attr.grh.sgid_index;
#endif
		qp->qplib_qp.ah.host_sgid_index = qp_attr->ah_attr.grh.sgid_index;
		qp->qplib_qp.ah.hop_limit = qp_attr->ah_attr.grh.hop_limit;
		qp->qplib_qp.ah.traffic_class =
					qp_attr->ah_attr.grh.traffic_class;
		qp->qplib_qp.ah.sl = qp_attr->ah_attr.sl;
#ifdef HAVE_IB_AH_DMAC
		memcpy(qp->qplib_qp.ah.dmac, qp_attr->ah_attr.dmac, ETH_ALEN);
#endif
#ifdef RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP
		status = ib_get_cached_gid(&rdev->ibdev, 1,
					   qp_attr->ah_attr.grh.sgid_index,
					   &sgid, &sgid_attr);
		if (!status && sgid_attr.ndev) {
			memcpy(qp->qplib_qp.smac, sgid_attr.ndev->dev_addr,
			       ETH_ALEN);
			dev_put(sgid_attr.ndev);
			nw_type = ib_gid_to_network_type(sgid_attr.gid_type,
				                         &sgid);
			dev_dbg(rdev_to_dev(rdev),
				 "Connection using the nw_type %d\n", nw_type);
			switch (nw_type) {
			case RDMA_NETWORK_IPV4:
				qp->qplib_qp.nw_type =
					CMDQ_MODIFY_QP_NETWORK_TYPE_ROCEV2_IPV4;
				break;
			case RDMA_NETWORK_IPV6:
				qp->qplib_qp.nw_type =
					CMDQ_MODIFY_QP_NETWORK_TYPE_ROCEV2_IPV6;
				break;
			default:
				qp->qplib_qp.nw_type =
					CMDQ_MODIFY_QP_NETWORK_TYPE_ROCEV1;
				break;
			}
		}
#else
		qp->qplib_qp.nw_type =
			CMDQ_MODIFY_QP_NETWORK_TYPE_ROCEV1;
#endif
	}

	if (qp_attr_mask & IB_QP_PATH_MTU) {
		qp->qplib_qp.modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU;
		qp->qplib_qp.path_mtu = __from_ib_mtu(qp_attr->path_mtu);
	} else if (qp_attr->qp_state == IB_QPS_RTR) {
		qp->qplib_qp.modify_flags |=
			CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU;
		qp->qplib_qp.path_mtu =
			__from_ib_mtu(iboe_get_mtu(rdev->netdev->mtu));
	}

	if (qp_attr_mask & IB_QP_TIMEOUT) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_TIMEOUT;
		qp->qplib_qp.timeout = qp_attr->timeout;
	}
	if (qp_attr_mask & IB_QP_RETRY_CNT) {
		qp->qplib_qp.modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_RETRY_CNT;
		qp->qplib_qp.retry_cnt = qp_attr->retry_cnt;
	}
	if (qp_attr_mask & IB_QP_RNR_RETRY) {
		qp->qplib_qp.modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_RNR_RETRY;
		qp->qplib_qp.rnr_retry = qp_attr->rnr_retry;
	}
	if (qp_attr_mask & IB_QP_MIN_RNR_TIMER) {
		qp->qplib_qp.modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_MIN_RNR_TIMER;
		qp->qplib_qp.min_rnr_timer = qp_attr->min_rnr_timer;
	}
	if (qp_attr_mask & IB_QP_RQ_PSN) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_RQ_PSN;
		qp->qplib_qp.rq.psn = qp_attr->rq_psn;
	}
	if (qp_attr_mask & IB_QP_MAX_QP_RD_ATOMIC) {
		qp->qplib_qp.modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_MAX_RD_ATOMIC;
		/* Cap the max_rd_atomic to device max */
		if (qp_attr->max_rd_atomic > dev_attr->max_qp_rd_atom)
			dev_dbg(rdev_to_dev(rdev),
				"max_rd_atomic requested %d is > device max %d\n",
				qp_attr->max_rd_atomic,
				dev_attr->max_qp_rd_atom);
		qp->qplib_qp.max_rd_atomic = min_t(u32, qp_attr->max_rd_atomic,
						   dev_attr->max_qp_rd_atom);
	}
	if (qp_attr_mask & IB_QP_SQ_PSN) {
		qp->qplib_qp.modify_flags |= CMDQ_MODIFY_QP_MODIFY_MASK_SQ_PSN;
		qp->qplib_qp.sq.psn = qp_attr->sq_psn;
	}
	if (qp_attr_mask & IB_QP_MAX_DEST_RD_ATOMIC) {
		if (qp_attr->max_dest_rd_atomic >
		    dev_attr->max_qp_init_rd_atom) {
			dev_err(rdev_to_dev(rdev),
				"max_dest_rd_atomic requested %d is > device max %d\n",
				qp_attr->max_dest_rd_atomic,
				dev_attr->max_qp_init_rd_atom);
			return -EINVAL;
		}
		qp->qplib_qp.modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_MAX_DEST_RD_ATOMIC;
		qp->qplib_qp.max_dest_rd_atomic = qp_attr->max_dest_rd_atomic;
	}
	if (qp_attr_mask & IB_QP_CAP) {
		qp->qplib_qp.modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_SQ_SIZE |
				CMDQ_MODIFY_QP_MODIFY_MASK_RQ_SIZE |
				CMDQ_MODIFY_QP_MODIFY_MASK_SQ_SGE |
				CMDQ_MODIFY_QP_MODIFY_MASK_RQ_SGE |
				CMDQ_MODIFY_QP_MODIFY_MASK_MAX_INLINE_DATA;
		if ((qp_attr->cap.max_send_wr >= dev_attr->max_qp_wqes) ||
		    (qp_attr->cap.max_recv_wr >= dev_attr->max_qp_wqes) ||
		    (qp_attr->cap.max_send_sge >= dev_attr->max_qp_sges) ||
		    (qp_attr->cap.max_recv_sge >= dev_attr->max_qp_sges) ||
		    (qp_attr->cap.max_inline_data >=
						dev_attr->max_inline_data)) {
			dev_err(rdev_to_dev(rdev),
				"Create QP failed - max exceeded");
			return -EINVAL;
		}
		entries = roundup_pow_of_two(qp_attr->cap.max_send_wr);
		if (entries > dev_attr->max_qp_wqes)
			entries = dev_attr->max_qp_wqes;
		entries = min_t(u32, entries, dev_attr->max_qp_wqes);
		qp->qplib_qp.sq.max_wqe = entries;
		qp->qplib_qp.sq.q_full_delta = qp->qplib_qp.sq.max_wqe -
						qp_attr->cap.max_send_wr;
		/*
 		 * Reserving one slot for Phantom WQE. Some application can
 		 * post one extra entry in this case. Allowing this to avoid
 		 * unexpected Queue full condition
 		 */
		qp->qplib_qp.sq.q_full_delta -= 1;
		qp->qplib_qp.sq.max_sge = qp_attr->cap.max_send_sge;
		if (qp->qplib_qp.rq.max_wqe) {
			entries = roundup_pow_of_two(qp_attr->cap.max_recv_wr);
			if (entries > dev_attr->max_qp_wqes)
				entries = dev_attr->max_qp_wqes;
			qp->qplib_qp.rq.max_wqe = entries;
			qp->qplib_qp.rq.q_full_delta = qp->qplib_qp.rq.max_wqe -
						       qp_attr->cap.max_recv_wr;
			qp->qplib_qp.rq.max_sge = qp_attr->cap.max_recv_sge;
		} else {
			/* SRQ was used prior, just ignore the RQ caps */
		}
	}
	if (qp_attr_mask & IB_QP_DEST_QPN) {
		qp->qplib_qp.modify_flags |=
				CMDQ_MODIFY_QP_MODIFY_MASK_DEST_QP_ID;
		qp->qplib_qp.dest_qpn = qp_attr->dest_qp_num;
	}
#ifdef ENABLE_ROCE_TOS
	qp->qplib_qp.tos_ecn = (u8)tos_ecn;
	qp->qplib_qp.tos_dscp = (u8)tos_dscp;
#endif
	rc = bnxt_qplib_modify_qp(&rdev->qplib_res, &qp->qplib_qp);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Modify HW QP failed!");
		return rc;
	}
#ifdef ENABLE_SHADOW_QP
	if (ib_qp->qp_type == IB_QPT_GSI && rdev->qp1_sqp) {
		rc = bnxt_re_modify_shadow_qp(rdev, qp, qp_attr_mask);
	}
#endif
#if 0
	/* Debug only */
	{
		struct bnxt_qplib_qp qqp;

		qqp.id = qp->qplib_qp.id;
		bnxt_qplib_query_qp(&rdev->qplib_res, &qqp);
	}
#endif
	return rc;
}

int bnxt_re_query_qp(struct ib_qp *ib_qp, struct ib_qp_attr *qp_attr,
		     int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr)
{
	struct bnxt_re_qp *qp = to_bnxt_re(ib_qp, struct bnxt_re_qp, ib_qp);
	struct bnxt_re_dev *rdev = qp->rdev;
	struct bnxt_qplib_qp qplib_qp;
	int rc;

	memset(&qplib_qp, 0, sizeof(struct bnxt_qplib_qp));
	qplib_qp.id = qp->qplib_qp.id;
	qplib_qp.ah.host_sgid_index = qp->qplib_qp.ah.host_sgid_index;

	rc = bnxt_qplib_query_qp(&rdev->qplib_res, &qplib_qp);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Query HW QP failed!");
		return rc;
	}
	qp_attr->qp_state = __to_ib_qp_state(qplib_qp.state);
	qp_attr->en_sqd_async_notify = qplib_qp.en_sqd_async_notify ? 1 : 0;
	qp_attr->qp_access_flags = __to_ib_access_flags(qplib_qp.access);
	qp_attr->pkey_index = qplib_qp.pkey_index;
	qp_attr->qkey = qplib_qp.qkey;
	memcpy(qp_attr->ah_attr.grh.dgid.raw, qplib_qp.ah.dgid.data,
	       sizeof(qplib_qp.ah.dgid.data));
	qp_attr->ah_attr.grh.flow_label = qplib_qp.ah.flow_label;
	qp_attr->ah_attr.grh.sgid_index = qplib_qp.ah.host_sgid_index;
	qp_attr->ah_attr.grh.hop_limit = qplib_qp.ah.hop_limit;
	qp_attr->ah_attr.grh.traffic_class = qplib_qp.ah.traffic_class;
	qp_attr->ah_attr.sl = qplib_qp.ah.sl;
#ifdef HAVE_IB_AH_DMAC
	memcpy(qp_attr->ah_attr.dmac, qplib_qp.ah.dmac, ETH_ALEN);
#endif
	qp_attr->path_mtu = __to_ib_mtu(qplib_qp.path_mtu);
	qp_attr->timeout = qplib_qp.timeout;
	qp_attr->retry_cnt = qplib_qp.retry_cnt;
	qp_attr->rnr_retry = qplib_qp.rnr_retry;
	qp_attr->min_rnr_timer = qplib_qp.min_rnr_timer;
	qp_attr->rq_psn = qplib_qp.rq.psn;
	qp_attr->max_rd_atomic = qplib_qp.max_rd_atomic;
	qp_attr->sq_psn = qplib_qp.sq.psn;
	qp_attr->max_dest_rd_atomic = qplib_qp.max_dest_rd_atomic;
	qp_init_attr->sq_sig_type = qplib_qp.sig_type ? IB_SIGNAL_ALL_WR :
							IB_SIGNAL_REQ_WR;
	qp_attr->dest_qp_num = qplib_qp.dest_qpn;

	qp_attr->cap.max_send_wr = qp->qplib_qp.sq.max_wqe;
	qp_attr->cap.max_send_sge = qp->qplib_qp.sq.max_sge;
	qp_attr->cap.max_recv_wr = qp->qplib_qp.rq.max_wqe;
	qp_attr->cap.max_recv_sge = qp->qplib_qp.rq.max_sge;
	qp_attr->cap.max_inline_data = qp->qplib_qp.max_inline_data;
	qp_init_attr->cap = qp_attr->cap;

	return 0;
}

/* Builders */

/* For Raw, the application is responsible to build the entire packet */
static void bnxt_re_build_raw_send(struct ib_send_wr *wr,
				   struct bnxt_qplib_swqe *wqe)
{
	switch (wr->send_flags) {
	case IB_SEND_IP_CSUM:
		wqe->rawqp1.lflags |= SQ_SEND_RAWETH_QP1_LFLAGS_IP_CHKSUM;
		break;
	default:
		/* Pad HW RoCE iCRC */
		wqe->rawqp1.lflags |= SQ_SEND_RAWETH_QP1_LFLAGS_ROCE_CRC;
		break;
	}
}

#ifndef ENABLE_ROCEV2_QP1
/* For QP1, the driver must build the entire RoCE (v1/v2) packet hdr
   as according to the sgid and AV
 */
static int bnxt_re_build_qp1_send(struct bnxt_re_qp *qp, struct ib_send_wr *wr,
				  struct bnxt_qplib_swqe *wqe, int payload_size)
{
#ifdef HAVE_IB_RDMA_WR
	struct bnxt_re_ah *ah = to_bnxt_re(ud_wr(wr)->ah, struct bnxt_re_ah,
					   ib_ah);
#else
	struct bnxt_re_ah *ah = to_bnxt_re(wr->wr.ud.ah, struct bnxt_re_ah,
					   ib_ah);
#endif
	struct bnxt_qplib_ah *qplib_ah = &ah->qplib_ah;
	struct bnxt_qplib_sge sge;
	union ib_gid sgid;
//	u16 vlan_id, pkey;
	u16 vlan_id;
	void *buf;
	int i, rc = 0, size;

	memset(&qp->qp1_hdr, 0, sizeof(qp->qp1_hdr));


	/* Get sgid */
	rc = bnxt_re_query_gid(&qp->rdev->ibdev, 1, qplib_ah->sgid_index, &sgid);
	if (rc)
		return rc;

	/* ETH */
	qp->qp1_hdr.eth_present = 1;
	memcpy(qp->qp1_hdr.eth.dmac_h, ah->qplib_ah.dmac, ETH_ALEN);
	memcpy(qp->qp1_hdr.eth.smac_h, qp->qplib_qp.smac, ETH_ALEN);
	qp->qp1_hdr.eth.type = cpu_to_be16(BNXT_QPLIB_ETHTYPE_ROCEV1);

	/* For vlan, check the sgid for vlan existence */
	vlan_id = rdma_get_vlan_id(&sgid);
	if (vlan_id && vlan_id < 0x1000) {
		qp->qp1_hdr.vlan_present = 1;
		qp->qp1_hdr.eth.type = cpu_to_be16(ETH_P_8021Q);
	}
	/* GRH */
	qp->qp1_hdr.grh_present = 1;
	qp->qp1_hdr.grh.ip_version = 6;
	qp->qp1_hdr.grh.payload_length =
		cpu_to_be16((IB_BTH_BYTES + IB_DETH_BYTES + payload_size + 7)
			    & ~3);
	qp->qp1_hdr.grh.next_header = 0x1b;
	memcpy(qp->qp1_hdr.grh.source_gid.raw, sgid.raw, sizeof(sgid));
	memcpy(qp->qp1_hdr.grh.destination_gid.raw, qplib_ah->dgid.data,
	       sizeof(sgid));

	/* BTH */
	if (wr->opcode == IB_WR_SEND_WITH_IMM) {
		qp->qp1_hdr.bth.opcode = IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
		qp->qp1_hdr.immediate_present = 1;
	} else {
		qp->qp1_hdr.bth.opcode = IB_OPCODE_UD_SEND_ONLY;
	}
	if (wr->send_flags & IB_SEND_SOLICITED)
		qp->qp1_hdr.bth.solicited_event = 1;
	qp->qp1_hdr.bth.pad_count = (4 - payload_size) & 3;
//	if (bnxt_re_query_pkey(ibdev, 1, qp->qplib_qp.pkey_index, &pkey))
//		qp->qp1_hdr.bth.pkey = cpu_to_be16(pkey);
	/* P_key for QP1 is for all members */
	qp->qp1_hdr.bth.pkey = cpu_to_be16(0xFFFF);
	qp->qp1_hdr.bth.destination_qpn = IB_QP1;
	qp->qp1_hdr.bth.ack_req = 0;
	qp->send_psn++;
	qp->send_psn &= BTH_PSN_MASK;
	qp->qp1_hdr.bth.psn = cpu_to_be32(qp->send_psn);
	/* DETH */
	/* Use the priviledged Q_Key for QP1 */
	qp->qp1_hdr.deth.qkey = cpu_to_be32(IB_QP1_QKEY);
	qp->qp1_hdr.deth.source_qpn = IB_QP1;

	/* Pack the QP1 to the transmit buffer */
	buf = bnxt_qplib_get_qp1_sq_buf(&qp->qplib_qp, &sge);
	if (buf) {
		size = ib_ud_header_pack(&qp->qp1_hdr, buf);
		for (i = wqe->num_sge; i; i--) {
			wqe->sg_list[i].addr = wqe->sg_list[i - 1].addr;
			wqe->sg_list[i].lkey = wqe->sg_list[i - 1].lkey;
			wqe->sg_list[i].size = wqe->sg_list[i - 1].size;
		}
		wqe->sg_list[0].addr = sge.addr;
		wqe->sg_list[0].lkey = sge.lkey;
		wqe->sg_list[0].size = sge.size;
		wqe->num_sge++;
	} else {
		dev_err(rdev_to_dev(qp->rdev), "QP1 buffer is empty!");
		rc = -ENOMEM;
	}
	return rc;
}

#else
/* Routine for sending QP1 packets for RoCE V1 an V2
 */
static int bnxt_re_build_qp1_send_v2(struct bnxt_re_qp *qp,
				     struct ib_send_wr *wr,
				     struct bnxt_qplib_swqe *wqe,
				     int payload_size)
{
	struct ib_device *ibdev = &qp->rdev->ibdev;
#ifdef HAVE_IB_RDMA_WR
	struct bnxt_re_ah *ah = to_bnxt_re(ud_wr(wr)->ah, struct bnxt_re_ah,
					   ib_ah);
#else
	struct bnxt_re_ah *ah = to_bnxt_re(wr->wr.ud.ah, struct bnxt_re_ah,
					   ib_ah);
#endif
	struct bnxt_qplib_ah *qplib_ah = &ah->qplib_ah;
	struct bnxt_qplib_sge sge;
	union ib_gid sgid;
	u8 nw_type;
	u16 ether_type;
#ifdef RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP
	struct ib_gid_attr sgid_attr;
#endif
	union ib_gid dgid;
	bool is_eth = false;
	bool is_vlan = false;
	bool is_grh = false;
	bool is_udp = false;
	u8 ip_version = 0;
	u16 vlan_id = 0xFFFF;
	void *buf;
	int i, rc = 0, size;

	memset(&qp->qp1_hdr, 0, sizeof(qp->qp1_hdr));

	rc = ib_get_cached_gid(ibdev, 1,
			       qplib_ah->host_sgid_index, &sgid,
			       &sgid_attr);
	if (rc) {
		dev_err(rdev_to_dev(qp->rdev),
			"Failed to query gid at index %d",
			qplib_ah->host_sgid_index);
		return rc;
	}
	if (sgid_attr.ndev) {
		if (is_vlan_dev(sgid_attr.ndev))
			vlan_id = vlan_dev_vlan_id(sgid_attr.ndev);
		dev_put(sgid_attr.ndev);
	}
	/* Get network header type for this GID */
	nw_type = ib_gid_to_network_type(sgid_attr.gid_type, &sgid);
	switch (nw_type) {
	case RDMA_NETWORK_IPV4:
		nw_type = BNXT_RE_ROCEV2_IPV4_PACKET;
		break;
	case RDMA_NETWORK_IPV6:
		nw_type = BNXT_RE_ROCEV2_IPV6_PACKET;
		break;
	default:
		nw_type = BNXT_RE_ROCE_V1_PACKET;
		break;
	}
	memcpy(&dgid.raw, &qplib_ah->dgid, 16);
	is_udp = sgid_attr.gid_type == IB_GID_TYPE_ROCE_UDP_ENCAP;
	if (is_udp) {
		if (ipv6_addr_v4mapped((struct in6_addr *)&sgid)) {
			ip_version = 4;
			ether_type = ETH_P_IP;
		} else {
			ip_version = 6;
			ether_type = ETH_P_IPV6;
		}
		is_grh = false;
	} else {
		ether_type = BNXT_QPLIB_ETHTYPE_ROCEV1;
		is_grh = true;
	}

	is_eth = true;
	is_vlan = (vlan_id && (vlan_id < 0x1000)) ? true : false;

	dev_dbg(rdev_to_dev(qp->rdev),
		 "eth = %d grh = %d udp = %d vlan = %d ip_ver = %d\n",
		 is_eth, is_grh, is_udp, is_vlan, ip_version);

	ib_ud_header_init(payload_size, !is_eth, is_eth, is_vlan, is_grh,
			  ip_version, is_udp, 0, &qp->qp1_hdr);

	/* ETH */
	memcpy(qp->qp1_hdr.eth.dmac_h, ah->qplib_ah.dmac, ETH_ALEN);
	memcpy(qp->qp1_hdr.eth.smac_h, qp->qplib_qp.smac, ETH_ALEN);

	/* For vlan, check the sgid for vlan existence */

	if (!is_vlan) {
		qp->qp1_hdr.eth.type = cpu_to_be16(ether_type);
	} else {
		qp->qp1_hdr.vlan.type = cpu_to_be16(ether_type);
		qp->qp1_hdr.vlan.tag = cpu_to_be16(vlan_id);
	}

	if (is_grh || (ip_version == 6)) {
		memcpy(qp->qp1_hdr.grh.source_gid.raw, sgid.raw, sizeof(sgid));
		memcpy(qp->qp1_hdr.grh.destination_gid.raw, qplib_ah->dgid.data,
		       sizeof(sgid));
		qp->qp1_hdr.grh.hop_limit     = qplib_ah->hop_limit;
	}

	if (ip_version == 4) {
		/* TODO */
		qp->qp1_hdr.ip4.tos = 0;
		qp->qp1_hdr.ip4.id = 0;
		qp->qp1_hdr.ip4.frag_off = htons(IP_DF);
		qp->qp1_hdr.ip4.ttl = qplib_ah->hop_limit;

		memcpy(&qp->qp1_hdr.ip4.saddr, sgid.raw + 12, 4);
		memcpy(&qp->qp1_hdr.ip4.daddr, qplib_ah->dgid.data + 12, 4);
		qp->qp1_hdr.ip4.check = ib_ud_ip4_csum(&qp->qp1_hdr);
	}

	if (is_udp) {
		qp->qp1_hdr.udp.dport = htons(ROCE_V2_UDP_DPORT);
		qp->qp1_hdr.udp.sport = htons(0x8CD1);
		qp->qp1_hdr.udp.csum = 0;
	}

	/* BTH */
	if (wr->opcode == IB_WR_SEND_WITH_IMM) {
		qp->qp1_hdr.bth.opcode = IB_OPCODE_UD_SEND_ONLY_WITH_IMMEDIATE;
		qp->qp1_hdr.immediate_present = 1;
	} else {
		qp->qp1_hdr.bth.opcode = IB_OPCODE_UD_SEND_ONLY;
	}
	if (wr->send_flags & IB_SEND_SOLICITED)
		qp->qp1_hdr.bth.solicited_event = 1;
	/* pad_count */
	qp->qp1_hdr.bth.pad_count = (4 - payload_size) & 3;

	/* P_key for QP1 is for all members */
	qp->qp1_hdr.bth.pkey = cpu_to_be16(0xFFFF);
	qp->qp1_hdr.bth.destination_qpn = IB_QP1;
	qp->qp1_hdr.bth.ack_req = 0;
	qp->send_psn++;
	qp->send_psn &= BTH_PSN_MASK;
	qp->qp1_hdr.bth.psn = cpu_to_be32(qp->send_psn);
	/* DETH */
	/* Use the priviledged Q_Key for QP1 */
	qp->qp1_hdr.deth.qkey = cpu_to_be32(IB_QP1_QKEY);
	qp->qp1_hdr.deth.source_qpn = IB_QP1;

	/* Pack the QP1 to the transmit buffer */
	buf = bnxt_qplib_get_qp1_sq_buf(&qp->qplib_qp, &sge);
	if (buf) {
		size = ib_ud_header_pack(&qp->qp1_hdr, buf);
		for (i = wqe->num_sge; i; i--) {
			wqe->sg_list[i].addr = wqe->sg_list[i - 1].addr;
			wqe->sg_list[i].lkey = wqe->sg_list[i - 1].lkey;
			wqe->sg_list[i].size = wqe->sg_list[i - 1].size;
		}

		/*
		 * Max Header buf size for IPV6 RoCE V2 is 86,
		 * which is same as the QP1 SQ header buffer.
		 * Header buf size for IPV4 RoCE V2 can be 66.
		 * ETH(14) + VLAN(4)+ IP(20) + UDP (8) + BTH(20).
		 * Subtract 20 bytes from QP1 SQ header buf size
		 */
		if (is_udp && ip_version == 4)
			sge.size -= 20;
		/*
		 * Max Header buf size for RoCE V1 is 78.
		 * ETH(14) + VLAN(4) + GRH(40) + BTH(20).
		 * Subtract 8 bytes from QP1 SQ header buf size
		 */
		if (!is_udp)
			sge.size -= 8;

		/* Subtract 4 bytes for non vlan packets */
		if (!is_vlan)
			sge.size -= 4;

		wqe->sg_list[0].addr = sge.addr;
		wqe->sg_list[0].lkey = sge.lkey;
		wqe->sg_list[0].size = sge.size;
		wqe->num_sge++;

		/* TODO Remove the Debug code */
		if (0) {
			pr_err("built UD header of size %d:\n", size);
			for (i = 0; i < size / 4; ++i) {
				if (i % 8 == 0)
					pr_err("  [%02x] ", i * 4);
				pr_cont(" %08x",
						be32_to_cpu(((__be32 *) buf)[i]));
				if ((i + 1) % 8 == 0)
					pr_cont("\n");
			}
			pr_err("\n");
		}
	} else {
		dev_err(rdev_to_dev(qp->rdev), "QP1 buffer is empty!");
		rc = -ENOMEM;
	}
	return rc;
}
#endif

#ifndef ENABLE_SHADOW_QP
/* For the MAD layer, it only provides the recv SGE the size of
   ib_grh + MAD datagram.  No Ethernet headers, Ethertype, BTH, DETH,
   nor RoCE iCRC.  The Cu+ solution must provide buffer for the entire
   receive packet (334 bytes) with no VLAN and then copy the GRH
   and the MAD datagram out to the provided SGE.
*/
static int bnxt_re_build_qp1_recv(struct bnxt_re_qp *qp, struct ib_recv_wr *wr,
				  struct bnxt_qplib_swqe *wqe, int payload_size)
{
	struct ib_device *ibdev = &qp->rdev->ibdev;
	struct bnxt_qplib_sge ref, sge;
	int rc = 0;

	/* TODO: Add support for RoCEv2 on QP1 */

	if (bnxt_qplib_get_qp1_rq_buf(&qp->qplib_qp, &sge)) {
		/* Create 5 SGEs as according to the following:
		   Ethernet header (14)
		   ib_grh (40) - as provided from the wr
		   ib_bth + ib_deth (20)
		   MAD (256) - as provided from the wr
		   iCRC (4)
		*/
		/* Save the reference from ULP */
		ref.addr = wqe->sg_list[0].addr;
		ref.lkey = wqe->sg_list[0].lkey;
		ref.size = wqe->sg_list[0].size;

		/* SGE 1 */
		wqe->sg_list[0].addr = sge.addr;
		wqe->sg_list[0].lkey = sge.lkey;
		wqe->sg_list[0].size = BNXT_QPLIB_MAX_QP1_RQ_ETH_HDR_SIZE;
		sge.size -= wqe->sg_list[0].size;
		if (sge.size <= 0) {
			dev_err(rdev_to_dev(qp->rdev),"QP1 rq buffer is empty!");
			rc = -ENOMEM;
			goto done;
		}
		sge.addr += wqe->sg_list[0].size;

		/* SGE 2 */
		wqe->sg_list[1].addr = ref.addr;
		wqe->sg_list[1].lkey = ref.lkey;
		wqe->sg_list[1].size = sizeof(struct ib_grh);
		ref.size -= wqe->sg_list[1].size;
		if (ref.size <= 0) {
			dev_err(rdev_to_dev(qp->rdev),
				"QP1 ref buffer is empty!");
			rc = -ENOMEM;
			goto done;
		}
		ref.addr += wqe->sg_list[1].size;

		/* SGE 3 */
		wqe->sg_list[2].addr = sge.addr;
		wqe->sg_list[2].lkey = sge.lkey;
		wqe->sg_list[2].size = BNXT_QPLIB_MAX_QP1_RQ_BDETH_HDR_SIZE;
		sge.size -= wqe->sg_list[2].size;
		if (sge.size <= 0) {
			dev_err(rdev_to_dev(qp->rdev),
				"QP1 rq buffer is empty!");
			rc = -ENOMEM;
			goto done;
		}
		sge.addr += wqe->sg_list[2].size;

		/* SGE 4 */
		wqe->sg_list[3].addr = ref.addr;
		wqe->sg_list[3].lkey = ref.lkey;
		wqe->sg_list[3].size = ref.size;
		ref.size -= wqe->sg_list[3].size;
		if (ref.size) {
			dev_err(rdev_to_dev(qp->rdev),
				"QP1 ref buffer is incorrect!");
			rc = -ENOMEM;
			goto done;
		}
		/* SGE 5 */
		wqe->sg_list[4].addr = sge.addr;
		wqe->sg_list[4].lkey = sge.lkey;
		wqe->sg_list[4].size = sge.size;
		sge.size -= wqe->sg_list[4].size;
		if (sge.size) {
			dev_err(rdev_to_dev(qp->rdev),
				"QP1 rq buffer is incorrect!");
			rc = -ENOMEM;
			goto done;
		}
		wqe->num_sge = 5;
	} else {
		dev_err(rdev_to_dev(qp->rdev), "QP1 buffer is empty!");
		rc = -ENOMEM;
	}
done:
	return rc;
}

#else
static int bnxt_re_build_qp1_shadow_qp_recv(struct bnxt_re_qp *qp,
					    struct ib_recv_wr *wr,
					    struct bnxt_qplib_swqe *wqe,
					    int payload_size)
{
	struct bnxt_qplib_sge ref, sge;
	int rc = 0;
	u32 rq_prod_index;
	struct bnxt_re_sqp_entries *sqp_entry;

	rq_prod_index = bnxt_qplib_get_rq_prod_index(&qp->qplib_qp);

	if (bnxt_qplib_get_qp1_rq_buf(&qp->qplib_qp, &sge)) {
		/* Create 1 SGE to receive the entire
		 * ethernet packet
		 */
		/* Save the reference from ULP */
		ref.addr = wqe->sg_list[0].addr;
		ref.lkey = wqe->sg_list[0].lkey;
		ref.size = wqe->sg_list[0].size;

		sqp_entry = &qp->rdev->sqp_tbl[rq_prod_index];

		/* SGE 1 */
		wqe->sg_list[0].addr = sge.addr;
		/* TODO check the lkey to be used */
		wqe->sg_list[0].lkey = sge.lkey;
		wqe->sg_list[0].size = BNXT_QPLIB_MAX_QP1_RQ_HDR_SIZE_V2;
		sge.size -= wqe->sg_list[0].size;
		if (sge.size < 0) {
			dev_err(rdev_to_dev(qp->rdev),
				"QP1 rq buffer is empty!");
			rc = -ENOMEM;
			goto done;
		}

		sqp_entry->sge.addr = ref.addr;
		sqp_entry->sge.lkey = ref.lkey;
		sqp_entry->sge.size = ref.size;
		/* Store the wrid for reporting completion */
		sqp_entry->wrid = wqe->wr_id;
		/* change the wqe->wrid to table index */
		wqe->wr_id = rq_prod_index;
	}
	return 0;
done:

	return rc;
}
#endif

int is_ud_qp(struct bnxt_re_qp *qp)
{
	return qp->qplib_qp.type == CMDQ_CREATE_QP_TYPE_UD;
}

static int bnxt_re_build_send_wqe(struct bnxt_re_qp *qp,
				  struct ib_send_wr *wr,
				  struct bnxt_qplib_swqe *wqe)
{
	struct bnxt_re_ah *ah = NULL;

	if(is_ud_qp(qp)) {
#ifdef HAVE_IB_RDMA_WR
		ah = to_bnxt_re(ud_wr(wr)->ah, struct bnxt_re_ah, ib_ah);
		wqe->send.q_key = ud_wr(wr)->remote_qkey;
		wqe->send.dst_qp = ud_wr(wr)->remote_qpn;
#else
		ah = to_bnxt_re(wr->wr.ud.ah, struct bnxt_re_ah,
				ib_ah);
		wqe->send.q_key = wr->wr.ud.remote_qkey;
		wqe->send.dst_qp = wr->wr.ud.remote_qpn;
#endif
		wqe->send.avid = ah->qplib_ah.id;
	}
	switch (wr->opcode) {
	case IB_WR_SEND:
		wqe->type = BNXT_QPLIB_SWQE_TYPE_SEND;
		break;
	case IB_WR_SEND_WITH_IMM:
		wqe->type = BNXT_QPLIB_SWQE_TYPE_SEND_WITH_IMM;
		wqe->send.imm_data_or_inv_key = wr->ex.imm_data;
		break;
	case IB_WR_SEND_WITH_INV:
		wqe->type = BNXT_QPLIB_SWQE_TYPE_SEND_WITH_INV;
		wqe->send.imm_data_or_inv_key = wr->ex.invalidate_rkey;
		break;
	default:
		return -EINVAL;
	}
	if (wr->send_flags & IB_SEND_SIGNALED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP;
	if (wr->send_flags & IB_SEND_FENCE)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
	if (wr->send_flags & IB_SEND_SOLICITED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SOLICIT_EVENT;
	if (wr->send_flags & IB_SEND_INLINE)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_INLINE;

	return 0;
}

static int bnxt_re_build_rdma_wqe(struct ib_send_wr *wr,
				  struct bnxt_qplib_swqe *wqe)
{
	switch (wr->opcode) {
	case IB_WR_RDMA_WRITE:
		wqe->type = BNXT_QPLIB_SWQE_TYPE_RDMA_WRITE;
		break;
	case IB_WR_RDMA_WRITE_WITH_IMM:
		wqe->type = BNXT_QPLIB_SWQE_TYPE_RDMA_WRITE_WITH_IMM;
		wqe->rdma.imm_data_or_inv_key = wr->ex.imm_data;
		break;
	case IB_WR_RDMA_READ:
		wqe->type = BNXT_QPLIB_SWQE_TYPE_RDMA_READ;
		wqe->rdma.imm_data_or_inv_key = wr->ex.invalidate_rkey;
		break;
	default:
		return -EINVAL;
	}
#ifdef HAVE_IB_RDMA_WR
	wqe->rdma.remote_va = rdma_wr(wr)->remote_addr;
	wqe->rdma.r_key = rdma_wr(wr)->rkey;
#else
	wqe->rdma.remote_va = wr->wr.rdma.remote_addr;
	wqe->rdma.r_key = wr->wr.rdma.rkey;
#endif
	if (wr->send_flags & IB_SEND_SIGNALED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP;
	if (wr->send_flags & IB_SEND_FENCE)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
	if (wr->send_flags & IB_SEND_SOLICITED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SOLICIT_EVENT;
	if (wr->send_flags & IB_SEND_INLINE)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_INLINE;

	return 0;
}

static int bnxt_re_build_atomic_wqe(struct ib_send_wr *wr,
				    struct bnxt_qplib_swqe *wqe)
{
	switch (wr->opcode) {
	case IB_WR_ATOMIC_CMP_AND_SWP:
		wqe->type = BNXT_QPLIB_SWQE_TYPE_ATOMIC_CMP_AND_SWP;
#ifdef HAVE_IB_RDMA_WR
		wqe->atomic.swap_data = atomic_wr(wr)->swap;
#else
		wqe->atomic.swap_data = wr->wr.atomic.swap;
#endif
		break;
	case IB_WR_ATOMIC_FETCH_AND_ADD:
		wqe->type = BNXT_QPLIB_SWQE_TYPE_ATOMIC_FETCH_AND_ADD;
#ifdef HAVE_IB_RDMA_WR
		wqe->atomic.cmp_data = atomic_wr(wr)->compare_add;
#else
		wqe->atomic.cmp_data = wr->wr.atomic.compare_add;
#endif
		break;
	default:
		return -EINVAL;
	}
#ifdef HAVE_IB_RDMA_WR
	wqe->atomic.remote_va = atomic_wr(wr)->remote_addr;
	wqe->atomic.r_key = atomic_wr(wr)->rkey;
#else
	wqe->atomic.remote_va = wr->wr.atomic.remote_addr;
	wqe->atomic.r_key = wr->wr.atomic.rkey;
#endif
	if (wr->send_flags & IB_SEND_SIGNALED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP;
	if (wr->send_flags & IB_SEND_FENCE)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
	if (wr->send_flags & IB_SEND_SOLICITED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SOLICIT_EVENT;
	return 0;
}

static int bnxt_re_build_inv_wqe(struct ib_send_wr *wr,
				 struct bnxt_qplib_swqe *wqe)
{
	wqe->type = BNXT_QPLIB_SWQE_TYPE_LOCAL_INV;
	wqe->local_inv.inv_l_key = wr->ex.invalidate_rkey;

	if (wr->send_flags & IB_SEND_SIGNALED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP;
	if (wr->send_flags & IB_SEND_SOLICITED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SOLICIT_EVENT;
	bnxt_re_set_fence_flag(wr, wqe);

	return 0;
}

#ifdef HAVE_IB_FAST_REG_MR_WR
static int bnxt_re_build_frmr_wqe(struct ib_send_wr *wr,
				  struct bnxt_qplib_swqe *wqe)
{
	struct bnxt_re_frpl *frpl = to_bnxt_re(wr->wr.fast_reg.page_list,
					       struct bnxt_re_frpl, ib_frpl);
	int access = wr->wr.fast_reg.access_flags;

	if (!wr->wr.fast_reg.page_list_len ||
	    wr->wr.fast_reg.page_list_len > frpl->qplib_frpl.max_pg_ptrs)
		return -EINVAL;

	wqe->frmr.pbl_ptr = (u64 *)frpl->qplib_frpl.hwq.pbl_ptr[0];
	wqe->frmr.page_list = wr->wr.fast_reg.page_list->page_list;
	wqe->frmr.pbl_dma_ptr = frpl->qplib_frpl.hwq.pbl_dma_ptr[0];
	wqe->frmr.page_list_len = wr->wr.fast_reg.page_list_len;
	wqe->frmr.levels = frpl->qplib_frpl.hwq.level + 1;
	wqe->type = BNXT_QPLIB_SWQE_TYPE_FAST_REG_MR;
	//wqe->lkey = wr->wr.fast_reg.rkey;

	if (wr->send_flags & IB_SEND_FENCE)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
	if (wr->send_flags & IB_SEND_SIGNALED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP;

	if (access & IB_ACCESS_LOCAL_WRITE)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_LOCAL_WRITE;
	if (access & IB_ACCESS_REMOTE_READ)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_REMOTE_READ;
	if (access & IB_ACCESS_REMOTE_WRITE)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_REMOTE_WRITE;
	if (access & IB_ACCESS_REMOTE_ATOMIC)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_REMOTE_ATOMIC;
	if (access & IB_ACCESS_MW_BIND)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_WINDOW_BIND;

	/* TODO: OFED provides the rkey of the MR instead of the lkey */
	wqe->frmr.l_key = wr->wr.fast_reg.rkey;
	wqe->frmr.length = wr->wr.fast_reg.length;
	wqe->frmr.pbl_pg_sz_log = ((1 << wr->wr.fast_reg.page_shift) >>
				   PAGE_SHIFT_4K) - 1;
	wqe->frmr.va = wr->wr.fast_reg.iova_start;
	wqe->frmr.zero_based = false;
	return 0;
}
#endif

#ifdef HAVE_IB_REG_MR_WR
static int bnxt_re_build_reg_wqe(struct ib_reg_wr *wr,
				 struct bnxt_qplib_swqe *wqe)
{
	struct bnxt_re_mr *mr = to_bnxt_re(wr->mr, struct bnxt_re_mr, ib_mr);
	struct bnxt_qplib_frpl *qplib_frpl = &mr->qplib_frpl;
	int access = wr->access;

	wqe->frmr.pbl_ptr = (u64 *)qplib_frpl->hwq.pbl_ptr[0];
	wqe->frmr.pbl_dma_ptr = qplib_frpl->hwq.pbl_dma_ptr[0];
	wqe->frmr.page_list = mr->pages;
	wqe->frmr.page_list_len = mr->npages;
	wqe->frmr.levels = qplib_frpl->hwq.level + 1;
	wqe->type = BNXT_QPLIB_SWQE_TYPE_REG_MR;
	//wqe->lkey = wr->wr.fast_reg.rkey;

	if (wr->wr.send_flags & IB_SEND_FENCE)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
	if (wr->wr.send_flags & IB_SEND_SIGNALED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP;

	if (access & IB_ACCESS_LOCAL_WRITE)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_LOCAL_WRITE;
	if (access & IB_ACCESS_REMOTE_READ)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_REMOTE_READ;
	if (access & IB_ACCESS_REMOTE_WRITE)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_REMOTE_WRITE;
	if (access & IB_ACCESS_REMOTE_ATOMIC)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_REMOTE_ATOMIC;
	if (access & IB_ACCESS_MW_BIND)
		wqe->frmr.access_cntl |= SQ_FR_PMR_ACCESS_CNTL_WINDOW_BIND;

	/* TODO: OFED provides the rkey of the MR instead of the lkey */
	wqe->frmr.l_key = wr->key;
	wqe->frmr.length = wr->mr->length;
	wqe->frmr.pbl_pg_sz_log = (wr->mr->page_size >> PAGE_SHIFT_4K) - 1;
	wqe->frmr.va = wr->mr->iova;

	{
		struct bnxt_re_dev *rdev = mr->rdev;
		int i;

		for (i = 0; i < mr->npages; i++)
			dev_dbg(rdev_to_dev(rdev),
				"build_reg_wqe page[%d] = 0x%llx",
				i, mr->pages[i]);
	}
	return 0;
}
#endif

#ifdef HAVE_IB_WR_BIND_MW
static int bnxt_re_build_bind_wqe(struct ib_send_wr *wr,
				  struct bnxt_qplib_swqe *wqe)
{
	struct ib_mw_bind_info *bind_info = get_bind_info(wr);
	struct ib_mw *mw = get_ib_mw(wr);

	wqe->type = BNXT_QPLIB_SWQE_TYPE_BIND_MW;
	wqe->wr_id = wr->wr_id;
	if (wr->send_flags & IB_SEND_SIGNALED)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP;
	if (wr->send_flags & IB_SEND_FENCE)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
	wqe->bind.zero_based = false;

	wqe->bind.parent_l_key = bind_info->mr->lkey;
	wqe->bind.r_key = ib_inc_rkey(mw->rkey);
	wqe->bind.va = bind_info->addr;
	wqe->bind.length = bind_info->length;
	wqe->bind.access_cntl = __from_ib_access_flags(
	bind_info->mw_access_flags);
	wqe->bind.mw_type = mw->type == IB_MW_TYPE_1 ?
			SQ_BIND_MW_TYPE_TYPE1 : SQ_BIND_MW_TYPE_TYPE2;
	return 0;
}
#endif

int bnxt_re_copy_inline_data(struct bnxt_re_dev *rdev, struct ib_send_wr *wr, struct bnxt_qplib_swqe *wqe)
{
	/*  Copy the inline data to the data  field */
	u8 *in_data;
	uint32_t i, sge_len;
	void *sge_addr;

	in_data = wqe->inline_data;
	for (i = 0; i < wr->num_sge; i++) {

		sge_addr = (void *)(unsigned long)
				wr->sg_list[i].addr;
		sge_len = wr->sg_list[i].length;

		if ((sge_len + wqe->inline_len) > BNXT_QPLIB_SWQE_MAX_INLINE_LENGTH) {
			dev_err(rdev_to_dev(rdev),
				"Inline Data size requested ");
			dev_err(rdev_to_dev(rdev),
				"excceeds the supported value");
			return -EINVAL;
		} else {
			sge_len = wr->sg_list[i].length;
		}
		memcpy(in_data, sge_addr, sge_len);
		in_data += wr->sg_list[i].length;
		wqe->inline_len += wr->sg_list[i].length;
	}
	return wqe->inline_len;
}
int bnxt_re_copy_wr_payload(struct bnxt_re_dev *rdev, struct ib_send_wr *wr, struct bnxt_qplib_swqe *wqe)
{
	int payload_sz = 0;

	if (wr->send_flags & IB_SEND_INLINE)
		payload_sz = bnxt_re_copy_inline_data(rdev, wr, wqe);
	else

		payload_sz = bnxt_re_build_sgl(wr->sg_list, wqe->sg_list, wqe->num_sge);

	return payload_sz;
}

void bnxt_ud_qp_hw_stall_workaround(struct bnxt_re_qp *qp)
{
	if ((qp->ib_qp.qp_type == IB_QPT_UD || qp->ib_qp.qp_type == IB_QPT_GSI ||
	    qp->ib_qp.qp_type == IB_QPT_RAW_ETHERTYPE) &&
	    qp->qplib_qp.wqe_cnt == BNXT_RE_UD_QP_HW_STALL) {
		int qp_attr_mask;
		struct ib_qp_attr qp_attr;

		qp_attr_mask = IB_QP_STATE;
		qp_attr.qp_state = IB_QPS_RTS;
		bnxt_re_modify_qp(&qp->ib_qp, &qp_attr, qp_attr_mask, NULL);
		qp->qplib_qp.wqe_cnt = 0;
	}
}

#ifdef ENABLE_SHADOW_QP
int bnxt_re_post_send_shadow_qp(struct bnxt_re_dev *rdev,
				struct bnxt_re_qp *qp,
				struct ib_send_wr *wr)
{
	struct bnxt_qplib_swqe wqe;
	int rc = 0, payload_sz = 0;
	unsigned long flags;

	spin_lock_irqsave(&qp->sq_lock, flags);
	memset(&wqe, 0, sizeof(wqe));
	while (wr) {
		/* House keeping */
		memset(&wqe, 0, sizeof(wqe));

		/* Common */
		wqe.num_sge = wr->num_sge;
		if (wr->num_sge > qp->qplib_qp.sq.max_sge) {
			dev_err(rdev_to_dev(rdev),
				"Limit exceeded for Send SGEs");
			rc = -EINVAL;
			goto bad;
		}

		payload_sz = bnxt_re_copy_wr_payload(qp->rdev, wr, &wqe);
		if (payload_sz < 0) {
			rc = -EINVAL;
			goto bad;
		}
		wqe.wr_id = wr->wr_id;

		wqe.type = BNXT_QPLIB_SWQE_TYPE_SEND;

		rc = bnxt_re_build_send_wqe(qp, wr, &wqe);
		if (!rc)
			rc = bnxt_qplib_post_send(&qp->qplib_qp, &wqe);
bad:
		if (rc) {
			dev_err(rdev_to_dev(rdev),
				"bad_wr seen with opcode = 0x%x rc = %d",
				wr->opcode, rc);
			break;
		}
		wr = wr->next;
	}
	bnxt_qplib_post_send_db(&qp->qplib_qp);
	bnxt_ud_qp_hw_stall_workaround(qp);
	spin_unlock_irqrestore(&qp->sq_lock, flags);
	return rc;
}
#endif

int bnxt_re_post_send(struct ib_qp *ib_qp, struct ib_send_wr *wr,
		      struct ib_send_wr **bad_wr)
{
	struct bnxt_re_qp *qp = to_bnxt_re(ib_qp, struct bnxt_re_qp, ib_qp);
	struct bnxt_qplib_swqe wqe;
	int rc = 0, payload_sz = 0;
	unsigned long flags;

	spin_lock_irqsave(&qp->sq_lock, flags);
	while (wr) {
		/* House keeping */
		memset(&wqe, 0, sizeof(wqe));

		/* Common */
		wqe.num_sge = wr->num_sge;
		if (wr->num_sge > qp->qplib_qp.sq.max_sge) {
			dev_err(rdev_to_dev(qp->rdev),
				"Limit exceeded for Send SGEs");
                        rc = -EINVAL;
                        goto bad;
                }

		payload_sz = bnxt_re_copy_wr_payload(qp->rdev, wr, &wqe);
		if (payload_sz < 0) {
			rc = -EINVAL;
			goto bad;
		}
		wqe.wr_id = wr->wr_id;

		switch (wr->opcode) {
		case IB_WR_SEND:
		case IB_WR_SEND_WITH_IMM:
			if (ib_qp->qp_type == IB_QPT_GSI) {
#ifdef ENABLE_ROCEV2_QP1
				rc = bnxt_re_build_qp1_send_v2(qp, wr, &wqe,
							       payload_sz);
#else
				rc = bnxt_re_build_qp1_send(qp, wr, &wqe,
							    payload_sz);
#endif
				if (rc)
					goto bad;
				wqe.rawqp1.lflags |=
					SQ_SEND_RAWETH_QP1_LFLAGS_ROCE_CRC;

			} else if (ib_qp->qp_type == IB_QPT_RAW_ETHERTYPE) {
				bnxt_re_build_raw_send(wr, &wqe);
			}
			switch (wr->send_flags) {
			case IB_SEND_IP_CSUM:
				wqe.rawqp1.lflags |=
					SQ_SEND_RAWETH_QP1_LFLAGS_IP_CHKSUM;
				break;
			default:
				break;
			}
			/* Fall thru to build the wqe */
		case IB_WR_SEND_WITH_INV:
			rc = bnxt_re_build_send_wqe(qp, wr, &wqe);
			break;
		case IB_WR_RDMA_WRITE:
		case IB_WR_RDMA_WRITE_WITH_IMM:
		case IB_WR_RDMA_READ:
			rc = bnxt_re_build_rdma_wqe(wr, &wqe);
			break;
		case IB_WR_ATOMIC_CMP_AND_SWP:
		case IB_WR_ATOMIC_FETCH_AND_ADD:
			rc = bnxt_re_build_atomic_wqe(wr, &wqe);
			break;
		case IB_WR_RDMA_READ_WITH_INV:
			dev_err(rdev_to_dev(qp->rdev),
				"RDMA Read with Invalidate is not supported");
			rc = -EINVAL;
			goto bad;
		case IB_WR_LOCAL_INV:
			rc = bnxt_re_build_inv_wqe(wr, &wqe);
			break;
#ifdef HAVE_IB_FAST_REG_MR_WR
		case IB_WR_FAST_REG_MR:
			rc = bnxt_re_build_frmr_wqe(wr, &wqe);
			break;
#endif
#ifdef HAVE_IB_REG_MR_WR
		case IB_WR_REG_MR:
			rc = bnxt_re_build_reg_wqe(reg_wr(wr), &wqe);
			break;
#endif
#ifdef HAVE_IB_WR_BIND_MW
		case IB_WR_BIND_MW:
			/* For type 1, 2A, and 2B binding */
			rc = bnxt_re_build_bind_wqe(wr, &wqe);
			break;
#endif
		default:
			/* Unsupported WRs */
			dev_err(rdev_to_dev(qp->rdev),
				"WR (0x%x) is not supported", wr->opcode);
			rc = -EINVAL;
			goto bad;
		}
		if (!rc)
			rc = bnxt_qplib_post_send(&qp->qplib_qp, &wqe);
bad:
		if (rc) {
			dev_err(rdev_to_dev(qp->rdev),
				"bad_wr seen with opcode = 0x%x", wr->opcode);
			*bad_wr = wr;
			break;
		}
		wr = wr->next;
	}
	bnxt_qplib_post_send_db(&qp->qplib_qp);
	bnxt_ud_qp_hw_stall_workaround(qp);
	spin_unlock_irqrestore(&qp->sq_lock, flags);

	return rc;
}

#ifdef ENABLE_SHADOW_QP
int bnxt_re_post_recv_shadow_qp(struct bnxt_re_dev *rdev,
				struct bnxt_re_qp *qp,
				struct ib_recv_wr *wr)
{
	struct bnxt_qplib_swqe wqe;
	int rc = 0, payload_sz = 0;

	memset(&wqe, 0, sizeof(wqe));
	/* rq lock can be pardoned here. */
	while (wr) {
		/* House keeping */
		memset(&wqe, 0, sizeof(wqe));

		/* Common */
		wqe.num_sge = wr->num_sge;
		if (wr->num_sge > qp->qplib_qp.rq.max_sge) {
			dev_err(rdev_to_dev(rdev),
				"Limit exceeded for Receive SGEs");
			rc = -EINVAL;
			goto bad;
		}
		payload_sz = bnxt_re_build_sgl(wr->sg_list, wqe.sg_list,
					       wr->num_sge);
		wqe.wr_id = wr->wr_id;
		wqe.type = BNXT_QPLIB_SWQE_TYPE_RECV;

		if (!rc)
			rc = bnxt_qplib_post_recv(&qp->qplib_qp, &wqe);
bad:
		if (rc) {
			dev_err(rdev_to_dev(rdev),
				"bad_wr seen with RQ post");
			break;
		}
		wr = wr->next;
	}
	bnxt_qplib_post_recv_db(&qp->qplib_qp);
	return rc;
}
#endif

int bnxt_re_post_recv(struct ib_qp *ib_qp, struct ib_recv_wr *wr,
		      struct ib_recv_wr **bad_wr)
{
	struct bnxt_re_qp *qp = to_bnxt_re(ib_qp, struct bnxt_re_qp, ib_qp);
	struct bnxt_qplib_swqe wqe;
	int rc = 0, payload_sz = 0;
	u32 count = 0;
	unsigned long flags;

	spin_lock_irqsave(&qp->rq_lock, flags);
	while (wr) {
		/* House keeping */
		memset(&wqe, 0, sizeof(wqe));

		/* Common */
		wqe.num_sge = wr->num_sge;
		if (wr->num_sge > qp->qplib_qp.rq.max_sge) {
			dev_err(rdev_to_dev(qp->rdev),
				"Limit exceeded for Receive SGEs");
                        rc = -EINVAL;
                        goto bad;
                }
		payload_sz = bnxt_re_build_sgl(wr->sg_list, wqe.sg_list,
					       wr->num_sge);
		wqe.wr_id = wr->wr_id;
		wqe.type = BNXT_QPLIB_SWQE_TYPE_RECV;

		if (ib_qp->qp_type == IB_QPT_GSI)
#ifdef ENABLE_SHADOW_QP
			rc = bnxt_re_build_qp1_shadow_qp_recv(qp, wr, &wqe,
							      payload_sz);
#else
			rc = bnxt_re_build_qp1_recv(qp, wr, &wqe,
						    payload_sz);
#endif
		if (!rc)
			rc = bnxt_qplib_post_recv(&qp->qplib_qp, &wqe);
bad:
		if (rc) {
			dev_err(rdev_to_dev(qp->rdev),
				"bad_wr seen with RQ post");
			*bad_wr = wr;
			break;
		}
		/* Ring DB if the RQEs posted reaches a threshold value */
		if (++count >= BNXT_RE_RQ_WQE_THRESHOLD) {
			bnxt_qplib_post_recv_db(&qp->qplib_qp);
			count = 0;
		}

		wr = wr->next;
	}

	if (count)
		bnxt_qplib_post_recv_db(&qp->qplib_qp);
	spin_unlock_irqrestore(&qp->rq_lock, flags);

	return rc;
}

/* Completion Queues */
int bnxt_re_destroy_cq(struct ib_cq *ib_cq)
{
	struct bnxt_re_cq *cq = to_bnxt_re(ib_cq, struct bnxt_re_cq, ib_cq);
	struct bnxt_re_dev *rdev = cq->rdev;
	int rc;

	rc = bnxt_qplib_destroy_cq(&rdev->qplib_res, &cq->qplib_cq);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Destroy HW CQ failed!");
		return rc;
	}
	/* TODO: Must free the actual CQ DMA memory */
	if (cq->umem && !IS_ERR(cq->umem))
		ib_umem_release(cq->umem);

	if (cq) {
		if (cq->cql)
			kfree(cq->cql);
		kfree(cq);
	}
	atomic_dec(&rdev->cq_count);
	rdev->nq.budget--;
	return 0;
}

#ifdef HAVE_IB_CQ_INIT_ATTR
struct ib_cq *bnxt_re_create_cq(struct ib_device *ibdev,
				const struct ib_cq_init_attr *attr,
				struct ib_ucontext *context,
				struct ib_udata *udata)
#else
struct ib_cq *bnxt_re_create_cq(struct ib_device *ibdev, int cqe,
				int comp_vector, struct ib_ucontext *context,
				struct ib_udata *udata)
#endif
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct bnxt_qplib_dev_attr *dev_attr = &rdev->dev_attr;
	struct bnxt_re_cq *cq;
	int rc, entries;
#ifdef HAVE_IB_CQ_INIT_ATTR
	int cqe = attr->cqe;
	/* TODO: attr->flags holds what info? */
#endif

	/* Validate CQ fields */
	if (cqe < 1 || cqe > dev_attr->max_cq_wqes) {
		dev_err(rdev_to_dev(rdev), "Create CQ failed - max exceeded");
		rc = -EINVAL;
		goto exit;
	}
	cq = kzalloc(sizeof(*cq), GFP_KERNEL);
	if (!cq) {
		dev_err(rdev_to_dev(rdev), "Allocate CQ failed!");
		rc = -ENOMEM;
		goto exit;
	}
	cq->rdev = rdev;
	cq->qplib_cq.cq_handle = (u64)&cq->qplib_cq;

	entries = roundup_pow_of_two(cqe + 1);
	if (entries > dev_attr->max_cq_wqes + 1)
		entries = dev_attr->max_cq_wqes + 1;

	if (context) {
		struct bnxt_re_cq_req req;
		struct bnxt_re_ucontext *uctx = to_bnxt_re(context,
						   struct bnxt_re_ucontext,
						   ib_uctx);
		if (ib_copy_from_udata(&req, udata, sizeof(req))) {
			rc = -EFAULT;
			goto fail;
		}

		cq->umem = ib_umem_get(context, req.cq_va,
				       entries * sizeof(struct cq_base),
				       IB_ACCESS_LOCAL_WRITE, 1);
		if (IS_ERR(cq->umem)) {
			rc = PTR_ERR(cq->umem);
			goto fail;
		}
		cq->qplib_cq.sghead = get_ib_umem_sgl(cq->umem,
						      &cq->qplib_cq.nmap);
		cq->qplib_cq.dpi = &uctx->dpi;
	} else {
		cq->max_cql = entries > MAX_CQL_PER_POLL ? MAX_CQL_PER_POLL : entries;
		cq->max_cql = min_t(u32, entries, MAX_CQL_PER_POLL);
		cq->cql = kcalloc(cq->max_cql, sizeof(struct bnxt_qplib_cqe),
				  GFP_KERNEL);
		if (!cq->cql) {
			dev_err(rdev_to_dev(rdev),
				"Allocate CQL for %d failed!", cq->max_cql);
			rc = -ENOMEM;
			goto fail;
		}
		/* TODO: DPI is for priviledge app for now */

		cq->qplib_cq.dpi = &rdev->dpi_privileged;
		cq->qplib_cq.sghead = NULL;
		cq->qplib_cq.nmap = 0;
	}
	cq->qplib_cq.max_wqe = entries;
	cq->qplib_cq.cnq_hw_ring_id = rdev->nq.ring_id;
	cq->qplib_cq.nq	= &rdev->nq;

	rc = bnxt_qplib_create_cq(&rdev->qplib_res, &cq->qplib_cq);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Create HW CQ failed!");
		goto fail;
	}

	cq->ib_cq.cqe = entries;
	cq->cq_period = cq->qplib_cq.period;
	rdev->nq.budget++;

	atomic_inc(&rdev->cq_count);

	if (context) {
		struct bnxt_re_cq_resp resp;

		resp.cqid = cq->qplib_cq.id;
		resp.tail = cq->qplib_cq.hwq.cons;
		resp.phase = cq->qplib_cq.period;
		rc = bnxt_re_copy_to_udata(rdev, &resp, sizeof(resp), udata);
		if (rc) {
			dev_err(rdev_to_dev(rdev), "CQ copy to udata failed!");
			bnxt_qplib_destroy_cq(&rdev->qplib_res, &cq->qplib_cq);
			goto c2fail;
		}
	}

	return &cq->ib_cq;

c2fail:
	if (context && cq->umem && !IS_ERR(cq->umem))
		ib_umem_release(cq->umem);
fail:
	if (cq) {
		if (cq->cql)
			kfree(cq->cql);
		kfree(cq);
	}
exit:
	return ERR_PTR(rc);
}

int bnxt_re_modify_cq(struct ib_cq *ib_cq, u16 cq_count, u16 cq_period)
{
	struct bnxt_re_cq *cq = to_bnxt_re(ib_cq, struct bnxt_re_cq, ib_cq);
	struct bnxt_re_dev *rdev = cq->rdev;
	int rc;

	if ((cq->cq_count != cq_count) || (cq->cq_period != cq_period)) {
		cq->qplib_cq.count = cq_count;
		cq->qplib_cq.period = cq_period;
		rc = bnxt_qplib_modify_cq(&rdev->qplib_res, &cq->qplib_cq);
		if (rc) {
			dev_err(rdev_to_dev(rdev), "Modify HW CQ failed!");
			return rc;
		}
		/* On success, update the shadow */
		cq->cq_count = cq_count;
		cq->cq_period = cq_period;
	}
	return 0;
}

static void bnxt_re_resize_cq_complete(struct bnxt_re_cq *cq)
{
	struct bnxt_re_dev *rdev = cq->rdev;

	bnxt_qplib_resize_cq_complete(&rdev->qplib_res, &cq->qplib_cq);

	cq->qplib_cq.max_wqe = cq->resize_cqe;
	if (cq->resize_umem) {
		ib_umem_release(cq->umem);
		cq->umem = cq->resize_umem;
		cq->resize_umem = NULL;
		cq->resize_cqe = 0;
	}
}

int bnxt_re_resize_cq(struct ib_cq *ib_cq, int cqe, struct ib_udata *udata)
{
	struct bnxt_re_cq *cq = to_bnxt_re(ib_cq, struct bnxt_re_cq, ib_cq);
	struct bnxt_re_dev *rdev = cq->rdev;
	struct bnxt_qplib_dev_attr *dev_attr = &rdev->dev_attr;
	struct bnxt_re_resize_cq_req req;
	struct bnxt_qplib_dpi *orig_dpi = NULL;
	struct scatterlist *orig_sghead = NULL;
	struct bnxt_re_ucontext *uctx;
	struct ib_ucontext *context;
	int rc, entries;
	u32 orig_nmap = 0;

	/* Don't allow more than one resize request at the same time.
	 * TODO: need a mutex here when we support kernel consumers of resize.
	 */
	if (cq->resize_umem) {
		dev_err(rdev_to_dev(rdev), "Resize CQ failed - Busy");
		return -EBUSY;
	}

	if (cqe == cq->ib_cq.cqe) {
		dev_info(rdev_to_dev(rdev), "CQ is already at size %d", cqe);
		return 0;
	}
	if (cqe < 1 || cqe > dev_attr->max_cq_wqes) {
		dev_err(rdev_to_dev(rdev), "Resize CQ failed - max exceeded");
		return -EINVAL;
	}
	entries = roundup_pow_of_two(cqe + 1);
	entries = min_t(u32, (u32)entries, dev_attr->max_cq_wqes);

	/* TODO: Check to see if the new size can accommodate for all
	 * outstanding signaled SQ elements in the pipe */

	if (ib_cq->uobject) {
		/* uverbs consumer */
		context = cq->umem->context;
		uctx = to_bnxt_re(context, struct bnxt_re_ucontext, ib_uctx);

		if (ib_copy_from_udata(&req, udata, sizeof(req))) {
			rc = -EFAULT;
			goto fail;
		}

		dev_dbg(rdev_to_dev(rdev), "%s: va %p", __func__,
			(void *)req.cq_va);
		cq->resize_umem = ib_umem_get(context, req.cq_va,
					      entries * sizeof(struct cq_base),
					      IB_ACCESS_LOCAL_WRITE, 1);
		if (IS_ERR(cq->resize_umem)) {
			rc = PTR_ERR(cq->resize_umem);
			cq->resize_umem = NULL;
			dev_err(rdev_to_dev(rdev),
				"Resize CQ failed - failed to map user memory");
			goto fail;
		}
		cq->resize_cqe = entries;
		dev_dbg(rdev_to_dev(rdev), "%s: ib_umem_get() success\n",
			__func__);

		orig_sghead = cq->qplib_cq.sghead;
		orig_dpi = cq->qplib_cq.dpi;
		orig_nmap = cq->qplib_cq.nmap;
		cq->qplib_cq.sghead = get_ib_umem_sgl(cq->resize_umem,
						      &cq->qplib_cq.nmap);
		cq->qplib_cq.dpi = &uctx->dpi;
	} else {
		/* TODO: kernel consumer */
	}

	rc = bnxt_qplib_resize_cq(&rdev->qplib_res, &cq->qplib_cq, entries);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Resize HW CQ failed!");
		goto fail;
	}

	cq->ib_cq.cqe = cq->resize_cqe;
	/* For kernel consumers complete resize here. For uverbs consumers,
	 * we complete it in the context of ibv_poll_cq().
	 */
	if (!cq->resize_umem)
		bnxt_qplib_resize_cq_complete(&rdev->qplib_res, &cq->qplib_cq);

	return 0;

fail:
	if (cq->resize_umem) {
		ib_umem_release(cq->resize_umem);
		cq->resize_umem = NULL;
		cq->resize_cqe = 0;
		cq->qplib_cq.sghead = orig_sghead;
		cq->qplib_cq.nmap = orig_nmap;
		cq->qplib_cq.dpi = orig_dpi;
	}
	return rc;
}

static u8 __req_to_ib_wc_status(u8 qstatus)
{
	switch(qstatus) {
	case CQ_REQ_STATUS_OK:
		return IB_WC_SUCCESS;
	case CQ_REQ_STATUS_BAD_RESPONSE_ERR:
		return IB_WC_BAD_RESP_ERR;
	case CQ_REQ_STATUS_LOCAL_LENGTH_ERR:
		return IB_WC_LOC_LEN_ERR;
	case CQ_REQ_STATUS_LOCAL_QP_OPERATION_ERR:
		return IB_WC_LOC_QP_OP_ERR;
	case CQ_REQ_STATUS_LOCAL_PROTECTION_ERR:
		return IB_WC_LOC_PROT_ERR;
	case CQ_REQ_STATUS_MEMORY_MGT_OPERATION_ERR:
		return IB_WC_GENERAL_ERR;
	case CQ_REQ_STATUS_REMOTE_INVALID_REQUEST_ERR:
		return IB_WC_REM_INV_REQ_ERR;
	case CQ_REQ_STATUS_REMOTE_ACCESS_ERR:
		return IB_WC_REM_ACCESS_ERR;
	case CQ_REQ_STATUS_REMOTE_OPERATION_ERR:
		return IB_WC_REM_OP_ERR;
	case CQ_REQ_STATUS_RNR_NAK_RETRY_CNT_ERR:
		return IB_WC_RNR_RETRY_EXC_ERR;
	case CQ_REQ_STATUS_TRANSPORT_RETRY_CNT_ERR:
		return IB_WC_RETRY_EXC_ERR;
	case CQ_REQ_STATUS_WORK_REQUEST_FLUSHED_ERR:
		return IB_WC_WR_FLUSH_ERR;
	default:
		return IB_WC_GENERAL_ERR;
	}
	return 0;
}

static u8 __rawqp1_to_ib_wc_status(u8 qstatus)
{
	switch(qstatus) {
	case CQ_RES_RAWETH_QP1_STATUS_OK:
		return IB_WC_SUCCESS;
	case CQ_RES_RAWETH_QP1_STATUS_LOCAL_ACCESS_ERROR:
		return IB_WC_LOC_ACCESS_ERR;
	case CQ_RES_RAWETH_QP1_STATUS_HW_LOCAL_LENGTH_ERR:
		return IB_WC_LOC_LEN_ERR;
	case CQ_RES_RAWETH_QP1_STATUS_LOCAL_PROTECTION_ERR:
		return IB_WC_LOC_PROT_ERR;
	case CQ_RES_RAWETH_QP1_STATUS_LOCAL_QP_OPERATION_ERR:
		return IB_WC_LOC_QP_OP_ERR;
	case CQ_RES_RAWETH_QP1_STATUS_MEMORY_MGT_OPERATION_ERR:
		return IB_WC_GENERAL_ERR;
	case CQ_RES_RAWETH_QP1_STATUS_WORK_REQUEST_FLUSHED_ERR:
		return IB_WC_WR_FLUSH_ERR;
	case CQ_RES_RAWETH_QP1_STATUS_HW_FLUSH_ERR:
		return IB_WC_WR_FLUSH_ERR;
	default:
		return IB_WC_GENERAL_ERR;
	}
}

static u8 __rc_to_ib_wc_status(u8 qstatus)
{
	switch(qstatus) {
	case CQ_RES_RC_STATUS_OK:
		return IB_WC_SUCCESS;
	case CQ_RES_RC_STATUS_LOCAL_ACCESS_ERROR:
		return IB_WC_LOC_ACCESS_ERR;
	case CQ_RES_RC_STATUS_LOCAL_LENGTH_ERR:
		return IB_WC_LOC_LEN_ERR;
	case CQ_RES_RC_STATUS_LOCAL_PROTECTION_ERR:
		return IB_WC_LOC_PROT_ERR;
	case CQ_RES_RC_STATUS_LOCAL_QP_OPERATION_ERR:
		return IB_WC_LOC_QP_OP_ERR;
	case CQ_RES_RC_STATUS_MEMORY_MGT_OPERATION_ERR:
		return IB_WC_GENERAL_ERR;
	case CQ_RES_RC_STATUS_REMOTE_INVALID_REQUEST_ERR:
		return IB_WC_REM_INV_REQ_ERR;
	case CQ_RES_RC_STATUS_WORK_REQUEST_FLUSHED_ERR:
		return IB_WC_WR_FLUSH_ERR;
	case CQ_RES_RC_STATUS_HW_FLUSH_ERR:
		return IB_WC_WR_FLUSH_ERR;
	default:
		return IB_WC_GENERAL_ERR;
	}
}

/*
static u8 __to_ib_wc_opcode(u8 qplib_type)
{
	return 0;
}
*/

static void bnxt_re_process_req_wc(struct ib_wc *wc, struct bnxt_qplib_cqe *cqe)
{
	switch (cqe->type) {
	case BNXT_QPLIB_SWQE_TYPE_SEND:
		wc->opcode = IB_WC_SEND;
		break;
	case BNXT_QPLIB_SWQE_TYPE_SEND_WITH_IMM:
		wc->opcode = IB_WC_SEND;
		wc->wc_flags |= IB_WC_WITH_IMM;
		break;
	case BNXT_QPLIB_SWQE_TYPE_SEND_WITH_INV:
		wc->opcode = IB_WC_SEND;
		wc->wc_flags |= IB_WC_WITH_INVALIDATE;
		break;
	case BNXT_QPLIB_SWQE_TYPE_RDMA_WRITE:
		wc->opcode = IB_WC_RDMA_WRITE;
		break;
	case BNXT_QPLIB_SWQE_TYPE_RDMA_WRITE_WITH_IMM:
		wc->opcode = IB_WC_RDMA_WRITE;
		wc->wc_flags |= IB_WC_WITH_IMM;
		break;
	case BNXT_QPLIB_SWQE_TYPE_RDMA_READ:
		wc->opcode = IB_WC_RDMA_READ;
		break;
	case BNXT_QPLIB_SWQE_TYPE_ATOMIC_CMP_AND_SWP:
		wc->opcode = IB_WC_COMP_SWAP;
		break;
	case BNXT_QPLIB_SWQE_TYPE_ATOMIC_FETCH_AND_ADD:
		wc->opcode = IB_WC_FETCH_ADD;
		break;
	case BNXT_QPLIB_SWQE_TYPE_LOCAL_INV:
		wc->opcode = IB_WC_LOCAL_INV;
		break;
#ifdef HAVE_IB_FAST_REG_MR_WR
	case BNXT_QPLIB_SWQE_TYPE_FAST_REG_MR:
		wc->opcode = IB_WC_FAST_REG_MR;
		break;
#endif
#ifdef HAVE_IB_REG_MR_WR
	case BNXT_QPLIB_SWQE_TYPE_REG_MR:
		wc->opcode = IB_WC_REG_MR;
		break;
#endif
	default:
		wc->opcode = IB_WC_SEND;
		break;
	}

	wc->status = __req_to_ib_wc_status(cqe->status);
}

#ifdef ENABLE_SHADOW_QP
int bnxt_re_check_packet_type(u16 raweth_qp1_flags, u16 raweth_qp1_flags2)
{
	bool is_udp = false, is_ipv6 = false, is_ipv4 = false;

	/* raweth_qp1_flags Bit 9-6 indicates itype */

	if ((raweth_qp1_flags & CQ_RES_RAWETH_QP1_RAWETH_QP1_FLAGS_ITYPE_ROCE)
	    != CQ_RES_RAWETH_QP1_RAWETH_QP1_FLAGS_ITYPE_ROCE)
		return -1;

	if (raweth_qp1_flags2 &
	    CQ_RES_RAWETH_QP1_RAWETH_QP1_FLAGS2_IP_CS_CALC &&
	    raweth_qp1_flags2 &
	    CQ_RES_RAWETH_QP1_RAWETH_QP1_FLAGS2_L4_CS_CALC) {
		is_udp = true;
		/* raweth_qp1_flags2 Bit 8 indicates ip_type. 0-v4 1 - v6 */
		(raweth_qp1_flags2 &
		 CQ_RES_RAWETH_QP1_RAWETH_QP1_FLAGS2_IP_TYPE) ?
			(is_ipv6 = true) : (is_ipv4 = true);
		return ((is_ipv6) ?
			 BNXT_RE_ROCEV2_IPV6_PACKET :
			 BNXT_RE_ROCEV2_IPV4_PACKET);
	} else {
		return BNXT_RE_ROCE_V1_PACKET;
	}
}

#ifdef ENABLE_ROCEV2_QP1
static int bnxt_re_to_ib_nw_type(int nw_type)
{
	u8 nw_hdr_type = 0xFF;

	switch (nw_type) {
	case BNXT_RE_ROCE_V1_PACKET:
		nw_hdr_type = RDMA_NETWORK_ROCE_V1;
		break;
	case BNXT_RE_ROCEV2_IPV4_PACKET:
		nw_hdr_type = RDMA_NETWORK_IPV4;
		break;
	case BNXT_RE_ROCEV2_IPV6_PACKET:
		nw_hdr_type = RDMA_NETWORK_IPV6;
		break;
	}
	return nw_hdr_type;
}
#endif

static bool bnxt_re_is_loopback_packet(struct bnxt_re_dev *rdev,
					    void *rq_hdr_buf)
{
	u8 *tmp_buf = NULL;
	struct ethhdr *eth_hdr;
	u16 eth_type;
	bool rc = false;

	tmp_buf = (u8 *)rq_hdr_buf;
	/*
	 * If dest mac is not same as I/F mac, this could be a
	 * loopback address or multicast address, check whether
	 * it is a loopback packet
	 */
	if (!ether_addr_equal(tmp_buf, rdev->netdev->dev_addr)) {
		tmp_buf += 4;
		/* Check the  ether type */
		eth_hdr = (struct ethhdr *)tmp_buf;
		eth_type = ntohs(eth_hdr->h_proto);
		switch (eth_type) {
		case BNXT_QPLIB_ETHTYPE_ROCEV1:
			rc = true;
			break;
#ifdef ENABLE_ROCEV2_QP1
		case ETH_P_IP:
		case ETH_P_IPV6: {
			u32 len;
			struct udphdr *udp_hdr;

			len = (eth_type == ETH_P_IP ? sizeof(struct iphdr) :
						      sizeof(struct ipv6hdr));
			tmp_buf += sizeof(struct ethhdr) + len;
			udp_hdr = (struct udphdr *)tmp_buf;
			if (ntohs(udp_hdr->dest) ==
				    ROCE_V2_UDP_DPORT)
				rc = true;
				break;
			}
#endif
		default:
			break;
		}
	}

	return rc;
}

static int bnxt_re_process_raw_qp_packet_receive(struct bnxt_re_qp *qp1_qp,
						 struct bnxt_qplib_cqe *cqe)
{
	struct bnxt_re_dev *rdev = qp1_qp->rdev;
	struct bnxt_re_sqp_entries *sqp_entry = NULL;
	struct bnxt_re_qp *qp = rdev->qp1_sqp;
	struct ib_send_wr *swr;
#ifdef HAVE_IB_UD_WR
	struct ib_ud_wr udwr;
#else
	struct ib_send_wr udwr;
#endif
	struct ib_recv_wr rwr;
	u8 pkt_type = 0;
	u32 tbl_idx;
	void *rq_hdr_buf;
	dma_addr_t rq_hdr_buf_map;
	dma_addr_t shrq_hdr_buf_map;
	u32 offset = 0;
	u32 skip_bytes = 0;
	struct ib_sge s_sge[2];
	struct ib_sge r_sge[2];
	int rc;

	memset(&udwr, 0, sizeof(udwr));
	memset(&rwr, 0, sizeof(rwr));
	memset(&s_sge, 0, sizeof(s_sge));
	memset(&r_sge, 0, sizeof(r_sge));

#ifdef HAVE_IB_UD_WR
	swr = &udwr.wr;
#else
	swr = &udwr;
#endif
	tbl_idx = cqe->wr_id;

	rq_hdr_buf = qp1_qp->qplib_qp.rq_hdr_buf +
			(tbl_idx * qp1_qp->qplib_qp.rq_hdr_buf_size);
	rq_hdr_buf_map = bnxt_qplib_get_qp_buf_from_index(&qp1_qp->qplib_qp,
							  tbl_idx);

	/* Shadow QP header buffer */
	shrq_hdr_buf_map = bnxt_qplib_get_qp_buf_from_index(&qp->qplib_qp,
							    tbl_idx);
	sqp_entry = &rdev->sqp_tbl[tbl_idx];

	/* Store this cqe */
	memcpy(&sqp_entry->cqe, cqe, sizeof(struct bnxt_qplib_cqe));
	sqp_entry->qp1_qp = qp1_qp;

	/* Find packet type from the cqe */

	pkt_type = bnxt_re_check_packet_type(cqe->raweth_qp1_flags,
					     cqe->raweth_qp1_flags2);
	if (pkt_type < 0) {
		dev_err(rdev_to_dev(rdev), "Not handling this packet\n");
		return -EINVAL;
	}

	/* Adjust the offset for the user buffer and post in the rq */

	if (pkt_type == BNXT_RE_ROCEV2_IPV4_PACKET)
		offset = 20;

	/*
	 * QP1 loopback packet has 4 bytes of internal header before
	 * ether header. Skip these four bytes.
	 */
	if (bnxt_re_is_loopback_packet(rdev, rq_hdr_buf))
		skip_bytes = 4;

	/* First send SGE . Skip the ether header*/
	s_sge[0].addr = rq_hdr_buf_map + BNXT_QPLIB_MAX_QP1_RQ_ETH_HDR_SIZE
			+ skip_bytes;
	s_sge[0].lkey = 0xFFFFFFFF;
	s_sge[0].length = offset ? BNXT_QPLIB_MAX_GRH_HDR_SIZE_IPV4 :
				BNXT_QPLIB_MAX_GRH_HDR_SIZE_IPV6;

	/* Second Send SGE */
	s_sge[1].addr = s_sge[0].addr + s_sge[0].length +
			BNXT_QPLIB_MAX_QP1_RQ_BDETH_HDR_SIZE;
	if (pkt_type != BNXT_RE_ROCE_V1_PACKET)
		s_sge[1].addr += 8;
	s_sge[1].lkey = 0xFFFFFFFF;
	s_sge[1].length = 256;

	rq_hdr_buf = (char *)rq_hdr_buf +  BNXT_QPLIB_MAX_QP1_RQ_ETH_HDR_SIZE
					+ skip_bytes;

	/* TODO: Remove the debug prints */
	if (0) {
		int i;

		pr_err("recevice data \n");
		for (i = 0; i < s_sge[0].length / 4; ++i) {
			if (i % 8 == 0)
				pr_err("  [%02x] ", i * 4);
			pr_cont(" %08x",
					be32_to_cpu(((__be32 *) rq_hdr_buf)[i]));
			if ((i + 1) % 8 == 0)
				pr_cont("\n");
		}
		pr_err("\n");
	}

	rq_hdr_buf = (char *)rq_hdr_buf +  s_sge[0].length +
			BNXT_QPLIB_MAX_QP1_RQ_BDETH_HDR_SIZE + 8;
	if (0) {
		int i;
		pr_err("recevice data 2\n");
		for (i = 0; i < s_sge[0].length / 4; ++i) {
			if (i % 8 == 0)
				pr_err("  [%02x] ", i * 4);
			pr_cont(" %08x",
					be32_to_cpu(((__be32 *) rq_hdr_buf)[i]));
			if ((i + 1) % 8 == 0)
				pr_cont("\n");
		}
		pr_err("\n");
	}

	/* First recv SGE */

	r_sge[0].addr = shrq_hdr_buf_map;
	r_sge[0].lkey = 0xFFFFFFFF;
	r_sge[0].length = 40;

	r_sge[1].addr = sqp_entry->sge.addr + offset;
	r_sge[1].lkey = sqp_entry->sge.lkey;
	r_sge[1].length = BNXT_QPLIB_MAX_GRH_HDR_SIZE_IPV6 + 256 - offset;

	/* Create receive work request */
	rwr.num_sge = 2;
	rwr.sg_list = r_sge;
	rwr.wr_id = tbl_idx;
	rwr.next = NULL;

	rc = bnxt_re_post_recv_shadow_qp(rdev, qp, &rwr);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to post Rx buffers to shadow QP");
		return -ENOMEM;
	}

	swr->num_sge = 2;
	swr->sg_list = s_sge;
	swr->wr_id = tbl_idx;
	swr->opcode = IB_WR_SEND;
	swr->next = NULL;

#ifdef HAVE_IB_UD_WR
	udwr.ah = &rdev->sqp_ah->ib_ah;
	udwr.remote_qpn = rdev->qp1_sqp->qplib_qp.id;
	udwr.remote_qkey = rdev->qp1_sqp->qplib_qp.qkey;
#else
	udwr.wr.ud.ah = &rdev->sqp_ah->ib_ah;
	udwr.wr.ud.remote_qpn = rdev->qp1_sqp->qplib_qp.id;
	udwr.wr.ud.remote_qkey = rdev->qp1_sqp->qplib_qp.qkey;
#endif

	/* post data received  in the send queue */
	rc = bnxt_re_post_send_shadow_qp(rdev, qp, swr);

	return 0;
}
#endif

static void bnxt_re_process_res_rawqp1_wc(struct ib_wc *wc,
					  struct bnxt_qplib_cqe *cqe)
{
	wc->opcode = IB_WC_RECV;
	wc->status = __rawqp1_to_ib_wc_status(cqe->status);
	wc->wc_flags |= IB_WC_GRH;
}

static void bnxt_re_process_res_rc_wc(struct ib_wc *wc,
				      struct bnxt_qplib_cqe *cqe)
{
	wc->opcode = IB_WC_RECV;
	wc->status = __rc_to_ib_wc_status(cqe->status);

	if (cqe->flags & CQ_RES_RC_FLAGS_IMM)
		wc->wc_flags |= IB_WC_WITH_IMM;
	if (cqe->flags & CQ_RES_RC_FLAGS_INV)
		wc->wc_flags |= IB_WC_WITH_INVALIDATE;
	if ((cqe->flags & (CQ_RES_RC_FLAGS_RDMA | CQ_RES_RC_FLAGS_IMM)) ==
	    (CQ_RES_RC_FLAGS_RDMA | CQ_RES_RC_FLAGS_IMM))
		wc->opcode = IB_WC_RECV_RDMA_WITH_IMM;
}

#ifdef ENABLE_SHADOW_QP
static void bnxt_re_process_res_shadow_qp_wc(struct bnxt_re_qp *qp,
					     struct ib_wc *wc,
					     struct bnxt_qplib_cqe *cqe)
{
	u32 tbl_idx;
	struct bnxt_re_dev *rdev = qp->rdev;
	struct bnxt_re_qp *qp1_qp = NULL;
	struct bnxt_qplib_cqe *orig_cqe = NULL;
	struct bnxt_re_sqp_entries *sqp_entry = NULL;
	int nw_type;

	tbl_idx = cqe->wr_id;

	sqp_entry = &rdev->sqp_tbl[tbl_idx];
	qp1_qp = sqp_entry->qp1_qp;
	orig_cqe = &sqp_entry->cqe;

	wc->wr_id = sqp_entry->wrid;
	/* TODO Check whether this needs to be altered.*/
	wc->byte_len = orig_cqe->length;
	wc->qp = &qp1_qp->ib_qp;

	wc->ex.imm_data = orig_cqe->immdata_or_invrkey;
	wc->src_qp = orig_cqe->src_qp;
	memcpy(wc->smac, orig_cqe->smac, ETH_ALEN);
	wc->port_num = 1;
	wc->vendor_err = orig_cqe->status;

	wc->opcode = IB_WC_RECV;
	wc->status = __rawqp1_to_ib_wc_status(orig_cqe->status);
	wc->wc_flags |= IB_WC_GRH;

	nw_type = bnxt_re_check_packet_type(orig_cqe->raweth_qp1_flags,
					    orig_cqe->raweth_qp1_flags2);
	dev_dbg(rdev_to_dev(rdev), "%s nw_type = %d\n", __func__, nw_type);
#ifdef ENABLE_ROCEV2_QP1
	if (nw_type >= 0) {
		wc->network_hdr_type = bnxt_re_to_ib_nw_type(nw_type);
		wc->wc_flags |= IB_WC_WITH_NETWORK_HDR_TYPE;
	}
#endif
}
#endif

static void bnxt_re_process_res_ud_wc(struct ib_wc *wc,
				      struct bnxt_qplib_cqe *cqe)
{
	/* TODO: UD is not implemented yet */
	wc->opcode = IB_WC_RECV;
	wc->status = __rc_to_ib_wc_status(cqe->status);

	if (cqe->flags & CQ_RES_RC_FLAGS_IMM)
		wc->wc_flags |= IB_WC_WITH_IMM;
	if (cqe->flags & CQ_RES_RC_FLAGS_INV)
		wc->wc_flags |= IB_WC_WITH_INVALIDATE;
	if ((cqe->flags & (CQ_RES_RC_FLAGS_RDMA | CQ_RES_RC_FLAGS_IMM)) ==
	    (CQ_RES_RC_FLAGS_RDMA | CQ_RES_RC_FLAGS_IMM))
		wc->opcode = IB_WC_RECV_RDMA_WITH_IMM;
}

#ifndef WA9060_DELAY
#ifdef BIND_MW_FENCE_WQE
static int send_phantom_wqe(struct bnxt_re_qp *qp)
{
	struct bnxt_qplib_qp *lib_qp = &qp->qplib_qp;
	unsigned long flags;
	int rc = 0;

	spin_lock_irqsave(&qp->sq_lock, flags);

	rc = bnxt_re_bind_fence_mw(lib_qp);
	if (!rc) {
		lib_qp->sq.phantom_wqe_cnt++;
		dev_dbg(&lib_qp->sq.hwq.pdev->dev,
			"qp %#x sq->prod %#x sw_prod %#x phantom_wqe_cnt %d\n",
			lib_qp->id, lib_qp->sq.hwq.prod,
			HWQ_CMP(lib_qp->sq.hwq.prod, &lib_qp->sq.hwq),
			lib_qp->sq.phantom_wqe_cnt);
	}

	spin_unlock_irqrestore(&qp->sq_lock, flags);
	return rc;
}
#else
static int send_phantom_wqe(struct bnxt_re_qp *qp)
{
	struct bnxt_qplib_qp *lib_qp = &qp->qplib_qp;
	struct bnxt_qplib_swqe wqe;
	unsigned long flags;
	int rc = 0;

	spin_lock_irqsave(&qp->sq_lock, flags);

	wqe.num_sge = 0;
	wqe.wr_id = BNXT_QPLIB_FENCE_WRID;
	wqe.type = BNXT_QPLIB_SWQE_TYPE_RDMA_WRITE;
	wqe.flags = BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP |
		BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;

	rc = bnxt_qplib_post_send(lib_qp, &wqe);
	if (!rc) {
		lib_qp->sq.phantom_wqe_cnt++;
		bnxt_qplib_post_send_db(lib_qp);
		dev_dbg(&lib_qp->sq.hwq.pdev->dev,
			"qp %#x sq->prod %#x sw_prod %#x phantom_wqe_cnt %d\n",
			lib_qp->id, lib_qp->sq.hwq.prod,
	}

	spin_unlock_irqrestore(&qp->sq_lock, flags);
	return rc;
}
#endif
#endif

int bnxt_re_poll_cq(struct ib_cq *ib_cq, int num_entries, struct ib_wc *wc)
{
	struct bnxt_re_cq *cq = to_bnxt_re(ib_cq, struct bnxt_re_cq, ib_cq);
	struct bnxt_re_qp *qp;
	struct bnxt_qplib_cqe *cqe;
	int i, ncqe, budget;
	struct bnxt_qplib_q *sq;
	struct bnxt_qplib_qp *lib_qp;
#ifdef ENABLE_SHADOW_QP
	u32 tbl_idx;
        struct bnxt_re_sqp_entries *sqp_entry = NULL;
#endif
	unsigned long flags;

	spin_lock_irqsave(&cq->cq_lock, flags);

	/* User CQ; the only processing we do is to
	 * complete any pending CQ resize operation.
	 */
	if (cq->umem) {
		if (cq->resize_umem)
			bnxt_re_resize_cq_complete(cq);
		spin_unlock_irqrestore(&cq->cq_lock, flags);
		return 0;
	}

	budget = min_t(u32, num_entries, cq->max_cql);
	if (!cq->cql) {
		dev_err(rdev_to_dev(cq->rdev), "POLL CQ no CQL to use");
		goto exit;
	}
	cqe = &cq->cql[0];
	while (budget) {
		lib_qp = NULL;
		ncqe = bnxt_qplib_poll_cq(&cq->qplib_cq, cqe, budget, &lib_qp);
		if (lib_qp) {
			sq = &lib_qp->sq;
			if (sq->send_phantom == true) {
				qp = container_of(lib_qp, struct bnxt_re_qp, qplib_qp);
				if (send_phantom_wqe(qp) == -ENOMEM)
					dev_err(rdev_to_dev(cq->rdev),
						"Phantom failed! Scheduled to send again\n");
				else
					sq->send_phantom = false;
			}
		}
		if (ncqe < budget)
			ncqe += bnxt_qplib_process_flush_list(&cq->qplib_cq,
							    &cq->cql[ncqe],
							    budget - ncqe);

		if (!ncqe)
			break;

		for (i = 0; i < ncqe; i++, cqe++) {
			/* Transcribe each qplib_wqe back to ib_wc */
			memset(wc, 0, sizeof(*wc));

			wc->wr_id = cqe->wr_id;
			wc->byte_len = cqe->length;
			qp = to_bnxt_re((struct bnxt_qplib_qp *)cqe->qp_handle,
					struct bnxt_re_qp, qplib_qp);
			if (!qp) {
				dev_err(rdev_to_dev(cq->rdev),
					"POLL CQ bad QP handle");
				continue;
			}
			wc->qp = &qp->ib_qp;
			wc->ex.imm_data = cqe->immdata_or_invrkey;
			wc->src_qp = cqe->src_qp;
			memcpy(wc->smac, cqe->smac, ETH_ALEN);
			wc->port_num = 1;
			wc->vendor_err = cqe->status;

			switch(cqe->opcode) {
			case CQ_BASE_CQE_TYPE_REQ:
#ifdef ENABLE_SHADOW_QP
				if (qp->qplib_qp.id ==
				    qp->rdev->qp1_sqp->qplib_qp.id) {
					/* Handle this completion with
					 * the stored completion */
					 dev_dbg(rdev_to_dev(cq->rdev),
						  "Skipping this UD Send CQ\n");
					memset(wc, 0, sizeof(*wc));
					continue;
				}
#endif
				bnxt_re_process_req_wc(wc, cqe);
				break;
			case CQ_BASE_CQE_TYPE_RES_RAWETH_QP1:
#ifdef ENABLE_SHADOW_QP
				if (!cqe->status) {
					int rc = 0;
					rc = bnxt_re_process_raw_qp_packet_receive(qp, cqe);
					if (!rc) {
						memset(wc, 0, sizeof(*wc));
						continue;
					}
					/* TODO Respond with error to the stack */
					cqe->status = -1;
				}
				/* Errors need not be looped back.
				 * But change the wr_id to the one
				 * stored in the table
				 */
				tbl_idx = cqe->wr_id;
				sqp_entry = &cq->rdev->sqp_tbl[tbl_idx];
				wc->wr_id = sqp_entry->wrid;
#endif
				bnxt_re_process_res_rawqp1_wc(wc, cqe);
				break;
			case CQ_BASE_CQE_TYPE_RES_RC:
				bnxt_re_process_res_rc_wc(wc, cqe);
				break;
			case CQ_BASE_CQE_TYPE_RES_UD:
#ifdef ENABLE_SHADOW_QP
				if (qp->qplib_qp.id ==
				    qp->rdev->qp1_sqp->qplib_qp.id) {
					/* Handle this completion with
					 * the stored completion
					 */
					dev_dbg(rdev_to_dev(cq->rdev),
						 "Handling the UD receive CQ\n");
					if (cqe->status) {
						/* TODO handle this completion  as a failure in
						 * loopback porocedure
						 */
						continue;
					} else {
						bnxt_re_process_res_shadow_qp_wc(qp, wc, cqe);
						break;
					}
				}
#endif
				bnxt_re_process_res_ud_wc(wc, cqe);
				break;
			default:
				dev_err(rdev_to_dev(cq->rdev),
					"POLL CQ type 0x%x not handled, skip!",
					cqe->opcode);
				continue;
			}
			wc++;
			budget--;
		}
	}
exit:
	spin_unlock_irqrestore(&cq->cq_lock, flags);
	return num_entries - budget;
}

int bnxt_re_req_notify_cq(struct ib_cq *ib_cq,
			  enum ib_cq_notify_flags ib_cqn_flags)
{
	struct bnxt_re_cq *cq = to_bnxt_re(ib_cq, struct bnxt_re_cq, ib_cq);
	int type = 0;

	/* Trigger on the very next completion */
	if (ib_cqn_flags & IB_CQ_NEXT_COMP)
		type = DBR_DBR_TYPE_CQ_ARMALL;
	/* Trigger on the next solicited completion */
	else if (ib_cqn_flags & IB_CQ_SOLICITED)
		type = DBR_DBR_TYPE_CQ_ARMSE;

	bnxt_qplib_req_notify_cq(&cq->qplib_cq, type);

	/* TODO: Poll to see if there are missed events; how?? */
//	if (ib_cqn_flags & IB_CQ_REPORT_MISSED_EVENTS)
//		return 1;

	return 0;
}

/* Memory Regions */
struct ib_mr *bnxt_re_get_dma_mr(struct ib_pd *ib_pd, int mr_access_flags)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_mr *mr;
	u64 pbl = 0;
	int rc;

	dev_dbg(rdev_to_dev(rdev), "Get DMA MR");
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		dev_err(rdev_to_dev(rdev),
			"Allocate memory for DMA MR failed!");
		return ERR_PTR(-ENOMEM);
	}
	mr->rdev = rdev;
	mr->qplib_mr.pd = &pd->qplib_pd;
	mr->qplib_mr.flags = __from_ib_access_flags(mr_access_flags);
	mr->qplib_mr.type = CMDQ_ALLOCATE_MRW_MRW_FLAGS_PMR;

	/* Allocate and register 0 as the address */
	rc = bnxt_qplib_alloc_mrw(&rdev->qplib_res, &mr->qplib_mr);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Allocate DMA MR failed!");
		goto fail;
	}
	mr->qplib_mr.hwq.level = PBL_LVL_MAX;
	mr->qplib_mr.total_size = -1; /* Infinte length */
	rc = bnxt_qplib_reg_mr(&rdev->qplib_res, &mr->qplib_mr, &pbl, 0, false);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Register DMA MR failed!");
		goto fail_mr;
	}
	mr->ib_mr.lkey = mr->qplib_mr.lkey;
	if (mr_access_flags & (IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ |
			       IB_ACCESS_REMOTE_ATOMIC))
		mr->ib_mr.rkey = mr->ib_mr.lkey;
	atomic_inc(&rdev->mr_count);

	return &mr->ib_mr;

fail_mr:
	bnxt_qplib_free_mrw(&rdev->qplib_res, &mr->qplib_mr);
fail:
	kfree(mr);
	return ERR_PTR(rc);
}

#ifdef HAVE_IB_REG_PHYS_MR
static u32 __get_phys_page_count(struct ib_phys_buf *phys_buf_array,
				 int num_phys_buf)
{
	int i, pages;

	/* Calculate the size of the PTL needed */
	for (i = 0, pages = 0; i < num_phys_buf; i++)
		pages += DIV_ROUND_UP(phys_buf_array[i].size, PAGE_SIZE);

	return pages;
}

struct ib_mr *bnxt_re_reg_phys_mr(struct ib_pd *ib_pd,
				  struct ib_phys_buf *phys_buf_array,
				  int num_phys_buf, int mr_access_flags,
				  u64 *iova_start)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_mr *mr;
	u64 *pbl_tbl, *pbl_tbl_orig;
	int i, j, num_pgs, pages, rc;

	dev_dbg(rdev_to_dev(rdev), "Reg phys MR");
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		dev_err(rdev_to_dev(rdev), "Allocate MR failed!");
		return ERR_PTR(-ENOMEM);
	}
	mr->rdev = rdev;
	mr->qplib_mr.pd = &pd->qplib_pd;
	mr->qplib_mr.type = CMDQ_ALLOCATE_MRW_MRW_FLAGS_PMR;

	rc = bnxt_qplib_alloc_mrw(&rdev->qplib_res, &mr->qplib_mr);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "HW alloc MR failed!");
		goto fail;
	}
	mr->ib_mr.lkey = mr->qplib_mr.lkey;
	if (mr_access_flags & (IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ |
			       IB_ACCESS_REMOTE_ATOMIC))
		mr->ib_mr.rkey = mr->ib_mr.lkey;

	/* Must unravel the ib_phys_buf->addr/size to align with
	   what the hw expects */
	mr->qplib_mr.va = *iova_start;
	num_pgs = __get_phys_page_count(phys_buf_array, num_phys_buf);
	if (!num_pgs) {
		dev_err(rdev_to_dev(rdev), "Phys buf array is invalid!");
		rc = -EINVAL;
		goto fail_mr;
	}

	pbl_tbl = kcalloc(num_pgs, sizeof(u64 *), GFP_KERNEL);
	if (!pbl_tbl) {
		dev_err(rdev_to_dev(rdev), "Allocate pbl_tbl failed!");
		rc = -EINVAL;
		goto fail_mr;
	}
	pbl_tbl_orig = pbl_tbl;
	for (i = 0; i < num_phys_buf; i++) {
		pages = DIV_ROUND_UP(phys_buf_array[i].size, PAGE_SIZE);
		mr->qplib_mr.total_size += phys_buf_array[i].size;
		for (j = 0; j < pages; j++, pbl_tbl++)
			*pbl_tbl = phys_buf_array[i].addr + j * PAGE_SHIFT;
	}
	mr->qplib_mr.flags = __from_ib_access_flags(mr_access_flags);
	rc = bnxt_qplib_reg_mr(&rdev->qplib_res, &mr->qplib_mr, pbl_tbl_orig,
			       num_pgs, false);
	kfree(pbl_tbl_orig);

	if (rc) {
		dev_err(rdev_to_dev(rdev), "Reg phys MR failed!");
		goto fail_mr;
	}
	atomic_inc(&rdev->mr_count);
	return &mr->ib_mr;

fail_mr:
	bnxt_qplib_free_mrw(&rdev->qplib_res, &mr->qplib_mr);
fail:
	kfree(mr);
	return ERR_PTR(rc);
}

int bnxt_re_rereg_phys_mr(struct ib_mr *ib_mr, int mr_rereg_mask,
			  struct ib_pd *ib_pd,
			  struct ib_phys_buf *phys_buf_array,
			  int num_phys_buf, int mr_access_flags,
			  u64 *iova_start)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_mr *mr = to_bnxt_re(ib_mr, struct bnxt_re_mr, ib_mr);
	struct bnxt_re_dev *rdev = mr->rdev;
	u64 *pbl_tbl, *pbl_tbl_orig = NULL;
	int i, j, num_pgs = 0, pages, rc;

	dev_dbg(rdev_to_dev(rdev), "Rereg phys MR");
	/* TODO: Must decipher what to modify based on the mr_rereg_mask */
	if (mr_rereg_mask & IB_MR_REREG_TRANS) {
		mr->qplib_mr.va = *iova_start;
		num_pgs = __get_phys_page_count(phys_buf_array, num_phys_buf);
		if (!num_pgs) {
			dev_err(rdev_to_dev(rdev),
				"Phys buf array is invalid!");
			rc = -EINVAL;
			goto fail;
		}

		pbl_tbl = kcalloc(num_pgs, sizeof(u64 *), GFP_KERNEL);
		if (!pbl_tbl) {
			dev_err(rdev_to_dev(rdev), "Allocate pbl_tbl failed!");
			rc = -EINVAL;
			goto fail;
		}
		mr->qplib_mr.total_size = 0;
		for (i = 0; i < num_phys_buf; i++) {
			pages = DIV_ROUND_UP(phys_buf_array[i].size, PAGE_SIZE);
			mr->qplib_mr.total_size += phys_buf_array[i].size;
			for (j = 0; j < pages; j++, pbl_tbl++)
				*pbl_tbl = phys_buf_array[i].addr +
					   j * PAGE_SIZE;
		}
	}
	if (mr_rereg_mask & IB_MR_REREG_PD)
		mr->qplib_mr.pd = &pd->qplib_pd;

	if (mr_rereg_mask & IB_MR_REREG_ACCESS)
		mr->qplib_mr.flags = __from_ib_access_flags(mr_access_flags);

	rc = bnxt_qplib_reg_mr(&rdev->qplib_res, &mr->qplib_mr, pbl_tbl_orig,
			       num_pgs, false);
	kfree(pbl_tbl_orig);

	if (rc) {
		dev_err(rdev_to_dev(rdev), "Rereg phys MR failed!");
		goto fail;
	}
	mr->ib_mr.rkey = mr->qplib_mr.rkey;
	dev_dbg(rdev_to_dev(rdev), "Alloc Phy MR lkey=0x%x rkey=0x%x",
		mr->ib_mr.lkey, mr->ib_mr.rkey);
	return 0;
fail:
	return rc;
}
#endif

#ifdef HAVE_IB_QUERY_MR
int bnxt_re_query_mr(struct ib_mr *ib_mr, struct ib_mr_attr *mr_attr)
{
	struct bnxt_re_mr *mr = to_bnxt_re(ib_mr, struct bnxt_re_mr, ib_mr);

	/* TODO: Transcribe the qplib_mr's attributes back to ib_mr_attr */
	mr_attr->pd = ib_mr->pd;
	mr_attr->device_virt_addr = mr->qplib_mr.va;
	mr_attr->size = mr->qplib_mr.total_size;
	mr_attr->mr_access_flags = __to_ib_access_flags(mr->qplib_mr.flags);
	mr_attr->lkey = mr->qplib_mr.lkey;
	mr_attr->rkey = mr->qplib_mr.rkey;
	return 0;
}
#endif

int bnxt_re_dereg_mr(struct ib_mr *ib_mr)
{
	struct bnxt_re_mr *mr = to_bnxt_re(ib_mr, struct bnxt_re_mr, ib_mr);
	struct bnxt_re_dev *rdev = mr->rdev;
	int rc = 0;

	rc = bnxt_qplib_free_mrw(&rdev->qplib_res, &mr->qplib_mr);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Dereg MR failed: %#x\n", rc);
		return rc;
	}

#ifdef HAVE_IB_ALLOC_MR
	if (mr->npages && mr->pages) {
		bnxt_qplib_free_fast_reg_page_list(&rdev->qplib_res,
						   &mr->qplib_frpl);
		kfree(mr->pages);
		mr->npages = 0;
		mr->pages = NULL;
	}
#endif

	if (!IS_ERR(mr->ib_umem) && mr->ib_umem)
		ib_umem_release(mr->ib_umem);

	kfree(mr);
	atomic_dec(&rdev->mr_count);
	return rc;
}

#ifdef HAVE_IB_CREATE_MR
/* Create/destroy a MR that may be used for signature handover operations */
int bnxt_re_destroy_mr(struct ib_mr *ib_mr)
{
	struct bnxt_re_mr *mr = to_bnxt_re(ib_mr, struct bnxt_re_mr, ib_mr);
	struct bnxt_re_dev *rdev = mr->rdev;

	dev_err(rdev_to_dev(rdev), "Destroy MR called!");
	return 0;
}

struct ib_mr *bnxt_re_create_mr(struct ib_pd *ib_pd,
				struct ib_mr_init_attr *mr_init_attr)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;

	dev_err(rdev_to_dev(rdev), "Create MR called!");
	return NULL;
}
#endif

#ifdef HAVE_IB_FAST_REG_MR
/* Fast Register Memory Regions */
struct ib_mr *bnxt_re_alloc_fast_reg_mr(struct ib_pd *ib_pd,
					int max_page_list_len)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_mr *mr;
	int rc;

	/* Qualify */
	if (max_page_list_len > MAX_PBL_LVL_1_PGS) {
		dev_err(rdev_to_dev(rdev),
			"Allocate Fast reg MR exceeded MAX!");
		return ERR_PTR(-ENOMEM);
	}
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		dev_err(rdev_to_dev(rdev),
			"Allocate Fast reg MR mem failed!");
		return ERR_PTR(-ENOMEM);
	}
	mr->rdev = rdev;
	mr->qplib_mr.pd = &pd->qplib_pd;
	mr->qplib_mr.flags = BNXT_QPLIB_FR_PMR;
	mr->qplib_mr.type = CMDQ_ALLOCATE_MRW_MRW_FLAGS_PMR;

	rc = bnxt_qplib_alloc_mrw(&rdev->qplib_res, &mr->qplib_mr);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Fast reg phys MR failed!");
		goto fail;
	}
	mr->ib_mr.lkey = mr->qplib_mr.lkey;
	mr->ib_mr.rkey = mr->ib_mr.lkey;

	atomic_inc(&rdev->mr_count);
	return &mr->ib_mr;

fail:
	kfree(mr);
	return ERR_PTR(rc);
}

struct ib_fast_reg_page_list *bnxt_re_alloc_fast_reg_page_list(
						struct ib_device *ibdev,
						int page_list_len)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct bnxt_re_frpl *frpl;
	int rc;

	frpl = kzalloc(sizeof(*frpl), GFP_KERNEL);
	if (!frpl) {
		dev_err(rdev_to_dev(rdev),
			"Allocate Fast reg page list struct failed!");
		return ERR_PTR(-ENOMEM);
	}
	frpl->rdev = rdev;
	frpl->page_list = kzalloc(sizeof(u64) * page_list_len, GFP_KERNEL);
	if (!frpl->page_list) {
		dev_err(rdev_to_dev(rdev),
			"Allocate Fast reg page list mem failed!");
		rc = -ENOMEM;
		goto fail;
	}
	rc = bnxt_qplib_alloc_fast_reg_page_list(&rdev->qplib_res,
						 &frpl->qplib_frpl,
						 page_list_len);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Allocate HW Fast reg page list failed!");
		goto fail_pl;
	}
	frpl->ib_frpl.page_list = frpl->page_list;

	return &frpl->ib_frpl;

fail_pl:
	kfree(frpl->page_list);
fail:
	kfree(frpl);
	return ERR_PTR(rc);
}

void bnxt_re_free_fast_reg_page_list(struct ib_fast_reg_page_list *ib_frpl)
{
	struct bnxt_re_frpl *frpl = to_bnxt_re(ib_frpl, struct bnxt_re_frpl,
					       ib_frpl);
	struct bnxt_re_dev *rdev = frpl->rdev;

	bnxt_qplib_free_fast_reg_page_list(&rdev->qplib_res,
					   &frpl->qplib_frpl);
	kfree(frpl->page_list);
	kfree(frpl);
}
#endif

#ifdef HAVE_IB_MAP_MR_SG
static int bnxt_re_set_page(struct ib_mr *ib_mr, u64 addr)
{
	struct bnxt_re_mr *mr = to_bnxt_re(ib_mr, struct bnxt_re_mr, ib_mr);

	if (unlikely(mr->npages == mr->qplib_frpl.max_pg_ptrs))
		return -ENOMEM;

	mr->pages[mr->npages++] = addr;
	dev_dbg(NULL, "%s: ibdev %p Set MR pages[%d] = 0x%llx",
		ROCE_DRV_MODULE_NAME, ib_mr->device, mr->npages - 1,
		mr->pages[mr->npages - 1]);
	return 0;
}

int bnxt_re_map_mr_sg(struct ib_mr *ib_mr, struct scatterlist *sg, int sg_nents
#ifdef HAVE_IB_MAP_MR_SG_PAGE_SIZE
		      , unsigned int *sg_offset
#else
#ifdef HAVE_IB_MAP_MR_SG_OFFSET
		      , unsigned int sg_offset
#endif
#endif
	)
{
	struct bnxt_re_mr *mr = to_bnxt_re(ib_mr, struct bnxt_re_mr, ib_mr);

	dev_dbg(NULL, "%s: ibdev %p Map MR sg nents = %d", ROCE_DRV_MODULE_NAME,
		ib_mr->device, sg_nents);
	mr->npages = 0;
	return ib_sg_to_pages(ib_mr, sg, sg_nents,
#ifdef HAVE_IB_MAP_MR_SG_OFFSET
			      sg_offset,
#endif
			      bnxt_re_set_page);
}
#endif

#ifdef HAVE_IB_ALLOC_MR
struct ib_mr *bnxt_re_alloc_mr(struct ib_pd *ib_pd, enum ib_mr_type type,
			       u32 max_num_sg)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_mr *mr;
	int rc;

	dev_dbg(rdev_to_dev(rdev), "Alloc MR");
	if (type != IB_MR_TYPE_MEM_REG) {
		dev_dbg(rdev_to_dev(rdev), "MR type 0x%x not supported", type);
		return ERR_PTR(-EINVAL);
	}
	if (max_num_sg > MAX_PBL_LVL_1_PGS) {
		dev_dbg(rdev_to_dev(rdev), "Max SG exceeded");
		return ERR_PTR(-EINVAL);
	}
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		dev_err(rdev_to_dev(rdev), "Allocate MR mem failed!");
		return ERR_PTR(-ENOMEM);
	}
	mr->rdev = rdev;
	mr->qplib_mr.pd = &pd->qplib_pd;
	mr->qplib_mr.flags = BNXT_QPLIB_FR_PMR;
	mr->qplib_mr.type = CMDQ_ALLOCATE_MRW_MRW_FLAGS_PMR;

	rc = bnxt_qplib_alloc_mrw(&rdev->qplib_res, &mr->qplib_mr);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Allocate MR failed!");
		goto fail;
	}
	mr->ib_mr.lkey = mr->qplib_mr.lkey;
	mr->ib_mr.rkey = mr->ib_mr.lkey;

	mr->pages = kzalloc(sizeof(u64) * max_num_sg, GFP_KERNEL);
	if (!mr->pages) {
		dev_err(rdev_to_dev(rdev),
			"Allocate MR page list mem failed!");
		rc = -ENOMEM;
		goto fail;
	}
	rc = bnxt_qplib_alloc_fast_reg_page_list(&rdev->qplib_res,
						 &mr->qplib_frpl, max_num_sg);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Allocate HW Fast reg page list failed!");
		goto fail_mr;
	}
	dev_dbg(rdev_to_dev(rdev), "Alloc MR pages = 0x%p", mr->pages);

	atomic_inc(&rdev->mr_count);
	return &mr->ib_mr;

fail_mr:
	bnxt_qplib_free_mrw(&rdev->qplib_res, &mr->qplib_mr);
fail:
	if (mr->pages)
		kfree(mr->pages);
	if (mr)
		kfree(mr);

	return ERR_PTR(rc);
}
#endif

/* Memory Windows */
#ifdef HAVE_IB_MW_TYPE
struct ib_mw *bnxt_re_alloc_mw(struct ib_pd *ib_pd, enum ib_mw_type type
#ifdef HAVE_ALLOW_MW_WITH_UDATA
			       , struct ib_udata *udata
#endif
			       )
#else
struct ib_mw *bnxt_re_alloc_mw(struct ib_pd *ib_pd)
#endif
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_mw *mw;
	int rc;

	mw = kzalloc(sizeof(*mw), GFP_KERNEL);
	if (!mw) {
		dev_err(rdev_to_dev(rdev), "Allocate MW failed!");
		return ERR_PTR (-ENOMEM);
	}
	mw->rdev = rdev;
	mw->qplib_mw.pd = &pd->qplib_pd;

#ifdef HAVE_IB_MW_TYPE
	mw->qplib_mw.type = (type == IB_MW_TYPE_1 ?
			       CMDQ_ALLOCATE_MRW_MRW_FLAGS_MW_TYPE1 :
			       CMDQ_ALLOCATE_MRW_MRW_FLAGS_MW_TYPE2B);
#else
	mw->qplib_mw.type = CMDQ_ALLOCATE_MRW_MRW_FLAGS_MW_TYPE1;
#endif
	rc = bnxt_qplib_alloc_mrw(&rdev->qplib_res, &mw->qplib_mw);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Allocate MW failed!");
		goto fail;
	}
	mw->ib_mw.rkey = mw->qplib_mw.rkey;

	atomic_inc(&rdev->mw_count);
	return &mw->ib_mw;

fail:
	kfree(mw);
	return ERR_PTR(rc);
}

#ifdef HAVE_IB_BIND_MW
/* bind_mw is only for Type 1 MW binding */
int bnxt_re_bind_mw(struct ib_qp *ib_qp, struct ib_mw *ib_mw,
		    struct ib_mw_bind *mw_bind)
{
	struct bnxt_re_qp *qp = to_bnxt_re(ib_qp, struct bnxt_re_qp, ib_qp);
	struct bnxt_qplib_swqe wqe;
	int rc = 0;

	memset(&wqe, 0, sizeof(wqe));
	wqe.type = BNXT_QPLIB_SWQE_TYPE_BIND_MW;
	wqe.wr_id = mw_bind->wr_id;
	if (mw_bind->send_flags & IB_SEND_SIGNALED)
		wqe.flags |= BNXT_QPLIB_SWQE_FLAGS_SIGNAL_COMP;
	if (mw_bind->send_flags & IB_SEND_FENCE)
		wqe.flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
	wqe.bind.zero_based = false;
	wqe.bind.parent_l_key = mw_bind->bind_info.mr->lkey;
	wqe.bind.r_key = ib_inc_rkey(ib_mw->rkey);
	wqe.bind.va = mw_bind->bind_info.addr;
	wqe.bind.length = mw_bind->bind_info.length;
	wqe.bind.access_cntl = __from_ib_access_flags(
					mw_bind->bind_info.mw_access_flags);
	wqe.bind.mw_type = ib_mw->type == IB_MW_TYPE_1 ? SQ_BIND_MW_TYPE_TYPE1 :
							 SQ_BIND_MW_TYPE_TYPE2;

	rc = bnxt_qplib_post_send(&qp->qplib_qp, &wqe);
	if (rc) {
		dev_err(rdev_to_dev(qp->rdev), "Bind MW failed");
		goto exit;
	}
	ib_mw->rkey = wqe.bind.r_key;
	bnxt_qplib_post_send_db(&qp->qplib_qp);
exit:
	return rc;
}
#endif

int bnxt_re_dealloc_mw(struct ib_mw *ib_mw)
{
	struct bnxt_re_mw *mw = to_bnxt_re(ib_mw, struct bnxt_re_mw, ib_mw);
	struct bnxt_re_dev *rdev = mw->rdev;
	int rc;

	rc = bnxt_qplib_free_mrw(&rdev->qplib_res, &mw->qplib_mw);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Free MW failed: %#x\n", rc);
		return rc;
	}

	kfree(mw);
	atomic_dec(&rdev->mw_count);
	return rc;
}

#ifdef USE_IB_FMR
/* Fast Memory Regions */
struct ib_fmr *bnxt_re_alloc_fmr(struct ib_pd *ib_pd, int mr_access_flags,
				 struct ib_fmr_attr *fmr_attr)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_fmr *fmr;
	int rc;

	if (fmr_attr->max_pages > MAX_PBL_LVL_2_PGS ||
	    fmr_attr->max_maps > rdev->dev_attr.max_map_per_fmr) {
		dev_err(rdev_to_dev(rdev), "Allocate FMR exceeded MAX!");
		return ERR_PTR (-ENOMEM);
	}
	fmr = kzalloc(sizeof(*fmr), GFP_KERNEL);
	if (!fmr) {
		dev_err(rdev_to_dev(rdev), "Allocate FMR memory failed!");
		return ERR_PTR (-ENOMEM);
	}
	/* TODO: Ignore fmr_attr->page_shift */
	fmr->rdev = rdev;
	fmr->qplib_fmr.pd = &pd->qplib_pd;
	fmr->qplib_fmr.type = CMDQ_ALLOCATE_MRW_MRW_FLAGS_PMR;

	rc = bnxt_qplib_alloc_mrw(&rdev->qplib_res, &fmr->qplib_fmr);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Allocate FMR failed!");
		goto fail;
	}
	fmr->qplib_fmr.flags = __from_ib_access_flags(mr_access_flags);
	fmr->ib_fmr.lkey = fmr->qplib_fmr.lkey;
//	if (mr_access_flags & (IB_ACCESS_REMOTE_WRITE | IB_ACCESS_REMOTE_READ |
//			       IB_ACCESS_REMOTE_ATOMIC))
		fmr->ib_fmr.rkey = fmr->ib_fmr.lkey;

	atomic_inc(&rdev->mr_count);
	return &fmr->ib_fmr;

fail:
	kfree(fmr);
	return ERR_PTR(rc);
}

int bnxt_re_map_phys_fmr(struct ib_fmr *ib_fmr, u64 *page_list, int list_len,
			 u64 iova)
{
	struct bnxt_re_fmr *fmr = to_bnxt_re(ib_fmr, struct bnxt_re_fmr, ib_fmr);
	struct bnxt_re_dev *rdev = fmr->rdev;
	int rc;

	fmr->qplib_fmr.va = iova;
	fmr->qplib_fmr.total_size = list_len * PAGE_SIZE;

	rc = bnxt_qplib_reg_mr(&rdev->qplib_res, &fmr->qplib_fmr, page_list,
			       list_len, true);
	if (rc)
		dev_err(rdev_to_dev(rdev), "Map FMR failed for lkey = 0x%x!",
			fmr->ib_fmr.lkey);
	return rc;
}

int bnxt_re_unmap_fmr(struct list_head *fmr_list)
{
	struct bnxt_re_dev *rdev;
	struct bnxt_re_fmr *fmr;
	struct ib_fmr *ib_fmr;
	int rc;

	/* Validate each FMRs inside the fmr_list */
	list_for_each_entry(ib_fmr, fmr_list, list) {
		fmr = to_bnxt_re(ib_fmr, struct bnxt_re_fmr, ib_fmr);
		rdev = fmr->rdev;

		if (rdev) {
			rc = bnxt_qplib_dereg_mrw(&rdev->qplib_res,
						  &fmr->qplib_fmr, true);
			if (rc) {
				dev_dbg(rdev_to_dev(rdev), "Unmap MR failed!");
				goto fail;
			}
		}
	}
	return 0;
fail:
	return rc;
}

int bnxt_re_dealloc_fmr(struct ib_fmr *ib_fmr)
{
	struct bnxt_re_fmr *fmr = to_bnxt_re(ib_fmr, struct bnxt_re_fmr,
					     ib_fmr);
	struct bnxt_re_dev *rdev = fmr->rdev;
	int rc;

	rc = bnxt_qplib_free_mrw(&rdev->qplib_res, &fmr->qplib_fmr);
	if (rc)
		dev_err(rdev_to_dev(rdev), "Free FMR failed!");

	kfree(fmr);
	atomic_dec(&rdev->mr_count);
	return rc;
}
#endif

/* Flows */
#ifdef HAVE_IB_FLOW
struct ib_flow *bnxt_re_create_flow(struct ib_qp *qp,
				    struct ib_flow_attr *flow_attr,
				    int domain)
{

	return NULL;
}

int bnxt_re_destroy_flow(struct ib_flow *flow_id)
{

	return 0;
}
#endif

/* uverbs */
struct ib_mr *bnxt_re_reg_user_mr(struct ib_pd *ib_pd, u64 start, u64 length,
				  u64 virt_addr, int mr_access_flags,
				  struct ib_udata *udata)
{
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = pd->rdev;
	struct bnxt_re_mr *mr;
	struct ib_umem *umem;
	u64 *pbl_tbl, *pbl_tbl_orig;
	int i, umem_pgs, pages, page_shift, rc;
#ifdef HAVE_IB_UMEM_SG_TABLE
	struct scatterlist *sg;
	int entry;
#else
	struct ib_umem_chunk *chunk;
	int j;
#endif

	dev_dbg(rdev_to_dev(rdev), "Reg user MR");
	if (length > BNXT_RE_MAX_MR_SIZE) {
		dev_err(rdev_to_dev(rdev), "Requested MR Size: %lld "
			"> Max supported: %d\n", length, BNXT_RE_MAX_MR_SIZE);
		return ERR_PTR(-ENOMEM);
	}
	mr = kzalloc(sizeof(*mr), GFP_KERNEL);
	if (!mr) {
		dev_err(rdev_to_dev(rdev), "Allocate MR failed!");
		return ERR_PTR (-ENOMEM);
	}
	mr->rdev = rdev;
	mr->qplib_mr.pd = &pd->qplib_pd;
	mr->qplib_mr.flags = __from_ib_access_flags(mr_access_flags);
	mr->qplib_mr.type = CMDQ_ALLOCATE_MRW_MRW_FLAGS_MR;

	rc = bnxt_qplib_alloc_mrw(&rdev->qplib_res, &mr->qplib_mr);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Alloc MR failed!");
		goto fail;
	}
	/* The fixed portion of the rkey is the same as the lkey */
	mr->ib_mr.rkey = mr->qplib_mr.rkey;

	umem = ib_umem_get(ib_pd->uobject->context, start, length,
			   mr_access_flags, 0);
	if (IS_ERR(umem)) {
		dev_err(rdev_to_dev(rdev), "Get umem failed!");
		rc = -EFAULT;
		goto fail;
	}
	mr->ib_umem = umem;

	mr->qplib_mr.va = virt_addr;
	umem_pgs = ib_umem_page_count(umem);
	if (!umem_pgs) {
		dev_err(rdev_to_dev(rdev), "umem is invalid!");
		rc = -EINVAL;
		goto fail_free_mr;
	}
	mr->qplib_mr.total_size = length;

	pbl_tbl = kcalloc(umem_pgs, sizeof(u64 *), GFP_KERNEL);
	if (!pbl_tbl) {
		dev_err(rdev_to_dev(rdev), "Allocate pbl_tbl failed!");
		rc = -EINVAL;
		goto fail_free_mr;
	}
	pbl_tbl_orig = pbl_tbl;

	page_shift = ilog2(umem->page_size);
	if (umem->hugetlb) {
		/* TODO: Add hugetlb support */
		dev_err(rdev_to_dev(rdev), "umem hugetlb not supported!");
		rc = -EFAULT;
		kfree(pbl_tbl);
		goto fail;
	}
	if (umem->page_size != PAGE_SIZE) {
		/* TODO: Add other page size support for umem */
		dev_err(rdev_to_dev(rdev), "umem page size unsupported!");
		rc = -EFAULT;
		kfree(pbl_tbl);
		goto fail;
	}
	/* Map umem buf ptrs to the PBL */
#ifdef HAVE_IB_UMEM_SG_TABLE
	for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
		pages = sg_dma_len(sg) >> page_shift;
		for (i = 0; i < pages; i++, pbl_tbl++)
			*pbl_tbl = sg_dma_address(sg) + (i << page_shift);
	}
#else
	list_for_each_entry(chunk, &umem->chunk_list, list) {
		for (i = 0; i < chunk->nmap; ++i) {
			pages = sg_dma_len(&chunk->page_list[i]) >> page_shift;
			for (j = 0; j < pages; ++j, pbl_tbl++)
				*pbl_tbl = sg_dma_address(&chunk->page_list[i])
							  + (i << page_shift);
		}
	}
#endif
	rc = bnxt_qplib_reg_mr(&rdev->qplib_res, &mr->qplib_mr, pbl_tbl_orig,
			       umem_pgs, false);
	kfree(pbl_tbl_orig);

	if (rc) {
		dev_err(rdev_to_dev(rdev), "Reg user MR failed!");
		goto fail;
	}

	mr->ib_mr.lkey = mr->ib_mr.rkey = mr->qplib_mr.lkey;
	atomic_inc(&rdev->mr_count);

	return &mr->ib_mr;

fail_free_mr:
	bnxt_qplib_free_mrw(&rdev->qplib_res, &mr->qplib_mr);
fail:
	kfree(mr);
	return ERR_PTR(rc);
}

int bnxt_re_rereg_user_mr(struct ib_mr *ib_mr, int flags, u64 start, u64 length,
			  u64 virt_addr, int mr_access_flags,
			  struct ib_pd *ib_pd, struct ib_udata *udata)
{
	struct bnxt_re_mr *mr = to_bnxt_re(ib_mr, struct bnxt_re_mr, ib_mr);
	struct bnxt_re_pd *pd = to_bnxt_re(ib_pd, struct bnxt_re_pd, ib_pd);
	struct bnxt_re_dev *rdev = mr->rdev;
	struct ib_umem *umem;
	u64 *pbl_tbl, *pbl_tbl_orig = NULL;
	int i, umem_pgs = 0, pages, page_shift, rc;
#ifdef HAVE_IB_UMEM_SG_TABLE
	struct scatterlist *sg;
	int entry;
#else
	struct ib_umem_chunk *chunk;
	int j;
#endif

	/* TODO: Must decipher what to modify based on the flags */
	if (flags & IB_MR_REREG_TRANS) {
		umem = ib_umem_get(ib_pd->uobject->context, start, length,
				   mr_access_flags, 0);
		if (IS_ERR(umem)) {
			dev_err(rdev_to_dev(rdev), "Get umem failed!");
			rc = -EFAULT;
			goto fail;
		}
		mr->ib_umem = umem;

		mr->qplib_mr.va = virt_addr;
		umem_pgs = ib_umem_page_count(umem);
		if (!umem_pgs) {
			dev_err(rdev_to_dev(rdev), "umem is invalid!");
			rc = -EINVAL;
			goto fail;
		}
		mr->qplib_mr.total_size = length;

		pbl_tbl = kcalloc(umem_pgs, sizeof(u64 *), GFP_KERNEL);
		if (!pbl_tbl) {
			dev_err(rdev_to_dev(rdev), "Allocate pbl_tbl failed!");
			rc = -EINVAL;
			goto fail;
		}
		pbl_tbl_orig = pbl_tbl;

		page_shift = ilog2(umem->page_size);
		if (umem->hugetlb) {
			/* TODO: Add hugetlb support */
			dev_err(rdev_to_dev(rdev),
				"umem hugetlb not supported!");
			kfree(pbl_tbl);
			rc = -EFAULT;
			goto fail;
		}
		/* TODO: Add other page size support for umem */
		if (umem->page_size != PAGE_SIZE) {
			dev_err(rdev_to_dev(rdev),
				"umem page size unsupported!");
			kfree(pbl_tbl);
			rc = -EFAULT;
			goto fail;
		}
		/* Map umem buf ptrs to the PBL */
#ifdef HAVE_IB_UMEM_SG_TABLE
		for_each_sg(umem->sg_head.sgl, sg, umem->nmap, entry) {
			pages = sg_dma_len(sg) >> page_shift;
			for (i = 0; i < pages; i++, pbl_tbl++)
				*pbl_tbl = sg_dma_address(sg) +
						(i << page_shift);
		}
#else
		list_for_each_entry(chunk, &umem->chunk_list, list) {
			for (i = 0; i < chunk->nmap; ++i) {
				pages = sg_dma_len(&chunk->page_list[i]) >>
						   page_shift;
				for (j = 0; j < pages; ++j, pbl_tbl++)
					*pbl_tbl = sg_dma_address(
							&chunk->page_list[i])
						   + (i << page_shift);
			}
		}
#endif
	}
	if (flags & IB_MR_REREG_PD)
		mr->qplib_mr.pd = &pd->qplib_pd;

	if (flags & IB_MR_REREG_ACCESS)
		mr->qplib_mr.flags = __from_ib_access_flags(mr_access_flags);

	rc = bnxt_qplib_reg_mr(&rdev->qplib_res, &mr->qplib_mr, pbl_tbl_orig,
			       umem_pgs, false);
	kfree(pbl_tbl_orig);

	if (rc) {
		dev_err(rdev_to_dev(rdev), "Rereg user MR failed!");
		goto fail;
	}
	mr->ib_mr.rkey = mr->qplib_mr.rkey;
	return 0;
fail:
	return rc;
}

struct ib_ucontext *bnxt_re_alloc_ucontext(struct ib_device *ibdev,
					   struct ib_udata *udata)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(ibdev, ibdev);
	struct bnxt_re_uctx_resp resp;
	struct bnxt_re_ucontext *uctx;
	struct bnxt_qplib_dev_attr *dev_attr = &rdev->dev_attr;
	int rc;

	dev_dbg(rdev_to_dev(rdev), "ABI version requested %d",
		ibdev->uverbs_abi_ver);
	if (ibdev->uverbs_abi_ver != BNXT_RE_ABI_VERSION) {
		dev_dbg(rdev_to_dev(rdev), " is different from the device %d ",
			BNXT_RE_ABI_VERSION);
		return ERR_PTR(-EPERM);
	}

	uctx = kzalloc(sizeof(*uctx), GFP_KERNEL);
	if (!uctx) {
		dev_err(rdev_to_dev(rdev), "ucontext alloc failed!");
		return ERR_PTR(-ENOMEM);
	}
	uctx->rdev = rdev;

	uctx->shpg = (void *)__get_free_page(GFP_KERNEL);
	if (!uctx->shpg) {
		dev_err(rdev_to_dev(rdev), "shared memory allocation failed!");
		rc = -ENOMEM;
		goto fail;
	}
	spin_lock_init(&uctx->sh_lock);

	resp.dev_id = rdev->en_dev->pdev->devfn; /*Temp, Use idr_alloc instead*/
	resp.max_qp = rdev->qplib_ctx.qpc_count;
	resp.pg_size = PAGE_SIZE;
	resp.cqe_sz = sizeof(struct cq_base);
	resp.max_cqd = dev_attr->max_cq_wqes;

	rc = ib_copy_to_udata(udata, &resp, sizeof(resp));
	if (rc) {
		dev_err(rdev_to_dev(rdev), "ucontext copy failed!");
		rc = -EFAULT;
		goto cfail;
	}

	return &uctx->ib_uctx;
cfail:
	free_page((u64)uctx->shpg);
	uctx->shpg = NULL;
fail:
	kfree(uctx);
	return ERR_PTR(rc);
}

int bnxt_re_dealloc_ucontext(struct ib_ucontext *ib_uctx)
{
	struct bnxt_re_ucontext *uctx = to_bnxt_re(ib_uctx,
						   struct bnxt_re_ucontext,
						   ib_uctx);
	struct bnxt_re_dev *rdev = uctx->rdev;
	int rc = 0;

	if (uctx->shpg)
		free_page((u64)uctx->shpg);

	if (uctx->dpi.dbr) {
		/* Free DPI only if this is the first PD allocated by the
		 * application and mark the context dpi as NULL
		 */
		rc = bnxt_qplib_dealloc_dpi(&rdev->qplib_res,
					    &rdev->qplib_res.dpi_tbl,
					    &uctx->dpi);
		if (rc)
			dev_err(rdev_to_dev(rdev), "Deallocte HW DPI failed!");
			/* Don't fail, continue*/
		uctx->dpi.dbr = 0;
	}

	kfree(uctx);
	return 0;
}

/* Helper function to mmap the virtual memory from user app */
int bnxt_re_mmap(struct ib_ucontext *ib_uctx, struct vm_area_struct *vma)
{
	struct bnxt_re_ucontext *uctx = to_bnxt_re(ib_uctx,
						   struct bnxt_re_ucontext,
						   ib_uctx);
	struct bnxt_re_dev *rdev = uctx->rdev;
	u64 pfn;

	if (vma->vm_end - vma->vm_start != PAGE_SIZE)
		return -EINVAL;

	if (vma->vm_pgoff) {
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
		if (io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
					PAGE_SIZE, vma->vm_page_prot)) {
			dev_err(rdev_to_dev(rdev), "DPI mapping failed!");
			return -EAGAIN;
		}
	} else {
		pfn = virt_to_phys(uctx->shpg) >> PAGE_SHIFT;
		if (remap_pfn_range(vma, vma->vm_start,
				    pfn, PAGE_SIZE, vma->vm_page_prot)) {
			dev_err(rdev_to_dev(rdev),
				"Shared page mapping failed!");
			return -EAGAIN;
		}
	}

	return 0;
}

#ifdef HAVE_IB_MAD_HDR
int bnxt_re_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
			const struct ib_wc *wc, const struct ib_grh *grh,
			const struct ib_mad_hdr *in_mad, size_t in_mad_size,
			struct ib_mad_hdr *out_mad, size_t *out_mad_size,
			u16 *out_mad_pkey_index)
#else
int bnxt_re_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
			struct ib_wc *wc, struct ib_grh *grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad)
#endif
{
#ifdef USE_PROCESS_MAD
	int i;
	u8 *ptr;

	dev_dbg(NULL, "%s: ibdev %p mad_flags=0x%x port_num=0x%x wc=%p grh=%p",
		ROCE_DRV_MODULE_NAME, ibdev, mad_flags, port_num, wc, grh);
	ptr = (u8 *)wc;
	dev_dbg(NULL, "%s: ibdev %p WC: ", ROCE_DRV_MODULE_NAME, ibdev);
	for (i = 0; i < sizeof(*wc); i+=8)
		dev_dbg(NULL,
			"%s: 0x%02x %02x %02x %02x %02x %02x %02x %02x\n",
			ROCE_DRV_MODULE_NAME, ptr[i], ptr[i + 1], ptr[i + 2],				ptr[i + 3], ptr[i + 4], ptr[i + 5], ptr[i + 6],
			ptr[i + 7]);

	ptr = (u8 *)grh;
	dev_dbg(NULL, "%s: ibdev %p GRH: ", ROCE_DRV_MODULE_NAME, ibdev);
	for (i = 0; i < sizeof(*grh); i+=8)
		dev_dbg(NULL,
			"%s: 0x%02x %02x %02x %02x %02x %02x %02x %02x\n",
			ROCE_DRV_MODULE_NAME, ptr[i], ptr[i + 1], ptr[i + 2],
			ptr[i + 3], ptr[i + 4], ptr[i + 5], ptr[i + 6],
			ptr[i + 7]);

	ptr = (u8 *)in_mad;
	dev_dbg(NULL, "%s: ibdev %p IN_MAD: ", ROCE_DRV_MODULE_NAME, ibdev);
	for (i = 0; i < sizeof(*in_mad); i+=8)
		dev_dbg(NULL,
			"%s: 0x%02x %02x %02x %02x %02x %02x %02x %02x\n",
			ROCE_DRV_MODULE_NAME, ptr[i], ptr[i + 1], ptr[i + 2],
			ptr[i + 3], ptr[i + 4], ptr[i + 5], ptr[i + 6],
			ptr[i + 7]);
#endif
	return IB_MAD_RESULT_SUCCESS;
}

#ifdef HAVE_IB_DRAIN
void bnxt_re_drain_rq(struct ib_qp *ib_qp)
{
	dev_dbg(NULL, "%s: ibdev %p Drain RQ request", ROCE_DRV_MODULE_NAME,
		ib_qp->device);

}

void bnxt_re_drain_sq(struct ib_qp *ib_qp)
{
	dev_dbg(NULL, "%s: ibdev %p Drain SQ request", ROCE_DRV_MODULE_NAME,
		ib_qp->device);

}
#endif
