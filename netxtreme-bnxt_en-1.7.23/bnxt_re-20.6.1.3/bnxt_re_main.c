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
 * Description: Main component of the bnxt_re driver
 */

#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/moduleparam.h>
#include <linux/netdevice.h>
#include <linux/inetdevice.h>
#include <linux/dcbnl.h>
#include <linux/ethtool.h>
#include <linux/mutex.h>
#include <linux/list.h>
#include <linux/rculist.h>
#include <linux/spinlock.h>
#include <linux/pci.h>
#include <net/ipv6.h>
#include <net/addrconf.h>

#if 0
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/errno.h>
#include <linux/rtnetlink.h>
#include <linux/if_vlan.h>

#endif
#include <rdma/ib_verbs.h>
#include <rdma/ib_user_verbs.h>
#include <rdma/ib_umem.h>
#include <rdma/ib_addr.h>

#include "bnxt_re_compat.h"
#include "bnxt_ulp.h"
#include "roce_hsi.h"
#include "bnxt_qplib_res.h"
#include "bnxt_qplib_sp.h"
#include "bnxt_qplib_fp.h"
#include "bnxt_qplib_rcfw.h"

#include "bnxt_re.h"

#ifdef ENABLE_DEBUGFS
#include "bnxt_re_debugfs.h"
#endif

#include "bnxt_re_ib_verbs.h"
#include "bnxt_re_uverbs_abi.h"
/* TODO: Temp bnxt.h include */
#include "bnxt.h"

static char version[] =
		"Broadcom NetXtreme-C/E RoCE Driver " ROCE_DRV_MODULE_NAME \
		" v" ROCE_DRV_MODULE_VERSION " (" ROCE_DRV_MODULE_RELDATE ")\n";

#define BNXT_RE_DESC	"Broadcom NetXtreme RoCE"

MODULE_AUTHOR("Eddie Wai <eddie.wai@broadcom.com>");
MODULE_DESCRIPTION(BNXT_RE_DESC " Driver");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_VERSION(ROCE_DRV_MODULE_VERSION);

#ifdef ENABLE_ROCE_TOS
unsigned int tos_ecn = 0;
module_param(tos_ecn, uint, 0);
MODULE_PARM_DESC(tos_ecn, " Enable ECN (0 = off, 1 or 2 = enable)");

unsigned int tos_dscp = 0xFF;
module_param(tos_dscp, uint, 0);
MODULE_PARM_DESC(tos_dscp, " DSCP config value (0-0x3F)");
#endif

unsigned int restrict_mrs = 0;
module_param(restrict_mrs, uint, 0);
MODULE_PARM_DESC(restrict_mrs, " Restrict the no. of MRs 0 = 256K , 1 = 64K");

/* globals */
struct list_head bnxt_re_dev_list = LIST_HEAD_INIT(bnxt_re_dev_list);
u32 adapter_count;
DEFINE_MUTEX(bnxt_re_dev_lock);

static void bnxt_re_task(struct work_struct *work_task);
static struct workqueue_struct *bnxt_re_wq;

const char *bnxt_re_event2str[] = {"NONE", "UP", "DOWN", "REBOOT",
				   "CHANGE", "REGISTER", "UNREGISTER",
				   "CHANGEMTU", "CHANGEADDR", "GOING_DOWN",
				   "CHANGENAME", "FEAT_CHANGE",
				   "BONDING_FAILOVER", "PRE_UP",
				   "PRE_TYPE_CHANGE", "POST_TYPE_CHANGE",
				   "POST_INIT", "UNREGISTER_FINAL", "RELEASE",
				   "NOTIFY_PEERS", "JOIN", "CHANGEUPPER",
				   "RESEND_IGMP", "PRECHANGEMTU",
				   "CHANGEINFODATA", "BONDING_INFO",
				   "UNKNOWN"};

#define NETDEV_UNKNOWN	25

/* SR-IOV helper functions */

static void bnxt_re_get_sriov_func_type(struct bnxt_re_dev *rdev)
{
	struct bnxt *bp;

	bp = netdev_priv(rdev->netdev);
	if (BNXT_VF(bp))
		rdev->is_virtfn = 1;
}

static void bnxt_re_set_resource_limits(struct bnxt_re_dev *rdev)
{
	u32 vf_qps = 0, vf_srqs = 0, vf_cqs = 0, vf_mrws = 0, vf_gids = 0;
	u32 i;

	rdev->qplib_ctx.qpc_count = BNXT_RE_MAX_QPC_COUNT;
	if (restrict_mrs)
		rdev->qplib_ctx.mrw_count = BNXT_RE_MAX_MRW_COUNT_64K;
	else
		rdev->qplib_ctx.mrw_count = BNXT_RE_MAX_MRW_COUNT_256K;

	rdev->qplib_ctx.srqc_count = BNXT_RE_MAX_SRQC_COUNT;
	rdev->qplib_ctx.cq_count = BNXT_RE_MAX_CQ_COUNT;
	for (i = 0; i < MAX_TQM_ALLOC_REQ; i++)
		rdev->qplib_ctx.tqm_count[i] =
		rdev->dev_attr.tqm_alloc_reqs[i];

	if (rdev->num_vfs) {
		vf_qps = (rdev->qplib_ctx.qpc_count - BNXT_RE_RES_RESVD_FOR_PF) /
					rdev->num_vfs;
		vf_srqs = (rdev->qplib_ctx.srqc_count - BNXT_RE_RES_RESVD_FOR_PF) /
			   rdev->num_vfs;
		vf_cqs = (rdev->qplib_ctx.cq_count - BNXT_RE_RES_RESVD_FOR_PF) /
			  rdev->num_vfs;
		vf_mrws = (rdev->qplib_ctx.mrw_count - BNXT_RE_RES_RESVD_FOR_PF) /
			   rdev->num_vfs;

		vf_gids = BNXT_RE_MAX_GID_PER_VF;
	}
	rdev->qplib_ctx.vf_res.max_mrw_per_vf = vf_mrws;
	rdev->qplib_ctx.vf_res.max_gid_per_vf = vf_gids;
	rdev->qplib_ctx.vf_res.max_qp_per_vf = vf_qps;
	rdev->qplib_ctx.vf_res.max_srq_per_vf = vf_srqs;
	rdev->qplib_ctx.vf_res.max_cq_per_vf = vf_cqs;
}


void bnxt_re_stop(void *p)
{
	struct bnxt_re_dev *rdev = p;

	if (!rdev)
		return;

	dev_info(rdev_to_dev(rdev), "%s: L2 driver detected an error."
		 "Dispatching FATAL event to inform the stack\n", __func__);
	bnxt_re_dev_stop(rdev);
}

/*ulp_start not implemented currently as ulp_stop is called only in case of
 * L2 detecting an error(PCIe or Tx Timeout) where we only inform the stack.
 * When L2 successfully recovers, we get NETDEV_CHANGE event from the netdev
 * notifier chain where we inform the stack that the port is back up again
 */
void bnxt_re_start(void *p)
{
}

void bnxt_re_sriov_config(void *p, int num_vfs)
{
	struct bnxt_re_dev *rdev = p;

        if (!rdev)
                return;

	rdev->num_vfs = num_vfs;
	bnxt_re_set_resource_limits(rdev);
	bnxt_qplib_set_func_resources(&rdev->qplib_res, &rdev->rcfw,
				      &rdev->qplib_ctx);
}

struct bnxt_ulp_ops bnxt_re_ulp_ops = {
	.ulp_async_notifier = NULL,
	.ulp_stop = bnxt_re_stop,
	.ulp_start = bnxt_re_start,
	.ulp_sriov_config = bnxt_re_sriov_config
};

static inline const char *bnxt_re_netevent(unsigned long event)
{
	if (event >= ARRAY_SIZE(bnxt_re_event2str))
		event = NETDEV_UNKNOWN;
	return bnxt_re_event2str[(event)];
}

/* The rdev ref_count is to protect immature removal of the device */
static inline void bnxt_re_hold(struct bnxt_re_dev *rdev)
{
	atomic_inc(&rdev->ref_count);
	dev_dbg(rdev_to_dev(rdev),
		"Hold ref_count = 0x%x", atomic_read(&rdev->ref_count));
}

static inline void bnxt_re_put(struct bnxt_re_dev *rdev)
{
	atomic_dec(&rdev->ref_count);
	dev_dbg(rdev_to_dev(rdev),
		"Put ref_count = 0x%x", atomic_read(&rdev->ref_count));
}

/* RoCE -> Net driver */

/* Driver registration routines used to let the networking driver (bnxt_en)
 * to know that the RoCE driver is now installed */
static int bnxt_re_unregister_netdev(struct bnxt_re_dev *rdev, bool lock_wait)
{
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	int rc;
	bool do_unlock = false;

	if (!rdev) {
		dev_err(NULL, "rdev %p Device is invalid", rdev);
		return -EINVAL;
	}
	if (!rtnl_is_locked() || lock_wait == true) {
		rtnl_lock();
		do_unlock = true;
	}

	rc = en_dev->en_ops->bnxt_unregister_device(rdev->en_dev,
						    BNXT_ROCE_ULP);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "netdev %p unregister failed!",
			rdev->netdev);
	}
	if (do_unlock == true)
		rtnl_unlock();
	return 0;
}

static int bnxt_re_register_netdev(struct bnxt_re_dev *rdev)
{
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	int rc = 0;

	if (!rdev) {
		dev_err(NULL, "%s: rdev %p Device is invalid",
			ROCE_DRV_MODULE_NAME, rdev);
		return -EINVAL;
	}
	rtnl_lock();
	rc = en_dev->en_ops->bnxt_register_device(en_dev, BNXT_ROCE_ULP,
						  &bnxt_re_ulp_ops, rdev);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "netdev %p register failed!",
			rdev->netdev);
		goto done;
	}
	dev_dbg(rdev_to_dev(rdev), "REGISTER NETDEV %p hold!", rdev->netdev);
done:
	rtnl_unlock();
	return rc;
}

static int bnxt_re_free_msix(struct bnxt_re_dev *rdev, bool lock_wait)
{
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	int rc;
	bool do_unlock = false;

	if (!rdev) {
		dev_err(NULL, "rdev %p Device is invalid", rdev);
		return -EINVAL;
	}
	if (!rtnl_is_locked() || lock_wait == true) {
		rtnl_lock();
		do_unlock = true;
	}

	rc = en_dev->en_ops->bnxt_free_msix(rdev->en_dev, BNXT_ROCE_ULP);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "netdev %p free_msix failed!",
			rdev->netdev);
	}
	if (do_unlock == true)
		rtnl_unlock();
	return 0;
}

static int bnxt_re_request_msix(struct bnxt_re_dev *rdev)
{
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	int rc = 0, num_msix_want = BNXT_RE_MIN_MSIX, num_msix_got;

	if (!rdev) {
		dev_err(NULL, "%s: rdev %p Device is invalid",
			ROCE_DRV_MODULE_NAME, rdev);
		return -EINVAL;
	}
	rtnl_lock();
	num_msix_got = en_dev->en_ops->bnxt_request_msix(en_dev, BNXT_ROCE_ULP,
							 rdev->msix_entries,
							 num_msix_want);
	if (num_msix_got < BNXT_RE_MIN_MSIX) {
		rc = -EINVAL;
		goto done;
	}
	if (num_msix_got != num_msix_want) {
		dev_warn(rdev_to_dev(rdev),
			 "bnxt_request_msix: wanted %d vectors, got %d\n",
			 num_msix_want, num_msix_got);
	}
	rdev->num_msix = num_msix_got;
done:
	rtnl_unlock();
	return rc;
}

#ifdef DISABLE_TIM_BLOCK
static int bnxt_re_net_reg_read(struct bnxt_re_dev *rdev, u32 reg_off,
				u16 num_words, u32 *reg_buf)
{
	struct bnxt_net_ctrl_info info;
	struct bnxt_net_ctrl_reg *reg = &info.data.reg;
	int rc = -EINVAL;

	rtnl_lock();
	if (!rdev->netdev || !rdev->intf->net_ctrl)
		goto done;

	memset(&info, 0, sizeof(info));
	reg->off = reg_off;
	reg->words = num_words;
	reg->buf = reg_buf;
	info.cmd = NET_CTRL_REG_READ_CMD;
	rc = (rdev->intf->net_ctrl)(rdev->netdev, &info);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Failed to read reg 0x%x rc = 0x%x",
			reg->off, rc);
		goto done;
	}
	dev_dbg(rdev_to_dev(rdev),
		"Reg 0x%x read with data 0x%x", reg->off, *reg->buf);
done:
	rtnl_unlock();
	return rc;
}

static int bnxt_re_net_reg_write(struct bnxt_re_dev *rdev, u32 reg_off,
				 u32 reg_val)
{
	struct bnxt_net_ctrl_info info;
	struct bnxt_net_ctrl_reg *reg = &info.data.reg;
	int rc = -EINVAL;

	rtnl_lock();
	if (!rdev->netdev || !rdev->intf->net_ctrl)
		goto done;

	memset(&info, 0, sizeof(info));
	reg->off = reg_off;
	reg->buf = &reg_val;
	info.cmd = NET_CTRL_REG_WRITE_CMD;
	rc = (rdev->intf->net_ctrl)(rdev->netdev, &info);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to write reg 0x%x rc = 0x%x", reg->off, rc);
		goto done;
	}
	dev_dbg(rdev_to_dev(rdev),
		"Reg 0x%x wrote with data 0x%x", reg->off, *reg->buf);
done:
	rtnl_unlock();
	return rc;
}
#endif

static void bnxt_re_init_hwrm_hdr(struct bnxt_re_dev *rdev, struct input *hdr,
				  u16 opcd, u16 crid, u16 trid)
{
	hdr->req_type = cpu_to_le16(opcd);
	hdr->cmpl_ring = cpu_to_le16(crid);
	hdr->target_id = cpu_to_le16(trid);
}

static void bnxt_re_fill_fw_msg(struct bnxt_fw_msg *fw_msg, void *msg,
				int msg_len, void *resp, int resp_max_len,
				int timeout)
{
	fw_msg->msg = msg;
	fw_msg->msg_len = msg_len;
	fw_msg->resp = resp;
	fw_msg->resp_max_len = resp_max_len;
	fw_msg->timeout = timeout;
}

static int bnxt_re_net_ring_free(struct bnxt_re_dev *rdev, u16 fw_ring_id,
				 bool lock_wait)
{
	int rc = -EINVAL;
	bool do_unlock = false;
	struct hwrm_ring_free_input req = {0};
	struct hwrm_ring_free_output resp;
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	struct bnxt_fw_msg fw_msg = {0};

	if (!en_dev)
		return rc;
	if (!rtnl_is_locked() || lock_wait == true) {
		rtnl_lock();
		do_unlock = true;
	}
	bnxt_re_init_hwrm_hdr(rdev, (void *)&req, HWRM_RING_FREE, -1, -1);
	req.ring_type = RING_ALLOC_REQ_RING_TYPE_L2_CMPL;
	req.ring_id = cpu_to_le16(fw_ring_id);
	bnxt_re_fill_fw_msg(&fw_msg, (void *)&req, sizeof(req), (void *)&resp,
			    sizeof(resp), DFLT_HWRM_CMD_TIMEOUT);
	rc = en_dev->en_ops->bnxt_send_fw_msg(en_dev, BNXT_ROCE_ULP, &fw_msg);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to free HW ring with rc = 0x%x", rc);
		goto done;
	}
	dev_dbg(rdev_to_dev(rdev), "HW ring freed with id = 0x%x\n",
		fw_ring_id);
done:
	if (do_unlock == true)
		rtnl_unlock();
	return rc;
}

static int bnxt_re_net_ring_alloc(struct bnxt_re_dev *rdev, dma_addr_t *dma_arr,
				  int pages, int type, u32 ring_mask,
				  u32 map_index, u16 *fw_ring_id)
{
	int rc = -EINVAL;
	struct hwrm_ring_alloc_input req = {0};
	struct hwrm_ring_alloc_output resp;
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	struct bnxt_fw_msg fw_msg = {0};

	if (!en_dev)
		return rc;

	rtnl_lock();
	bnxt_re_init_hwrm_hdr(rdev, (void *)&req, HWRM_RING_ALLOC, -1, -1);
	req.enables = 0;
	req.page_tbl_addr =  cpu_to_le64(dma_arr[0]);
	if (pages > 1) {
		/* Page size is in log2 units */
		req.page_size = BNXT_PAGE_SHIFT;
		req.page_tbl_depth = 1;
	}
	req.fbo = 0;
	/* Association of ring index with doorbell index and MSIX number */
	req.logical_id = cpu_to_le16(map_index);
	req.length = cpu_to_le32(ring_mask + 1);
	req.ring_type = RING_ALLOC_REQ_RING_TYPE_L2_CMPL;
	req.int_mode = RING_ALLOC_REQ_INT_MODE_MSIX;
	bnxt_re_fill_fw_msg(&fw_msg, (void *)&req, sizeof(req), (void *)&resp,
			    sizeof(resp), DFLT_HWRM_CMD_TIMEOUT);
	rc = en_dev->en_ops->bnxt_send_fw_msg(en_dev, BNXT_ROCE_ULP, &fw_msg);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to allocate HW ring with rc = 0x%x", rc);
		goto done;
	}
	*fw_ring_id = le16_to_cpu(resp.ring_id);
	dev_dbg(rdev_to_dev(rdev),
		"HW ring allocated with id = 0x%x at slot 0x%x",
		resp.ring_id, map_index);
done:
	rtnl_unlock();
	return rc;
}

static int bnxt_re_net_stats_ctx_free(struct bnxt_re_dev *rdev,
				      u32 fw_stats_ctx_id, bool lock_wait)
{
	int rc = -EINVAL;
	bool do_unlock = false;
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	struct hwrm_stat_ctx_free_input req = {0};
	struct bnxt_fw_msg fw_msg = {0};

	if (!en_dev)
		return rc;
	if (!rtnl_is_locked() || lock_wait == true) {
		rtnl_lock();
		do_unlock = true;
	}
	bnxt_re_init_hwrm_hdr(rdev, (void *)&req, HWRM_STAT_CTX_FREE, -1, -1);
	req.stat_ctx_id = cpu_to_le32(fw_stats_ctx_id);
	bnxt_re_fill_fw_msg(&fw_msg, (void *)&req, sizeof(req), (void *)&req,
			    sizeof(req), DFLT_HWRM_CMD_TIMEOUT);
	rc = en_dev->en_ops->bnxt_send_fw_msg(en_dev, BNXT_ROCE_ULP, &fw_msg);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to free HW stats ctx with rc = 0x%x", rc);
		goto done;
	}
	dev_dbg(rdev_to_dev(rdev),
		"HW stats ctx freed with id = 0x%x", fw_stats_ctx_id);
done:
	if (do_unlock == true)
		rtnl_unlock();
	return rc;
}

static int bnxt_re_net_stats_ctx_alloc(struct bnxt_re_dev *rdev,
				       dma_addr_t dma_map,
				       u32 *fw_stats_ctx_id)
{
	int rc = 0;
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	struct hwrm_stat_ctx_alloc_input req = {0};
	struct hwrm_stat_ctx_alloc_output resp = {0};
	struct bnxt_fw_msg fw_msg = {0};

	*fw_stats_ctx_id = INVALID_STATS_CTX_ID;

	rtnl_lock();
	if (!en_dev)
		goto done;

	bnxt_re_init_hwrm_hdr(rdev, (void *)&req, HWRM_STAT_CTX_ALLOC, -1, -1);
	req.update_period_ms = cpu_to_le32(1000);
	req.stats_dma_addr = cpu_to_le64(dma_map);
	req.stat_ctx_flags = STAT_CTX_ALLOC_REQ_STAT_CTX_FLAGS_ROCE;
	bnxt_re_fill_fw_msg(&fw_msg, (void *)&req, sizeof(req), (void *)&resp,
			    sizeof(resp), DFLT_HWRM_CMD_TIMEOUT);
	rc = en_dev->en_ops->bnxt_send_fw_msg(en_dev, BNXT_ROCE_ULP, &fw_msg);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to allocate HW stats ctx, rc = 0x%x", rc);
		goto done;
	}
	*fw_stats_ctx_id = le32_to_cpu(resp.stat_ctx_id);
	dev_dbg(rdev_to_dev(rdev), "HW stats ctx allocated with id = 0x%x",
		*fw_stats_ctx_id);
done:
	rtnl_unlock();
	return rc;
}
/* Net -> RoCE driver */

/* Device */

static bool is_bnxt_re_dev(struct net_device *netdev)
{
	struct ethtool_drvinfo drvinfo;

	if (netdev->ethtool_ops && netdev->ethtool_ops->get_drvinfo) {
		memset(&drvinfo, 0, sizeof(drvinfo));
		netdev->ethtool_ops->get_drvinfo(netdev, &drvinfo);

		if (strcmp(drvinfo.driver, "bnxt_en"))
			return false;

		dev_dbg(NULL, "%s: netdev %p name %s version %s",
			ROCE_DRV_MODULE_NAME, netdev, drvinfo.driver,
			drvinfo.version);
#ifdef HAVE_NET_VERSION
		{
			unsigned int len, version, major, minor;
			char *verstr, *src, *ptr;

			len = strlen(drvinfo.version);
			verstr = kmalloc(len + 1, GFP_KERNEL);
			if (!verstr)
				return false;
			strlcpy(verstr, drvinfo.version, len + 1);

			src = verstr;
			ptr = strsep(&src, ".");
			if (kstrtouint(ptr, 15, &version))
				goto free;
			ptr = strsep(&src, ".");
			if (kstrtouint(ptr, 15, &major))
				goto free;
			if (kstrtouint(src, 15, &minor))
				dev_dbg(NULL,
				"%s: bnxt_en ver %d.%d.XX detected",
				ROCE_DRV_MODULE_NAME, version, major);
			else
				dev_dbg(NULL,
					"%s: bnxt_en ver %d.%d.%d detected",
					ROCE_DRV_MODULE_NAME, version, major,
					minor);
free:
			kfree(verstr);
			if (version <= 0)
				return false;
		}
#endif
		return true;
	}
	return false;
}

static struct bnxt_re_dev *bnxt_re_from_netdev(struct net_device *netdev)
{
	struct bnxt_re_dev *rdev;

	rcu_read_lock();
	list_for_each_entry_rcu(rdev, &bnxt_re_dev_list, list) {
		if (rdev->netdev == netdev) {
			rcu_read_unlock();
			dev_dbg(rdev_to_dev(rdev),
				"netdev (%p) found, ref_count = 0x%x",
				netdev, atomic_read(&rdev->ref_count));
			return rdev;
		}
	}
	rcu_read_unlock();
	return NULL;
}

static void bnxt_re_dev_unprobe(struct net_device *netdev,
				struct bnxt_en_dev *en_dev)
{
	dev_put(netdev);
}

struct bnxt_en_dev *bnxt_re_dev_probe(struct net_device *netdev)
{
	struct bnxt *bp = netdev_priv(netdev);
	struct bnxt_en_dev *en_dev;
	struct pci_dev *pdev;

	/* Call bnxt_en's RoCE probe via indirect API */
	if (!bp->ulp_probe) {
		dev_err(NULL, "%s: probe error: bp->bnxt_ulp_probe is NULL!",
			ROCE_DRV_MODULE_NAME);
		return ERR_PTR(-EINVAL);
	}
	en_dev = bp->ulp_probe(netdev);
	if (IS_ERR(en_dev)) {
		dev_err(NULL, "%s: (0x%p) probe error!\n ",
			ROCE_DRV_MODULE_NAME, bp);
		return en_dev;
	}

	pdev = en_dev->pdev;
	if (!pdev) {
		dev_err(NULL, "%s: probe error: PCI device is NULL!",
			ROCE_DRV_MODULE_NAME);
		return ERR_PTR(-EINVAL);
	}

	if (!(en_dev->flags & BNXT_EN_FLAG_ROCE_CAP)) {
		dev_dbg(&pdev->dev,
			"%s: probe error: RoCE is not supported on this device",
			ROCE_DRV_MODULE_NAME);
		return ERR_PTR(-ENODEV);
	}
	dev_dbg(&pdev->dev, "%s: RoCE is supported on this device",
		 ROCE_DRV_MODULE_NAME);
	/* Bump net device reference count */
	dev_hold(netdev);

	return en_dev;
}

static void bnxt_re_unregister_ib(struct bnxt_re_dev *rdev)
{
	ib_unregister_device(&rdev->ibdev);
}

static int bnxt_re_register_ib(struct bnxt_re_dev *rdev)
{
	struct ib_device *ibdev = &rdev->ibdev;

	/* ib device init */
	ibdev->owner = THIS_MODULE;
	ibdev->node_type = RDMA_NODE_IB_CA;
	strlcpy(ibdev->name, "bnxt_re%d", IB_DEVICE_NAME_MAX);
	strlcpy(ibdev->node_desc, BNXT_RE_DESC " HCA",
		strlen(BNXT_RE_DESC) + 5);
	ibdev->phys_port_cnt = 1;

	bnxt_qplib_get_guid(rdev->netdev->dev_addr, (u8 *)&ibdev->node_guid);

	/* TODO: 4K completion vectors? */
	ibdev->num_comp_vectors	= 1 << 12;
	ibdev->dma_device = &rdev->en_dev->pdev->dev;
	ibdev->local_dma_lkey = BNXT_QPLIB_RSVD_LKEY;

	/* User space */
	ibdev->uverbs_abi_ver = BNXT_RE_ABI_VERSION;
	ibdev->uverbs_cmd_mask =
			(1ull << IB_USER_VERBS_CMD_GET_CONTEXT)		|
			(1ull << IB_USER_VERBS_CMD_QUERY_DEVICE)	|
			(1ull << IB_USER_VERBS_CMD_QUERY_PORT)		|
			(1ull << IB_USER_VERBS_CMD_ALLOC_PD)		|
			(1ull << IB_USER_VERBS_CMD_DEALLOC_PD)		|
			(1ull << IB_USER_VERBS_CMD_REG_MR)		|
			(1ull << IB_USER_VERBS_CMD_REREG_MR)		|
			(1ull << IB_USER_VERBS_CMD_DEREG_MR)		|
			(1ull << IB_USER_VERBS_CMD_CREATE_COMP_CHANNEL) |
			(1ull << IB_USER_VERBS_CMD_CREATE_CQ)		|
			(1ull << IB_USER_VERBS_CMD_RESIZE_CQ)		|
			(1ull << IB_USER_VERBS_CMD_DESTROY_CQ)		|
			(1ull << IB_USER_VERBS_CMD_CREATE_QP)		|
			(1ull << IB_USER_VERBS_CMD_MODIFY_QP)		|
			(1ull << IB_USER_VERBS_CMD_QUERY_QP)		|
			(1ull << IB_USER_VERBS_CMD_DESTROY_QP)		|
			(1ull << IB_USER_VERBS_CMD_CREATE_SRQ)		|
			(1ull << IB_USER_VERBS_CMD_MODIFY_SRQ)		|
			(1ull << IB_USER_VERBS_CMD_QUERY_SRQ)		|
			(1ull << IB_USER_VERBS_CMD_DESTROY_SRQ)		|
			(1ull << IB_USER_VERBS_CMD_CREATE_AH)		|
			(1ull << IB_USER_VERBS_CMD_MODIFY_AH)		|
			(1ull << IB_USER_VERBS_CMD_QUERY_AH)		|
			(1ull << IB_USER_VERBS_CMD_DESTROY_AH)		|
			(1ull << IB_USER_VERBS_CMD_ALLOC_MW)		|
			(1ull << IB_USER_VERBS_CMD_DEALLOC_MW)		|
			(1ull << IB_USER_VERBS_CMD_POLL_CQ);

	/* REQ_NOTIFY_CQ is directly handled in libbnxt_re.
	 * POLL_CQ is processed only as part of a RESIZE_CQ operation;
	 * the library uses this to let the kernel driver know that
	 * RESIZE_CQ is complete and memory from the previous CQ can be
	 * unmapped.
	 */

	/* Kernel verbs */
	ibdev->query_device		= bnxt_re_query_device;
	ibdev->modify_device		= bnxt_re_modify_device;

	ibdev->query_port		= bnxt_re_query_port;
	ibdev->modify_port		= bnxt_re_modify_port;
#ifdef HAVE_IB_GET_PORT_IMMUTABLE
	ibdev->get_port_immutable	= bnxt_re_get_port_immutable;
#endif
	ibdev->query_pkey		= bnxt_re_query_pkey;
	ibdev->query_gid		= bnxt_re_query_gid;
#ifdef HAVE_IB_GET_NETDEV
	ibdev->get_netdev		= bnxt_re_get_netdev;
#endif
#ifdef HAVE_IB_ADD_DEL_GID
	ibdev->add_gid			= bnxt_re_add_gid;
	ibdev->del_gid			= bnxt_re_del_gid;
#endif
#ifdef HAVE_IB_MODIFY_GID
	ibdev->modify_gid		= bnxt_re_modify_gid;
#endif
	ibdev->get_link_layer		= bnxt_re_get_link_layer;

	ibdev->alloc_pd			= bnxt_re_alloc_pd;
	ibdev->dealloc_pd		= bnxt_re_dealloc_pd;

	ibdev->create_ah		= bnxt_re_create_ah;
	ibdev->modify_ah		= bnxt_re_modify_ah;
	ibdev->query_ah			= bnxt_re_query_ah;
	ibdev->destroy_ah		= bnxt_re_destroy_ah;

	ibdev->create_srq		= bnxt_re_create_srq;
	ibdev->modify_srq		= bnxt_re_modify_srq;
	ibdev->query_srq		= bnxt_re_query_srq;
	ibdev->destroy_srq		= bnxt_re_destroy_srq;
	ibdev->post_srq_recv		= bnxt_re_post_srq_recv;

	ibdev->create_qp		= bnxt_re_create_qp;
	ibdev->modify_qp		= bnxt_re_modify_qp;
	ibdev->query_qp			= bnxt_re_query_qp;
	ibdev->destroy_qp		= bnxt_re_destroy_qp;

	ibdev->post_send		= bnxt_re_post_send;
	ibdev->post_recv		= bnxt_re_post_recv;

	ibdev->create_cq		= bnxt_re_create_cq;
	ibdev->modify_cq		= bnxt_re_modify_cq;	/* Need ? */
	ibdev->destroy_cq		= bnxt_re_destroy_cq;
	ibdev->resize_cq		= bnxt_re_resize_cq;
	ibdev->poll_cq			= bnxt_re_poll_cq;
	ibdev->req_notify_cq		= bnxt_re_req_notify_cq;

	ibdev->get_dma_mr		= bnxt_re_get_dma_mr;
#ifdef HAVE_IB_REG_PHYS_MR
	ibdev->reg_phys_mr		= bnxt_re_reg_phys_mr;
	ibdev->rereg_phys_mr		= bnxt_re_rereg_phys_mr;
#endif
#ifdef HAVE_IB_QUERY_MR
	ibdev->query_mr			= bnxt_re_query_mr;
#endif
	ibdev->dereg_mr			= bnxt_re_dereg_mr;
#ifdef HAVE_IB_SIGNATURE_HANDOVER
	ibdev->destroy_mr		= bnxt_re_destroy_mr;
	ibdev->create_mr		= bnxt_re_create_mr;
#endif
#ifdef HAVE_IB_FAST_REG_MR
	ibdev->alloc_fast_reg_mr	= bnxt_re_alloc_fast_reg_mr;
	ibdev->alloc_fast_reg_page_list	= bnxt_re_alloc_fast_reg_page_list;
	ibdev->free_fast_reg_page_list	= bnxt_re_free_fast_reg_page_list;
#endif
#ifdef HAVE_IB_ALLOC_MR
	ibdev->alloc_mr			= bnxt_re_alloc_mr;
#endif
#ifdef HAVE_IB_MAP_MR_SG
	ibdev->map_mr_sg		= bnxt_re_map_mr_sg;
#endif
	ibdev->alloc_mw			= bnxt_re_alloc_mw;
#ifdef HAVE_IB_BIND_MW
	ibdev->bind_mw			= bnxt_re_bind_mw;
#endif
	ibdev->dealloc_mw		= bnxt_re_dealloc_mw;
#ifdef USE_IB_FMR
	ibdev->alloc_fmr		= bnxt_re_alloc_fmr;
	ibdev->map_phys_fmr		= bnxt_re_map_phys_fmr;
	ibdev->unmap_fmr		= bnxt_re_unmap_fmr;
	ibdev->dealloc_fmr		= bnxt_re_dealloc_fmr;
#endif
#ifdef HAVE_IB_FLOW
	ibdev->create_flow		= bnxt_re_create_flow;
	ibdev->destroy_flow		= bnxt_re_destroy_flow;
#endif

	ibdev->reg_user_mr		= bnxt_re_reg_user_mr;
#ifdef HAVE_IB_REREG_USER_MR
	ibdev->rereg_user_mr		= bnxt_re_rereg_user_mr;
#endif
#ifdef HAVE_IB_DRAIN
	ibdev->drain_rq			= bnxt_re_drain_rq;
	ibdev->drain_sq			= bnxt_re_drain_sq;
#endif
	ibdev->alloc_ucontext		= bnxt_re_alloc_ucontext;
	ibdev->dealloc_ucontext		= bnxt_re_dealloc_ucontext;
	ibdev->mmap			= bnxt_re_mmap;
	ibdev->process_mad		= bnxt_re_process_mad;

#ifndef HAVE_IB_ALLOC_MR
	/* TODO: Workaround to uninitialized the kobj */
	ibdev->dev.kobj.state_initialized = 0;
#endif
	return ib_register_device(ibdev, NULL);
}

static ssize_t show_rev(struct device *device, struct device_attribute *attr,
			char *buf)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(device, ibdev.dev);

	return scnprintf(buf, PAGE_SIZE, "0x%x\n", rdev->en_dev->pdev->vendor);
	strcpy(buf, "bnxt_re");
	return 0;
}

static ssize_t show_fw_ver(struct device *device, struct device_attribute *attr,
			   char *buf)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(device, ibdev.dev);

	return scnprintf(buf, PAGE_SIZE, "%s\n", rdev->dev_attr.fw_ver);
}

static ssize_t show_hca(struct device *device, struct device_attribute *attr,
			char *buf)
{
	struct bnxt_re_dev *rdev = to_bnxt_re_dev(device, ibdev.dev);

	return scnprintf(buf, PAGE_SIZE, "%s\n", rdev->ibdev.node_desc);
}

static DEVICE_ATTR(hw_rev, S_IRUGO, show_rev, NULL);
static DEVICE_ATTR(fw_rev, S_IRUGO, show_fw_ver, NULL);
static DEVICE_ATTR(hca_type, S_IRUGO, show_hca, NULL);

static struct device_attribute *bnxt_re_attributes[] = {
	&dev_attr_hw_rev,
	&dev_attr_fw_rev,
	&dev_attr_hca_type
};

static void bnxt_re_dev_remove(struct bnxt_re_dev *rdev)
{
	int i = BNXT_RE_REF_WAIT_COUNT;

	/* Wait for rdev refcount to come down */
	while ((atomic_read(&rdev->ref_count) > 1) && i--)
		msleep(100);

	if (atomic_read(&rdev->ref_count) > 1)
		dev_err(rdev_to_dev(rdev),
			"Failed waiting for ref count to deplete %d",
			atomic_read(&rdev->ref_count));

	atomic_set(&rdev->ref_count, 0);
	dev_put(rdev->netdev);
	rdev->netdev = NULL;

	mutex_lock(&bnxt_re_dev_lock);
	list_del_rcu(&rdev->list);
	adapter_count--;
	mutex_unlock(&bnxt_re_dev_lock);
	dev_dbg(rdev_to_dev(rdev), "Device removed (adapter count %d)",
		adapter_count);

	synchronize_rcu();
	flush_workqueue(bnxt_re_wq);

	ib_dealloc_device(&rdev->ibdev);
	/* rdev is gone */
}

static struct bnxt_re_dev *bnxt_re_dev_add(struct net_device *netdev,
					   struct bnxt_en_dev *en_dev)
{
	struct bnxt_re_dev *rdev;

	/* Allocate bnxt_re_dev instance here */
	rdev = (struct bnxt_re_dev *)ib_alloc_device(sizeof(*rdev));
	if (!rdev) {
		dev_err(NULL, "%s: bnxt_re_dev allocation failure!",
			ROCE_DRV_MODULE_NAME);
		return NULL;
	}
	/* Default values */
	atomic_set(&rdev->ref_count, 0);
	rdev->netdev = netdev;
	dev_hold(rdev->netdev);
	rdev->en_dev = en_dev;
	rdev->id = rdev->en_dev->pdev->devfn;
	INIT_LIST_HEAD(&rdev->qp_list);
	mutex_init(&rdev->qp_lock);
	atomic_set(&rdev->qp_count, 0);
	atomic_set(&rdev->cq_count, 0);
	atomic_set(&rdev->srq_count, 0);
	atomic_set(&rdev->mr_count, 0);
	atomic_set(&rdev->mw_count, 0);
	rdev->cosq[0] = rdev->cosq[1] = 0xFFFF;

	mutex_lock(&bnxt_re_dev_lock);
	list_add_tail_rcu(&rdev->list, &bnxt_re_dev_list);
	adapter_count++;
	mutex_unlock(&bnxt_re_dev_lock);
	dev_dbg(rdev_to_dev(rdev), "Device added (adapter count %d)",
		adapter_count);
	return rdev;
}

static int bnxt_re_aeq_handler(struct bnxt_qplib_rcfw *rcfw,
			       struct creq_func_event *aeqe)
{
//	struct bnxt_re_dev *rdev = to_bnxt_re_dev(rcfw, rcfw);

	switch (aeqe->event) {
	case CREQ_FUNC_EVENT_EVENT_TX_WQE_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_TX_DATA_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_RX_WQE_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_RX_DATA_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_CQ_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_TQM_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_CFCQ_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_CFCS_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_CFCC_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_CFCM_ERROR:
		break;
	case CREQ_FUNC_EVENT_EVENT_TIM_ERROR:
		break;
	default:
		return -EINVAL;
	}
	return 0;
}

/*
static enum ib_event_type __to_ib_event(u8 event)
{
	switch (event) {
	case NQ_SRQ_EVENT_EVENT_SRQ_THRESHOLD_EVENT:
		return IB_EVENT_SRQ_LIMIT_REACHED;
}
*/

static int bnxt_re_srqn_handler(struct bnxt_qplib_nq *nq,
				struct bnxt_qplib_srq *handle, u8 event)
{
	struct bnxt_re_srq *srq = to_bnxt_re(handle, struct bnxt_re_srq,
					     qplib_srq);
	struct ib_event ib_event;
	int rc = 0;

	if (srq == NULL) {
		dev_err(NULL, "%s: SRQ is NULL, SRQN not handled",
			ROCE_DRV_MODULE_NAME);
		rc = -EINVAL;
		goto done;
	}
	ib_event.device = &srq->rdev->ibdev;
	ib_event.element.srq = &srq->ib_srq;
	if (event == NQ_SRQ_EVENT_EVENT_SRQ_THRESHOLD_EVENT)
		ib_event.event = IB_EVENT_SRQ_LIMIT_REACHED;
	else
		ib_event.event = IB_EVENT_SRQ_ERR;

	if (srq->ib_srq.event_handler) {
		/* Lock event_handler? */
		(*srq->ib_srq.event_handler)(&ib_event,
					     srq->ib_srq.srq_context);
	}
done:
	return rc;
}

static int bnxt_re_cqn_handler(struct bnxt_qplib_nq *nq,
			       struct bnxt_qplib_cq *handle)
{
	struct bnxt_re_cq *cq = to_bnxt_re(handle, struct bnxt_re_cq,
					   qplib_cq);
	int rc = 0;

	if (cq == NULL) {
		dev_err(NULL, "%s: CQ is NULL, CQN not handled",
			ROCE_DRV_MODULE_NAME);
		rc = -EINVAL;
		goto done;
	}
	if (cq->ib_cq.comp_handler) {
		/* Lock comp_handler? */
		(*cq->ib_cq.comp_handler)(&cq->ib_cq, cq->ib_cq.cq_context);
	}
done:
	return rc;
}

static void bnxt_re_cleanup_res(struct bnxt_re_dev *rdev)
{
	if (rdev->nq.hwq.max_elements)
		bnxt_qplib_disable_nq(&rdev->nq);

	if (rdev->qplib_res.rcfw)
		bnxt_qplib_cleanup_res(&rdev->qplib_res);
}

static int bnxt_re_init_res(struct bnxt_re_dev *rdev)
{
	int rc = 0;

	bnxt_qplib_init_res(&rdev->qplib_res);
	if (rdev->msix_entries[BNXT_RE_NQ_IDX].vector > 0)
		rc = bnxt_qplib_enable_nq(rdev->en_dev->pdev, &rdev->nq,
				rdev->msix_entries[BNXT_RE_NQ_IDX].vector,
				rdev->msix_entries[BNXT_RE_NQ_IDX].db_offset,
				&bnxt_re_cqn_handler, &bnxt_re_srqn_handler);
	else
		/* TODO: Allow Poll mode operation only?  Maybe later... */
		rc = -EINVAL;
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to enable NQ with rc = 0x%x", rc);
		goto fail;
	}
	return 0;
fail:
	return rc;
}

static void bnxt_re_free_res(struct bnxt_re_dev *rdev, bool lock_wait)
{
	if (rdev->nq.hwq.max_elements) {
		bnxt_re_net_ring_free(rdev, rdev->nq.ring_id, lock_wait);
		bnxt_qplib_free_nq(&rdev->nq);
	}
	if (rdev->qplib_res.dpi_tbl.max) {
		bnxt_qplib_dealloc_dpi(&rdev->qplib_res,
			       &rdev->qplib_res.dpi_tbl, &rdev->dpi_privileged);
	}
	if (rdev->qplib_res.rcfw) {
		bnxt_qplib_free_res(&rdev->qplib_res);
		rdev->qplib_res.rcfw = NULL;
	}
}

static int bnxt_re_alloc_res(struct bnxt_re_dev *rdev)
{
	int rc = 0;

	/* Configure and allocate resources for qplib */
	rdev->qplib_res.rcfw = &rdev->rcfw;
	rc = bnxt_qplib_get_dev_attr(&rdev->rcfw, &rdev->dev_attr,
				     rdev->is_virtfn);
	if (rc)
		goto fail;

	rc = bnxt_qplib_alloc_res(&rdev->qplib_res, rdev->en_dev->pdev,
				  rdev->netdev, &rdev->dev_attr);
	if (rc)
		goto fail;

	rc = bnxt_qplib_alloc_dpi(&rdev->qplib_res.dpi_tbl,
				  &rdev->dpi_privileged,
				  rdev);
	if (rc)
		goto fail;

	rdev->nq.hwq.max_elements = BNXT_RE_MAX_CQ_COUNT +
				    BNXT_RE_MAX_SRQC_COUNT + 2;
	rc = bnxt_qplib_alloc_nq(rdev->en_dev->pdev, &rdev->nq);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Failed to allocate ");
		dev_err(rdev_to_dev(rdev),
			"Notification memory with rc = 0x%x", rc);
		goto fail;
	}
	rc = bnxt_re_net_ring_alloc(rdev,
				rdev->nq.hwq.pbl[PBL_LVL_0].pg_map_arr,
				rdev->nq.hwq.pbl[rdev->nq.hwq.level].pg_count,
				HWRM_RING_ALLOC_CMPL,
				BNXT_QPLIB_NQE_MAX_CNT - 1,
				rdev->msix_entries[BNXT_RE_NQ_IDX].ring_idx,
				&rdev->nq.ring_id);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to allocate NQ fw id with rc = 0x%x", rc);
		goto free_nq;
	}
	return 0;
free_nq:
	bnxt_qplib_free_nq(&rdev->nq);
fail:
	rdev->qplib_res.rcfw = NULL;
	return rc;
}

static void bnxt_re_dispatch_event(struct ib_device *ibdev, struct ib_qp *qp,
				   u8 port_num, enum ib_event_type event)
{
	struct ib_event ib_event;

	ib_event.device = ibdev;
	if (qp)
		ib_event.element.qp = qp;
	else
		ib_event.element.port_num = port_num;
	ib_event.event = event;
	ib_dispatch_event(&ib_event);

	dev_dbg(rdev_to_dev(to_bnxt_re_dev(ibdev, ibdev)),
		"ibdev %p Event 0x%x port_num 0x%x", ibdev, event, port_num);
}

#define HWRM_QUEUE_PRI2COS_QCFG_INPUT_FLAGS_IVLAN      0x02
int bnxt_re_query_hwrm_pri2cos(struct bnxt_re_dev *rdev, u8 prio_mask, u8 dir,
			       u64 *cid_map)
{
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	struct hwrm_queue_pri2cos_qcfg_input req = {0};
	struct hwrm_queue_pri2cos_qcfg_output resp;
	struct bnxt *bp = netdev_priv(rdev->netdev);
	struct bnxt_fw_msg fw_msg = {0};
	u32 flags = 0;
	u8 *cidmap;
	int rc = 0;

	bnxt_re_init_hwrm_hdr(rdev, (void *)&req,
			      HWRM_QUEUE_PRI2COS_QCFG, -1, -1);
	flags |= (dir & 0x01);
	flags |= HWRM_QUEUE_PRI2COS_QCFG_INPUT_FLAGS_IVLAN;
	req.flags = cpu_to_le32(flags);
	req.port_id = bp->pf.port_id;

	/* TBD - Do we need spinlock here ? */
	bnxt_re_fill_fw_msg(&fw_msg, (void *)&req, sizeof(req), (void *)&resp,
			    sizeof(resp), DFLT_HWRM_CMD_TIMEOUT);
	rc = en_dev->en_ops->bnxt_send_fw_msg(en_dev, BNXT_ROCE_ULP, &fw_msg);
	if (rc)
		return rc;

	if (resp.queue_cfg_info) {
		dev_warn(rdev_to_dev(rdev),
			 "Asymmetric cos queue configuration detected");
		dev_warn(rdev_to_dev(rdev),
			 " on device, QoS may not be fully functional\n");
	}
	cidmap = &resp.pri0_cos_queue_id;
	if (cid_map)
		*cid_map = le64_to_cpu(*((u64 *)cidmap));

	return rc;
}

static bool bnxt_re_is_qp1_or_shadow_qp(struct bnxt_re_dev *rdev,
					struct bnxt_re_qp *qp)
{
	return (qp->ib_qp.qp_type == IB_QPT_GSI)
#ifdef ENABLE_SHADOW_QP
		|| (qp == rdev->qp1_sqp)
#endif
		;
}

void bnxt_re_dev_stop(struct bnxt_re_dev *rdev)
{
	struct bnxt_re_qp *qp;
	struct ib_qp_attr qp_attr;
	int mask = IB_QP_STATE;

	qp_attr.qp_state = IB_QPS_ERR;
	mutex_lock(&rdev->qp_lock);
	list_for_each_entry(qp, &rdev->qp_list, list) {
		/* Modify the state of all QPs except QP1/Shadow QP */
		if (qp && !bnxt_re_is_qp1_or_shadow_qp(rdev, qp)) {
			if (qp->qplib_qp.state !=
			    CMDQ_MODIFY_QP_NEW_STATE_RESET ||
			    qp->qplib_qp.state !=
			    CMDQ_MODIFY_QP_NEW_STATE_ERR) {
				bnxt_re_dispatch_event(&rdev->ibdev, &qp->ib_qp,
						       1, IB_EVENT_QP_FATAL);
				bnxt_re_modify_qp(&qp->ib_qp, &qp_attr, mask,
						  NULL);
			}
		}
	}

	mutex_unlock(&rdev->qp_lock);
}

static u32 bnxt_re_get_priority_mask(struct bnxt_re_dev *rdev)
{
	struct net_device *netdev;
	struct dcb_app app;
	u32 prio_map = 0, tmp_map = 0;

	netdev = rdev->netdev;

	memset(&app, 0, sizeof(app));
	app.selector = IEEE_8021QAZ_APP_SEL_ETHERTYPE;
	app.protocol = BNXT_RE_ROCE_V1_ETH_TYPE;
	tmp_map = dcb_ieee_getapp_mask(netdev, &app);
	prio_map = tmp_map;

	app.selector = IEEE_8021QAZ_APP_SEL_DGRAM;
	app.protocol = BNXT_RE_ROCE_V2_PORT_NO;
	tmp_map = dcb_ieee_getapp_mask(netdev, &app);
	prio_map |= tmp_map;

	return prio_map;
}

static void bnxt_re_parse_cid_map(u8 prio_map, u8 *cid_map, u16 *cosq)
{
	u8 id;
	u16 prio;

	for (prio = 0, id = 0; prio < 8; prio++) {
		if (prio_map & (1 << prio)) {
			cosq[id] = cid_map[prio];
			id++;
			if (id == 2) /* Max 2 tcs supported */
				break;
		}
	}
}

static int bnxt_re_setup_qos(struct bnxt_re_dev *rdev)
{
	u64 cid_map;
	u8 prio_map = 0;
	int rc;

	/* Get priority for roce */
	prio_map = bnxt_re_get_priority_mask(rdev);

	if (prio_map == rdev->cur_prio_map)
		return 0;
	rdev->cur_prio_map = prio_map;
	/* Get cosq id for this priority */
	rc = bnxt_re_query_hwrm_pri2cos(rdev, prio_map, 0, &cid_map);
	if (rc) {
		dev_warn(rdev_to_dev(rdev), "no cos for p_mask %x\n", prio_map);
		return rc;
	}
	/* Parse CoS IDs for app priority */
	bnxt_re_parse_cid_map(prio_map, (u8 *)&cid_map, rdev->cosq);

	/* Config BONO. */
	rc = bnxt_qplib_map_tc2cos(&rdev->qplib_res, rdev->cosq);
	if (rc) {
		dev_warn(rdev_to_dev(rdev), "no tc for cos{%x, %x}\n",
			 rdev->cosq[0], rdev->cosq[1]);
		return rc;
	}

	rdev->qplib_res.prio = prio_map ? true : false;

	return 0;
}

static void bnxt_re_ib_unreg(struct bnxt_re_dev *rdev, bool lock_wait)
{
	int i, rc;

	if (test_and_clear_bit(BNXT_RE_FLAG_IBDEV_REGISTERED, &rdev->flags)) {
		for (i = 0; i < ARRAY_SIZE(bnxt_re_attributes); i++)
			device_remove_file(&rdev->ibdev.dev,
					   bnxt_re_attributes[i]);
		/* Cleanup ib dev */
		bnxt_re_unregister_ib(rdev);
	}
	if (test_and_clear_bit(BNXT_RE_FLAG_QOS_WORK_REG, &rdev->flags))
		cancel_delayed_work(&rdev->worker);

	/* Wait for ULPs to release references */
	while (atomic_read(&rdev->cq_count))
		usleep_range(500, 1000);

	bnxt_re_cleanup_res(rdev);
	bnxt_re_free_res(rdev, lock_wait);

	if (test_and_clear_bit(BNXT_RE_FLAG_RCFW_CHANNEL_EN, &rdev->flags)) {
		rc = bnxt_qplib_deinit_rcfw(&rdev->rcfw);
		if (rc)
			dev_warn(rdev_to_dev(rdev),
				 "Failed to deinitialize fw with rc = 0x%x",
				 rc);
		bnxt_re_net_stats_ctx_free(rdev, rdev->qplib_ctx.stats.fw_id,
					   lock_wait);
		bnxt_qplib_free_ctx(rdev->en_dev->pdev, &rdev->qplib_ctx);
		bnxt_qplib_disable_rcfw_channel(&rdev->rcfw);
		bnxt_re_net_ring_free(rdev, rdev->rcfw.creq_ring_id, lock_wait);
		bnxt_qplib_free_rcfw_channel(&rdev->rcfw);
	}
	if (test_and_clear_bit(BNXT_RE_FLAG_GOT_MSIX , &rdev->flags)) {
		rc = bnxt_re_free_msix(rdev, lock_wait);
		if (rc)
			dev_warn(rdev_to_dev(rdev),
				 "free_msix failed with rc = 0x%x", rc);
	}
	if (test_and_clear_bit(BNXT_RE_FLAG_NETDEV_REGISTERED, &rdev->flags)) {
		rc = bnxt_re_unregister_netdev(rdev, lock_wait);
		if (rc)
			dev_warn(rdev_to_dev(rdev),
				 "Unregister netdev failed with rc = 0x%x", rc);
	}
}

/* worker thread for polling periodic events. Now used for QoS programming*/
static void bnxt_re_worker(struct work_struct *work)
{
	struct bnxt_re_dev *rdev = container_of(work, struct bnxt_re_dev,
						worker.work);

	bnxt_re_setup_qos(rdev);
	schedule_delayed_work(&rdev->worker, msecs_to_jiffies(30000));
}

static int bnxt_re_ib_reg(struct bnxt_re_dev *rdev)
{
	int i, j, rc = 0;
#ifdef DISABLE_TIM_BLOCK
	int val;
#endif

	/* Registered a new RoCE device instance to netdev */
	rc = bnxt_re_register_netdev(rdev);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Register driver failed with rc = 0x%x", rc);
		rc = -EINVAL;
		goto done;
	}
	set_bit(BNXT_RE_FLAG_NETDEV_REGISTERED, &rdev->flags);

	rc = bnxt_re_request_msix(rdev);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Requesting MSI-X vectors failed with rc = 0x%x", rc);
		rc = -EINVAL;
		goto fail;
	}
	set_bit(BNXT_RE_FLAG_GOT_MSIX, &rdev->flags);

	/* Check whether VF or PF */
	bnxt_re_get_sriov_func_type(rdev);

	/* Establish RCFW Communication Channel to initialize the context
	   memory for the function and all child VFs */
	rc = bnxt_qplib_alloc_rcfw_channel(rdev->en_dev->pdev, &rdev->rcfw);
	if (rc) {
		dev_err(rdev_to_dev(rdev), "Failed to allocate ");
		dev_err(rdev_to_dev(rdev),
			"RCFW channel memory with rc = 0x%x", rc);
		goto fail;
	}
	rc = bnxt_re_net_ring_alloc(rdev,
			rdev->rcfw.creq.pbl[PBL_LVL_0].pg_map_arr,
			rdev->rcfw.creq.pbl[rdev->rcfw.creq.level].pg_count,
			HWRM_RING_ALLOC_CMPL, BNXT_QPLIB_CREQE_MAX_CNT - 1,
			rdev->msix_entries[BNXT_RE_AEQ_IDX].ring_idx,
			&rdev->rcfw.creq_ring_id);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to allocate CREQ fw id with rc = 0x%x", rc);
		goto free_rcfw;
	}
	rc = bnxt_qplib_enable_rcfw_channel(rdev->en_dev->pdev, &rdev->rcfw,
				rdev->msix_entries[BNXT_RE_AEQ_IDX].vector,
				rdev->msix_entries[BNXT_RE_AEQ_IDX].db_offset,
				rdev->is_virtfn, &bnxt_re_aeq_handler);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to enable RCFW channel with rc = 0x%x", rc);
		goto free_ring;
	}

	rc = bnxt_qplib_get_dev_attr(&rdev->rcfw, &rdev->dev_attr,
				     rdev->is_virtfn);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to query func with rc = 0x%x", rc);
		goto disable_rcfw;
	}

	if (!rdev->is_virtfn) {
		bnxt_re_set_resource_limits(rdev);
	}

	rc = bnxt_qplib_alloc_ctx(rdev->en_dev->pdev, &rdev->qplib_ctx,
				  rdev->is_virtfn);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to allocate context with rc = 0x%x", rc);
		goto disable_rcfw;
	}
	rc = bnxt_re_net_stats_ctx_alloc(rdev,
					 rdev->qplib_ctx.stats.dma_map,
					 &rdev->qplib_ctx.stats.fw_id);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to allocate stats ctx rc = 0x%x", rc);
		goto free_ctx;
	}

	rc = bnxt_qplib_init_rcfw(&rdev->rcfw, &rdev->qplib_ctx,
				  rdev->is_virtfn);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Failed to initialize fw with rc = 0x%x", rc);
		goto free_sctx;
	}
	set_bit(BNXT_RE_FLAG_RCFW_CHANNEL_EN, &rdev->flags);

	/* Resources based on the 'new' device caps */
	rc = bnxt_re_alloc_res(rdev);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"dev open failed to alloc resc rc = 0x%x", rc);
		goto fail;
	}
	rc = bnxt_re_init_res(rdev);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"dev open failed to init hw rc = 0x%x", rc);
		goto fail;
	}
/*
	rc = bnxt_re_init_nq(rdev);
	if (rc) {
		dev_err(NULL, "%s: dev open failed to init irq rc = 0x%x",
			ROCE_DRV_MODULE_NAME, rc);
		goto fail;
	}
*/

#ifdef DISABLE_TIM_BLOCK
	if (!bnxt_re_net_reg_read(rdev, TIM_REG_TIM_EN, 1, &val)) {
		bnxt_re_net_reg_write(rdev, TIM_REG_TIM_EN, 0);
		BNXT_RE_DBG1(rdev, "TIM disabled");
	}
#endif
	if (!rdev->is_virtfn) {

		rc = bnxt_re_setup_qos(rdev);
		if (rc)
			dev_warn(rdev_to_dev(rdev),
				 "QoS init failed, may not be functional.\n");

		INIT_DELAYED_WORK(&rdev->worker, bnxt_re_worker);
		set_bit(BNXT_RE_FLAG_QOS_WORK_REG, &rdev->flags);
		schedule_delayed_work(&rdev->worker, msecs_to_jiffies(30000));
	}

	/* Register ib dev */
	rc = bnxt_re_register_ib(rdev);
	if (rc) {
		dev_err(rdev_to_dev(rdev),
			"Register IB failed with rc = 0x%x", rc);
		goto fail;
	}
	dev_info(rdev_to_dev(rdev), "Device registered successfully");
	for (i = 0; i < ARRAY_SIZE(bnxt_re_attributes); i++) {
		rc = device_create_file(&rdev->ibdev.dev,
					bnxt_re_attributes[i]);
		if (rc) {
			dev_err(rdev_to_dev(rdev),
				"Failed to create IB sysfs with rc = 0x%x", rc);
			/* Must clean up all created device files */
			for (j = 0; j < i; j++)
				device_remove_file(&rdev->ibdev.dev,
						   bnxt_re_attributes[j]);
			bnxt_re_unregister_ib(rdev);
			goto fail;
		}
	}
	set_bit(BNXT_RE_FLAG_IBDEV_REGISTERED, &rdev->flags);
	bnxt_re_dispatch_event(&rdev->ibdev, NULL, 1, IB_EVENT_PORT_ACTIVE);
	bnxt_re_dispatch_event(&rdev->ibdev, NULL, 1, IB_EVENT_GID_CHANGE);
	return 0;
free_sctx:
	bnxt_re_net_stats_ctx_free(rdev, rdev->qplib_ctx.stats.fw_id, true);

free_ctx:
	bnxt_qplib_free_ctx(rdev->en_dev->pdev, &rdev->qplib_ctx);
disable_rcfw:
	bnxt_qplib_disable_rcfw_channel(&rdev->rcfw);
free_ring:
	bnxt_re_net_ring_free(rdev, rdev->rcfw.creq_ring_id, true);
free_rcfw:
	bnxt_qplib_free_rcfw_channel(&rdev->rcfw);
fail:
	bnxt_re_ib_unreg(rdev, true);
done:
	return rc;
}

static int bnxt_re_dev_unreg(struct bnxt_re_dev *rdev)
{
	struct bnxt_en_dev *en_dev = rdev->en_dev;
	struct net_device *netdev = rdev->netdev;
	int rc = 0;

	bnxt_re_dev_remove(rdev);

	if (netdev)
		bnxt_re_dev_unprobe(netdev, en_dev);

	return rc;
}

static int bnxt_re_dev_reg(struct bnxt_re_dev **rdev, struct net_device *netdev)
{
	struct bnxt_en_dev *en_dev;
	int rc = 0;

	if (is_bnxt_re_dev(netdev) == false) {
		dev_dbg(NULL, "%s: netdev %p doesn't support bnxt_re",
			 ROCE_DRV_MODULE_NAME, netdev);
		rc = -EINVAL;
		goto exit;
	}

	en_dev = bnxt_re_dev_probe(netdev);
	if (IS_ERR(en_dev)) {
		if (en_dev != ERR_PTR(-ENODEV))
			dev_info(NULL, "%s: Device probe failed",
				 ROCE_DRV_MODULE_NAME);
		return PTR_ERR(en_dev);
	}
	*rdev = bnxt_re_dev_add(netdev, en_dev);
	if (!*rdev) {
		dev_err(NULL, "%s: netdev %p not handled",
			ROCE_DRV_MODULE_NAME, netdev);
		rc = -ENOMEM;
		bnxt_re_dev_unprobe(netdev, en_dev);
		goto exit;
	}
	bnxt_re_hold(*rdev);
exit:
	return rc;
}

static void bnxt_re_remove_one(struct bnxt_re_dev *rdev)
{
	pci_dev_put(rdev->en_dev->pdev);
	if (test_and_clear_bit(BNXT_RE_FLAG_HAVE_L2_REF, &rdev->flags))
		module_put(rdev->en_dev->pdev->driver->driver.owner);
}

static void bnxt_re_get_link_speed(struct bnxt_re_dev *rdev)
{
#ifdef HAVE_ETHTOOL_GLINKSETTINGS_25G
	struct ethtool_link_ksettings lksettings;
#else
	struct ethtool_cmd ecmd;
#endif
	struct net_device *netdev = rdev->netdev;

#ifdef HAVE_ETHTOOL_GLINKSETTINGS_25G
	if (netdev->ethtool_ops && netdev->ethtool_ops->get_link_ksettings) {
		memset(&lksettings, 0, sizeof(lksettings));
		if (rtnl_trylock()) {
			netdev->ethtool_ops->get_link_ksettings(netdev, &lksettings);
			rdev->espeed = lksettings.base.speed;
			rtnl_unlock();
		}
	}
#else
	if (netdev->ethtool_ops && netdev->ethtool_ops->get_settings) {
		memset(&ecmd, 0, sizeof(ecmd));
		if (rtnl_trylock()) {
			netdev->ethtool_ops->get_settings(netdev, &ecmd);
			rdev->espeed = ecmd.speed;
			rtnl_unlock();
		}
	}
#endif
}

/* Handle all deferred netevents tasks */
static void bnxt_re_task(struct work_struct *work)
{
	struct bnxt_re_dev *rdev;
	struct bnxt_re_work *re_work;

	int rc = 0;

	re_work = container_of(work, struct bnxt_re_work, work);
	rdev = re_work->rdev;

	if (re_work->event != NETDEV_REGISTER &&
	    !test_bit(BNXT_RE_FLAG_IBDEV_REGISTERED, &rdev->flags))
		goto done;

	dev_dbg(rdev_to_dev(rdev), "Scheduled work for event 0x%lx",
		re_work->event);
	switch (re_work->event) {
	case NETDEV_REGISTER:
			rc = bnxt_re_ib_reg(rdev);
			bnxt_re_get_link_speed(rdev);
			smp_mp__before_atomic();
			clear_bit(BNXT_RE_FLAG_NETDEV_REG_IN_PROG,
				  &rdev->flags);
			if (rc)
				dev_err(rdev_to_dev(rdev),
					"Failed to register rc = 0x%x", rc);
			break;
	case NETDEV_UP:
			if (re_work->vlan_dev) {
#ifndef STACK_MANAGES_GID
				bnxt_qplib_netdev_add_gid(
						&rdev->qplib_res.sgid_tbl,
						re_work->vlan_dev);
				bnxt_re_dispatch_event(&rdev->ibdev, NULL, 1,
						       IB_EVENT_GID_CHANGE);
#endif
			} else {
				bnxt_re_dispatch_event(&rdev->ibdev, NULL, 1,
						       IB_EVENT_PORT_ACTIVE);
			}
			break;

	case NETDEV_DOWN:
			bnxt_re_dev_stop(rdev);
			break;

	case NETDEV_CHANGEADDR:
			/* MAC addr change event */
			if (re_work->vlan_dev)
				break;
			break;
	case NETDEV_CHANGE:
			if (!netif_carrier_ok(rdev->netdev)) {
				dev_info(rdev_to_dev(rdev),
					 "Adapter link is DOWN");
				bnxt_re_dev_stop(rdev);
			} else if (netif_carrier_ok(rdev->netdev)) {
				dev_info(rdev_to_dev(rdev),
					 "Adapter link is UP");
				bnxt_re_dispatch_event(&rdev->ibdev, NULL, 1,
						       IB_EVENT_PORT_ACTIVE);
			}
			bnxt_re_get_link_speed(rdev);
			break;
	default:
			break;
	}
done:
	kfree(re_work);
}

static void bnxt_re_init_one(struct bnxt_re_dev *rdev)
{
	struct pci_dev *pdev = rdev->en_dev->pdev;

	if (pdev->driver) {
		try_module_get(pdev->driver->driver.owner);
		set_bit(BNXT_RE_FLAG_HAVE_L2_REF, &rdev->flags);
	}
	pci_dev_get(pdev);
}

/*
    "Notifier chain callback can be invoked for the same chain from
    different CPUs at the same time".

    For cases when the netdev is already present, our call to the
    register_netdevice_notifier() will actually get the rtnl_lock()
    before sending NETDEV_REGISTER and (if up) NETDEV_UP
    events.

    But for cases when the netdev is not already present, the notifier
    chain is subjected to be invoked from different CPUs simultaneously.

    This is protected by the netdev_mutex.
*/
static int bnxt_re_netdev_event(struct notifier_block *notifier,
				unsigned long event, void *ptr)
{
	struct bnxt_re_dev *rdev;
#ifdef HAVE_NETDEV_NOTIFIER_INFO_TO_DEV
	struct net_device *real_dev, *netdev = netdev_notifier_info_to_dev(ptr);
#else
	struct net_device *real_dev, *netdev = ptr;
#endif
	struct bnxt_re_work *re_work;
	int rc = 0;

	real_dev = rdma_vlan_dev_real_dev(netdev);
	if (!real_dev)
		real_dev = netdev;

	rdev = bnxt_re_from_netdev(real_dev);
	if (rdev) {
		bnxt_re_hold(rdev);
	} else {
		if (event != NETDEV_REGISTER) {
			dev_dbg(NULL,
				"%s: NETDEV_%s (netdev %p) doesn't belong ",
				ROCE_DRV_MODULE_NAME, bnxt_re_netevent(event),
				real_dev);
			dev_dbg(NULL, "%s: to bnxt_re", ROCE_DRV_MODULE_NAME);
			goto exit;
		}
	}
	dev_dbg(NULL, "%s: NETDEV_%s recv'd on device 0x%p/0x%p",
		ROCE_DRV_MODULE_NAME, bnxt_re_netevent(event), netdev,
		real_dev);

	if (real_dev != netdev) {
		switch (event) {
		case NETDEV_UP:
			goto sch_work;
		case NETDEV_DOWN:
#ifndef STACK_MANAGES_GID
			if (test_bit(BNXT_RE_FLAG_IBDEV_REGISTERED,
				     &rdev->flags)) {
				bnxt_qplib_netdev_del_gid(
					&rdev->qplib_res.sgid_tbl, netdev);
				bnxt_re_dispatch_event(&rdev->ibdev, NULL, 1,
						       IB_EVENT_GID_CHANGE);
			}
#endif
			break;
		default:
			break;
		}
		goto done;
	}
	switch (event) {
	case NETDEV_REGISTER:
		if (rdev) {
			dev_dbg(rdev_to_dev(rdev),
				"NETDEV_%s (netdev %p), is already registered",
				 bnxt_re_netevent(event), real_dev);
			break;
		}
		rc = bnxt_re_dev_reg(&rdev, real_dev);
		if (rc) {
			dev_dbg(NULL, "NETDEV_%s (netdev %p) failed to ",
				bnxt_re_netevent(event), real_dev);
			dev_dbg(NULL, "register rc = 0x%x", rc);
			break;
		}
		bnxt_re_init_one(rdev);
		set_bit(BNXT_RE_FLAG_NETDEV_REG_IN_PROG, &rdev->flags);
		goto sch_work;

	case NETDEV_UNREGISTER:
		/* netdev notifier will call NETDEV_UNREGISTER again later since
		 * we are still holding the reference to the netdev
		 */
		if (test_bit(BNXT_RE_FLAG_NETDEV_REG_IN_PROG, &rdev->flags))
			goto done;
		bnxt_re_ib_unreg(rdev, false);
		bnxt_re_remove_one(rdev);
		rc = bnxt_re_dev_unreg(rdev);
		if (rc)
			dev_err(rdev_to_dev(rdev),
				"Failed to unreg rc = 0x%x", rc);
		goto exit;

	default:
sch_work:
		/* Allocate for the deferred task */
		re_work = kzalloc(sizeof(*re_work), GFP_ATOMIC);
		if (!re_work) {
			dev_dbg(rdev_to_dev(rdev),
				"NETDEV_%s Failed to allocate work",
				bnxt_re_netevent(event));
			break;
		}
		re_work->rdev = rdev;
		re_work->event = event;
		re_work->vlan_dev = (real_dev == netdev ? NULL : netdev);
		INIT_WORK(&re_work->work, bnxt_re_task);
		queue_work(bnxt_re_wq, &re_work->work);
		break;
	}
done:
	if (rdev)
		bnxt_re_put(rdev);
exit:
	return NOTIFY_DONE;
}

static struct notifier_block bnxt_re_netdev_notifier = {
	.notifier_call = bnxt_re_netdev_event
};

#ifndef STACK_MANAGES_GID
static int bnxt_re_addr_event(struct net_device *netdev, unsigned long event,
			      union ib_gid *gid)
{
	struct bnxt_re_dev *rdev;
	struct net_device *real_dev;
	u16 vlan_id = 0xFFFF;
	u32 idx;
	int rc = 0;

	real_dev = rdma_vlan_dev_real_dev(netdev);
	if (real_dev)
		vlan_id = vlan_dev_vlan_id(netdev);
	else
		real_dev = netdev;

	rdev = bnxt_re_from_netdev(real_dev);
	if (rdev) {
		bnxt_re_hold(rdev);
	} else {
		dev_dbg(rdev_to_dev(rdev),
			"NETDEV_%s (inet %p) doesn't belong to bnxt_re",
			bnxt_re_netevent(event), real_dev);
		goto done;
	}
	if (!test_bit(BNXT_RE_FLAG_IBDEV_REGISTERED, &rdev->flags)) {
		dev_dbg(rdev_to_dev(rdev),
			"NETDEV_%s (inet %p) IBDEV is not registered",
			bnxt_re_netevent(event), real_dev);
		goto fail;
	}
	dev_dbg(rdev_to_dev(rdev), "NETDEV_%s (inet %p/%p) addr event recv'd",
		bnxt_re_netevent(event), netdev, real_dev);
	switch (event) {
	case NETDEV_UP:
		rc = bnxt_qplib_add_sgid(&rdev->qplib_res.sgid_tbl,
					 (struct bnxt_qplib_gid *)gid,
					 netdev->dev_addr, vlan_id, true, &idx);
		if (rc) {
			dev_dbg(rdev_to_dev(rdev),
				"NETDEV_%s (inet %p) failed to add sgid",
				bnxt_re_netevent(event), real_dev);
			goto fail;
		}
		break;
	case NETDEV_DOWN:
		/* On older distros where stack does not manage the GIDs, we
		 * get an inet6_addr event corresponding to the IPV6/link local
		 * address when the interface is brought down.
		 * HW requires that the GID 0 entry (GID corresponding to link
		 * local address) be retained as long as the QP1 QP is present.
		 */
		if (rdma_link_local_addr((struct in6_addr *)gid))
			goto fail;
		rc = bnxt_qplib_del_sgid(&rdev->qplib_res.sgid_tbl,
					 (struct bnxt_qplib_gid *)gid, true);
		if (rc) {
			dev_dbg(rdev_to_dev(rdev),
				"NETDEV_%s (inet %p) failed to del sgid",
				bnxt_re_netevent(event), real_dev);
			goto fail;
		}
		break;
	default:
		dev_dbg(rdev_to_dev(rdev),
			"NETDEV_%s (inet %p) is not supported",
			bnxt_re_netevent(event), real_dev);
		break;
	}
	/* Notify about GID table change */
	bnxt_re_dispatch_event(&rdev->ibdev, NULL, 1, IB_EVENT_GID_CHANGE);
	/* TODO: Need to tell Bono about SGID change?
	   If so, need to queue to sp wq. */
	/* Upon sp wq completion, notify the update SGID consumer if requested */
fail:
	bnxt_re_put(rdev);
done:
	return NOTIFY_DONE;
}

static int bnxt_re_inetaddr_event(struct notifier_block *notifier,
				  unsigned long event, void *ptr)
{
	struct in_ifaddr *ifa = ptr;
	struct net_device *netdev = ifa->ifa_dev->dev;
	union ib_gid gid;

	ipv6_addr_set_v4mapped(ifa->ifa_address, (struct in6_addr *)&gid);

	return bnxt_re_addr_event(netdev, event, &gid);
}

static struct notifier_block bnxt_re_inetaddr_notifier = {
	.notifier_call = bnxt_re_inetaddr_event
};

#if IS_ENABLED(CONFIG_IPV6)
static int bnxt_re_inet6addr_event(struct notifier_block *notifier,
				   unsigned long event, void *ptr)
{
	struct inet6_ifaddr *ifa = ptr;
	union ib_gid *gid = (union ib_gid *)&ifa->addr;
	struct net_device *netdev = ifa->idev->dev;

	return bnxt_re_addr_event(netdev, event, gid);
}

static struct notifier_block bnxt_re_inet6addr_notifier = {
	.notifier_call = bnxt_re_inet6addr_event
};
#endif
#endif

static int __init bnxt_re_mod_init(void)
{
	int rc = 0;

	pr_info("%s: %s", ROCE_DRV_MODULE_NAME, version);

	bnxt_re_wq = create_singlethread_workqueue("bnxt_re");
	if (!bnxt_re_wq)
		return -ENOMEM;

#ifdef ENABLE_DEBUGFS
	bnxt_re_debugfs_init();
#endif
	INIT_LIST_HEAD(&bnxt_re_dev_list);
	adapter_count = 0;

	rc = bnxt_re_register_netdevice_notifier(&bnxt_re_netdev_notifier);
	if (rc) {
		dev_err(NULL, "%s: Cannot register to netdevice_notifier",
			ROCE_DRV_MODULE_NAME);
		goto err_netdev;
	}
#ifndef STACK_MANAGES_GID
	/* Register to the inet/6 notifier to add/del SGID entries */
	rc = register_inetaddr_notifier(&bnxt_re_inetaddr_notifier);
	if (rc) {
		dev_err(NULL, "%s: Cannot register to inetaddr_notifier",
			ROCE_DRV_MODULE_NAME);
		goto err_inetaddr;
	}
#if IS_ENABLED(CONFIG_IPV6)
	rc = register_inet6addr_notifier(&bnxt_re_inet6addr_notifier);
	if (rc) {
		dev_err(NULL, "%s: Cannot register to inet6addr_notifier",
			ROCE_DRV_MODULE_NAME);
		goto err_inet6addr;
	}
#endif
#endif
	return 0;

#ifndef STACK_MANAGES_GID
err_inet6addr:
	unregister_inetaddr_notifier(&bnxt_re_inetaddr_notifier);
err_inetaddr:
	bnxt_re_unregister_netdevice_notifier(&bnxt_re_netdev_notifier);
#endif
err_netdev:
#ifdef ENABLE_DEBUGFS
	bnxt_re_debugfs_remove();
#endif
	destroy_workqueue(bnxt_re_wq);

	return rc;
}

static void __exit bnxt_re_mod_exit(void)
{
	struct bnxt_re_dev *rdev, *next;
	LIST_HEAD(to_be_deleted);

	/* Free all adapter allocated resources */
	mutex_lock(&bnxt_re_dev_lock);
	if (!list_empty(&bnxt_re_dev_list))
		list_splice_init(&bnxt_re_dev_list, &to_be_deleted);
	mutex_unlock(&bnxt_re_dev_lock);

	/*
	 * Can use the new list without protection. There is a window
	 * in which if any device gets added while module is unloading
	 * can cause a crash. TODO: Handle this condition.
	 */

	/*
	 * Cleanup the devices in reverse order so that the VF device
	 * cleanup is done before PF cleanup
	 */
	list_for_each_entry_safe_reverse(rdev, next, &to_be_deleted, list) {
		dev_dbg(rdev_to_dev(rdev), "Unregistering Device");
		bnxt_re_dev_stop(rdev);
		bnxt_re_ib_unreg(rdev, true);
		bnxt_re_remove_one(rdev);
		bnxt_re_dev_unreg(rdev);
	}


#ifndef STACK_MANAGES_GID
#if IS_ENABLED(CONFIG_IPV6)
	unregister_inet6addr_notifier(&bnxt_re_inet6addr_notifier);
#endif
	unregister_inetaddr_notifier(&bnxt_re_inetaddr_notifier);
#endif
	bnxt_re_unregister_netdevice_notifier(&bnxt_re_netdev_notifier);

	if (adapter_count)
		dev_warn(NULL, "%s: Mod exit failed to free all adapters!",
			 ROCE_DRV_MODULE_NAME);
#ifdef ENABLE_DEBUGFS
	bnxt_re_debugfs_remove();
#endif
	if (bnxt_re_wq)
		destroy_workqueue(bnxt_re_wq);
}

module_init(bnxt_re_mod_init);
module_exit(bnxt_re_mod_exit);
