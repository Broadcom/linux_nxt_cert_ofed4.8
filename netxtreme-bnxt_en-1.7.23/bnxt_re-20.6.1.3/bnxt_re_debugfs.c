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
 * Description: DebugFS specifics
 */

#include <linux/module.h>
#include <linux/interrupt.h>
#include <linux/debugfs.h>
#include <linux/seq_file.h>
#include <linux/netdevice.h>

#include <rdma/ib_verbs.h>
#include "roce_hsi.h"
#include "bnxt_ulp.h"
#include "bnxt_qplib_res.h"
#include "bnxt_qplib_sp.h"
#include "bnxt_qplib_fp.h"
#include "bnxt_qplib_rcfw.h"

#include "bnxt_re.h"
#include "bnxt_re_debugfs.h"

#ifdef ENABLE_DEBUGFS
extern struct list_head bnxt_re_dev_list;
extern u32 adapter_count;
extern struct mutex bnxt_re_dev_lock;

static struct dentry *bnxt_re_debugfs_root;
static struct dentry *bnxt_re_debugfs_info;

#if 0
static void bnxt_debugfs_add_stats(struct bnx2fc_tgt_dbg_stats *stats,
				   struct bnx2fc_rport *tgt)
{
	stats->num_cmd_timeouts		   += tgt->stats.num_cmd_timeouts;
	stats->num_eh_abort_timeouts       += tgt->stats.num_eh_abort_timeouts;
	stats->num_abts_timeouts	   += tgt->stats.num_abts_timeouts;
	stats->num_explicit_logos	   += tgt->stats.num_explicit_logos;
	stats->num_io_compl_before_abts    +=
					    tgt->stats.num_io_compl_before_abts;
	stats->num_els_abts_timeouts       += tgt->stats.num_els_abts_timeouts;
	stats->num_els_timeouts		   += tgt->stats.num_els_timeouts;
	stats->num_rrq_issued		   += tgt->stats.num_rrq_issued;
	stats->num_cleanup_issued	   += tgt->stats.num_cleanup_issued;
	stats->num_cleanup_compl	   += tgt->stats.num_cleanup_compl;
	stats->num_rec_issued		   += tgt->stats.num_rec_issued;
	stats->num_rec_compl		   += tgt->stats.num_rec_compl;
	stats->num_srr_issued		   += tgt->stats.num_srr_issued;
	stats->num_srr_compl		   += tgt->stats.num_srr_compl;
	stats->num_seq_cleanup_issued      += tgt->stats.num_seq_cleanup_issued;
	stats->num_seq_cleanup_compl       += tgt->stats.num_seq_cleanup_compl;
	stats->num_cmd_lost		   += tgt->stats.num_cmd_lost;
	stats->num_rsp_lost		   += tgt->stats.num_rsp_lost;
	stats->num_data_lost		   += tgt->stats.num_data_lost;
	stats->num_xfer_rdy_lost	   += tgt->stats.num_xfer_rdy_lost;
	stats->num_pending_ios_after_flush +=
					 tgt->stats.num_pending_ios_after_flush;
	stats->num_unsol_requests	   += tgt->stats.num_unsol_requests;
	stats->num_adisc_issued		   += tgt->stats.num_adisc_issued;
}

static void bnx2fc_debugfs_print_stats(struct seq_file *s,
				       struct bnx2fc_tgt_dbg_stats *stats)
{
	seq_printf(s, "\t\t-----[ Timeouts ]-------------------------------\n");
	seq_printf(s, "%50s: %10d\n", "Cmd timeouts",
				      stats->num_cmd_timeouts);
	seq_printf(s, "%50s: %10d\n", "EH Abort Timeouts",
				      stats->num_eh_abort_timeouts);
	seq_printf(s, "%50s: %10d\n", "Abts Timeouts",
				      stats->num_abts_timeouts);
	seq_printf(s, "%50s: %10d\n", "ELS abts timeouts",
				      stats->num_els_abts_timeouts);
	seq_printf(s, "%50s: %10d\n", "ELS timeouts",
				      stats->num_els_timeouts);

	seq_printf(s, "\t\t-----[ Error Handling ]-------------------------\n");
	seq_printf(s, "%50s: %10d\n", "Explicit Logos",
				      stats->num_explicit_logos);
	seq_printf(s, "%50s: %10d\n", "Io completes before abts issue",
				      stats->num_io_compl_before_abts);
	seq_printf(s, "%50s: %10d\n", "RRQ Issued", stats->num_rrq_issued);
	seq_printf(s, "%50s: %10d/%d\n", "Cleanup Issued/Completion",
					 stats->num_cleanup_issued,
					 stats->num_cleanup_compl);
	seq_printf(s, "%50s: %10d/%d\n", "REC Issued/Completion",
					 stats->num_rec_issued,
					 stats->num_rec_compl);
	seq_printf(s, "%50s: %10d/%d\n", "SRR Issued/Completion",
					 stats->num_srr_issued,
					 stats->num_srr_compl);
	seq_printf(s, "%50s: %10d/%d\n", "SEQ Cleanup Issued/Completion",
					 stats->num_seq_cleanup_issued,
					 stats->num_seq_cleanup_compl);

	seq_printf(s, "\t\t-----[ Lost Packets ]---------------------------\n");
	seq_printf(s, "%50s: %10d\n", "CMDs Lost", stats->num_cmd_lost);
	seq_printf(s, "%50s: %10d\n", "RSP Lost", stats->num_rsp_lost);
	seq_printf(s, "%50s: %10d\n", "Data Lost", stats->num_data_lost);
	seq_printf(s, "%50s: %10d\n", "Xfer RDY Lost",
				      stats->num_xfer_rdy_lost);

	seq_printf(s, "\t\t-----[ Misc ]-----------------------------------\n");
	seq_printf(s, "%50s: %10d\n", "num_pending_ios_after_flush",
				      stats->num_pending_ios_after_flush);
	seq_printf(s, "%50s: %10d\n", "num_unsol_requests",
				      stats->num_unsol_requests);
	seq_printf(s, "%50s: %10d\n", "num_adisc_issued",
				      stats->num_adisc_issued);
	seq_printf(s, "\n");
}

/* bnx2fc_debugfs_sync_stat - Adds the stats from the tgt structure to the hba
 * aggregate structure. If the hba does not contain the port from a previous
 * upload, a new structure is created. Called when a tgt is being uploaded.
 *
 * @hba:	The parent hba of tgt
 * @tgt:	The tgt that is being uploaded
 */
void bnx2fc_debugfs_sync_stat(struct bnx2fc_hba *hba, struct bnx2fc_rport *tgt)
{
	struct list_head *list;
	struct bnx2fc_tgt_dbg_stats *stats = NULL;

	spin_lock_bh(&hba->hba_lock);
	list_for_each(list, &hba->bnx2fc_stat_list) {
		struct bnx2fc_tgt_dbg_stats *tmp =
					    (struct bnx2fc_tgt_dbg_stats *)list;

		if (tmp->port_id == tgt->rport->port_id) {
			stats = tmp;
			break;
		}
	}

	if (!stats) {
		stats = kzalloc(sizeof(struct bnx2fc_tgt_dbg_stats),
				    GFP_ATOMIC);
		if (!stats)
			goto unlock;

		stats->port_id = tgt->rport->port_id;
		list_add_tail(&stats->list, &hba->bnx2fc_stat_list);
	}

	bnx2fc_debugfs_add_stats(stats, tgt);

unlock:
	spin_unlock_bh(&hba->hba_lock);
}

static void bnx2fc_debugfs_print_tgt(struct seq_file *s,
				     struct bnx2fc_rport *tgt)
{
	struct bnx2fc_tgt_dbg_stats *dbg = &tgt->stats;
	seq_printf(s, "%50s: %10d\n", "fcoe_conn_id", tgt->fcoe_conn_id);
	seq_printf(s, "%50s: %#10x\n", "sid", tgt->sid);
	seq_printf(s, "%50s: %#10lx\n", "flags", tgt->flags);
	seq_printf(s, "%50s: %10d\n", "free_sqes",
				      atomic_read(&tgt->free_sqes));
	seq_printf(s, "%50s: %10d\n", "num_active_ios",
				      atomic_read(&tgt->num_active_ios));
	seq_printf(s, "%50s: %10d\n", "Flush_in_prog", tgt->flush_in_prog);
	bnx2fc_debugfs_print_stats(s, dbg);
}
#endif

static ssize_t bnxt_re_debugfs_clear(struct file *fil, const char __user *u,
				     size_t size, loff_t *off)
{
	/* TODO: Add support for debugfs parameter clearing */
	return size;
}

static int bnxt_re_debugfs_show(struct seq_file *s, void *unused)
{
	struct bnxt_re_dev *rdev;

	seq_printf(s, "bnxt_re debug info:\n");
	seq_printf(s, "Adapter count:  %d\n", adapter_count);

	mutex_lock(&bnxt_re_dev_lock);
	list_for_each_entry(rdev, &bnxt_re_dev_list, list) {
		struct ctx_hw_stats *stats = rdev->qplib_ctx.stats.dma;

		seq_printf(s, "=====[ IBDEV %s ]=============================\n",
			   rdev->ibdev.name);
		if (rdev->netdev)
			seq_printf(s, "\tlink state: %s\n",
				   test_bit(__LINK_STATE_START,
					    &rdev->netdev->state) ?
				   (test_bit(__LINK_STATE_NOCARRIER,
					     &rdev->netdev->state) ?
				    "DOWN" : "UP") : "DOWN");
		seq_printf(s, "\tMax QP: 0x%x\n", rdev->dev_attr.max_qp);
		seq_printf(s, "\tMax SRQ: 0x%x\n", rdev->dev_attr.max_srq);
		seq_printf(s, "\tMax CQ: 0x%x\n", rdev->dev_attr.max_cq);
		seq_printf(s, "\tMax MR: 0x%x\n", rdev->dev_attr.max_mr);
		seq_printf(s, "\tMax MW: 0x%x\n", rdev->dev_attr.max_mw);

		seq_printf(s, "\tActive QP: %d\n",
			   atomic_read(&rdev->qp_count));
		seq_printf(s, "\tActive SRQ: %d\n",
			   atomic_read(&rdev->srq_count));
		seq_printf(s, "\tActive CQ: %d\n",
			   atomic_read(&rdev->cq_count));
		seq_printf(s, "\tActive MR: %d\n",
			   atomic_read(&rdev->mr_count));
		seq_printf(s, "\tActive MW: %d\n",
			   atomic_read(&rdev->mw_count));
		seq_printf(s, "\tRx Pkts: %lld\n",
			   stats ? stats->rx_ucast_pkts : 0);
		seq_printf(s, "\tRx Bytes: %lld\n",
			   stats ? stats->rx_ucast_bytes : 0);
		seq_printf(s, "\tTx Pkts: %lld\n",
			   stats ? stats->tx_ucast_pkts : 0);
		seq_printf(s, "\tTx Bytes: %lld\n",
			   stats ? stats->tx_ucast_bytes : 0);
		seq_printf(s, "\tRecoverable Errors: %lld\n",
			   stats ? stats->tx_bcast_pkts : 0);
		seq_printf(s, "\n");
	}
	mutex_unlock(&bnxt_re_dev_lock);
	return 0;
}

static int bnxt_re_debugfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, bnxt_re_debugfs_show, NULL);
}

static int bnxt_re_debugfs_release(struct inode *inode, struct file *file)
{
	return single_release(inode, file);
}

static const struct file_operations bnxt_re_dbg_ops = {
	.owner		= THIS_MODULE,
	.open		= bnxt_re_debugfs_open,
	.read		= seq_read,
	.write		= bnxt_re_debugfs_clear,
	.llseek		= seq_lseek,
	.release	= bnxt_re_debugfs_release,
};

void bnxt_re_debugfs_remove(void)
{
	debugfs_remove_recursive(bnxt_re_debugfs_root);
	bnxt_re_debugfs_root = NULL;
}

void bnxt_re_debugfs_init(void)
{
	bnxt_re_debugfs_root = debugfs_create_dir(ROCE_DRV_MODULE_NAME, NULL);
	if (IS_ERR_OR_NULL(bnxt_re_debugfs_root)) {
		dev_dbg(NULL, "%s: Unable to create debugfs root directory ",
			ROCE_DRV_MODULE_NAME);
		dev_dbg(NULL, "with err 0x%lx", PTR_ERR(bnxt_re_debugfs_root));
		return;
	}
	bnxt_re_debugfs_info = debugfs_create_file("info", S_IRUSR,
						   bnxt_re_debugfs_root, NULL,
						   &bnxt_re_dbg_ops);
	if (IS_ERR_OR_NULL(bnxt_re_debugfs_info)) {
		dev_dbg(NULL, "%s: Unable to create debugfs info node ",
			ROCE_DRV_MODULE_NAME);
		dev_dbg(NULL, "with err 0x%lx", PTR_ERR(bnxt_re_debugfs_info));
		bnxt_re_debugfs_remove();
	}
}
#endif
