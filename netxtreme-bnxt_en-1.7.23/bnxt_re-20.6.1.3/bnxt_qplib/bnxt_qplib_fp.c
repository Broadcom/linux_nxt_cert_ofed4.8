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
 * Description: Fast Path Operators
 */

#include <linux/interrupt.h>
#include <linux/spinlock.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/delay.h>

#include "roce_hsi.h"

#include "bnxt_qplib_res.h"
#include "bnxt_qplib_rcfw.h"
#include "bnxt_qplib_sp.h"
#include "bnxt_qplib_fp.h"

static void bnxt_qplib_arm_cq_enable(struct bnxt_qplib_cq *cq);
static void bnxt_qplib_arm_srq(struct bnxt_qplib_srq *srq, u32 arm_type);

/* Flush list */

#define bnxt_qplib_is_qp_in_sq_flushlist(qp) qp->sq.flushed
#define bnxt_qplib_is_qp_in_rq_flushlist(qp) qp->rq.flushed

void bnxt_qplib_add_flush_qp(struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_cq *scq, *rcq;

	scq = qp->scq;
	rcq = qp->rcq;

	spin_lock(&scq->flush_lock);
	if (!bnxt_qplib_is_qp_in_sq_flushlist(qp)) {
		dev_dbg(&scq->hwq.pdev->dev,
			"QPLIB: FP: Adding to SQ Flush list = %p",
			qp);
		list_add_tail(&qp->sq_flush, &scq->sqf_head);
		qp->sq.flushed = true;
	}
	spin_unlock(&scq->flush_lock);
	if (!qp->srq) {
		spin_lock(&rcq->flush_lock);
		if (!bnxt_qplib_is_qp_in_rq_flushlist(qp)) {
			dev_dbg(&rcq->hwq.pdev->dev,
				"QPLIB: FP: Adding to SQ Flush list = %p",
				qp);
			list_add_tail(&qp->rq_flush, &rcq->rqf_head);
			qp->rq.flushed = true;
		}
		spin_unlock(&rcq->flush_lock);
	}
}

void bnxt_qplib_del_flush_qp(struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_cq *scq, *rcq;

	scq = qp->scq;
	rcq = qp->rcq;

	spin_lock(&scq->flush_lock);
	if (bnxt_qplib_is_qp_in_sq_flushlist(qp)) {
		qp->sq.flushed = false;
		list_del(&qp->sq_flush);
	}
	spin_unlock(&scq->flush_lock);
	if (!qp->srq) {
		spin_lock(&rcq->flush_lock);
		if (bnxt_qplib_is_qp_in_rq_flushlist(qp)) {
			qp->rq.flushed = false;
			list_del(&qp->rq_flush);
		}
		spin_unlock(&rcq->flush_lock);
	}
}

static void bnxt_qpn_cqn_sched_task(struct work_struct *work)
{
	struct bnxt_qplib_nq_work *nq_work =
			container_of(work, struct bnxt_qplib_nq_work, work);

	struct bnxt_qplib_cq *cq = nq_work->cq;
	struct bnxt_qplib_nq *nq = nq_work->nq;

	if (cq && nq) {
		spin_lock_bh(&cq->compl_lock);
		if (cq->arm_state && nq->cqn_handler) {
			dev_dbg(&nq->pdev->dev,
				"%s:Trigger cq  = %p event nq = %p\n",
				__func__, cq, nq);
			nq->cqn_handler(nq, cq);
		}
		spin_unlock_bh(&cq->compl_lock);
	}
	kfree(nq_work);
}

/* NQ */
static int bnxt_qplib_process_dbqn(struct bnxt_qplib_nq *nq,
				   struct nq_dbq_event *nqe)
{
	u32 db_xid, db_type, db_pfid, db_dpi;

	if ((nqe->event) !=
	    NQ_DBQ_EVENT_EVENT_DBQ_THRESHOLD_EVENT) {
		dev_warn(&nq->pdev->dev, "QPLIB: DBQ event 0x%x not handled",
			 nqe->event);
		return -EINVAL;
	}
	db_type = le32_to_cpu((nqe->db_type_db_xid & NQ_DBQ_EVENT_DB_TYPE_MASK)
			      >> NQ_DBQ_EVENT_DB_TYPE_SFT);
	db_xid = le32_to_cpu((nqe->db_type_db_xid & NQ_DBQ_EVENT_DB_XID_MASK)
			     >> NQ_DBQ_EVENT_DB_XID_SFT);
	db_pfid = le16_to_cpu((nqe->db_pfid & NQ_DBQ_EVENT_DB_DPI_MASK)
			      >> NQ_DBQ_EVENT_DB_DPI_SFT);
	db_dpi = le32_to_cpu((nqe->db_dpi & NQ_DBQ_EVENT_DB_DPI_MASK)
			     >> NQ_DBQ_EVENT_DB_DPI_SFT);

	dev_dbg(&nq->pdev->dev,
		"QPLIB: DBQ notification xid 0x%x type 0x%x pfid 0x%x dpi 0x%x",
		db_xid, db_type, db_pfid, db_dpi);
	return 0;
}

static int bnxt_qplib_process_srqn(struct bnxt_qplib_nq *nq,
				   struct bnxt_qplib_srq *srq, u8 event)
{
	int rc = 0;

	if (srq == NULL) {
		dev_err(&nq->pdev->dev, "QPLIB: SRQ is NULL, SRQN not handled");
		rc = -EINVAL;
		goto done;
	}
	dev_dbg(&nq->pdev->dev,
		"QPLIB: SRQN notification with event = 0x%x", event);
	/* TODO: Call the installer? */
done:
	return rc;
}

static int bnxt_qplib_process_cqn(struct bnxt_qplib_nq *nq,
				  struct bnxt_qplib_cq *cq)
{
	int rc = 0;

	if (cq == NULL) {
		dev_err(&nq->pdev->dev, "QPLIB: CQ is NULL, CQN not handled");
		rc = -EINVAL;
		goto done;
	}
	dev_dbg(&nq->pdev->dev, "QPLIB: CQN notification");
	/* TODO: Call the installer? */
done:
	return rc;
}

static void bnxt_qplib_free_qp_hdr_buf(struct bnxt_qplib_res *res,
				       struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	struct bnxt_qplib_q *sq = &qp->sq;

	if (qp->rq_hdr_buf)
		dma_free_coherent(&res->pdev->dev,
				  rq->hwq.max_elements * qp->rq_hdr_buf_size,
				  qp->rq_hdr_buf, qp->rq_hdr_buf_map);
	if (qp->sq_hdr_buf)
		dma_free_coherent(&res->pdev->dev,
				  sq->hwq.max_elements * qp->sq_hdr_buf_size,
				  qp->sq_hdr_buf, qp->sq_hdr_buf_map);
	qp->rq_hdr_buf = NULL;
	qp->sq_hdr_buf = NULL;
	qp->rq_hdr_buf_map = 0;
	qp->sq_hdr_buf_map = 0;
	qp->sq_hdr_buf_size = 0;
	qp->rq_hdr_buf_size = 0;
}

static int bnxt_qplib_alloc_qp_hdr_buf(struct bnxt_qplib_res *res,
				       struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	struct bnxt_qplib_q *sq = &qp->rq;
	int rc = 0;

	if (qp->sq_hdr_buf_size && sq->hwq.max_elements) {
		qp->sq_hdr_buf = dma_alloc_coherent(&res->pdev->dev,
					sq->hwq.max_elements *
					qp->sq_hdr_buf_size,
					&qp->sq_hdr_buf_map, GFP_KERNEL);
		if (!qp->sq_hdr_buf) {
			rc = -ENOMEM;
			dev_err(&res->pdev->dev,
				"QPLIB: Failed to create sq_hdr_buf");
			goto fail;
		}
	}

	if (qp->rq_hdr_buf_size && rq->hwq.max_elements) {
		qp->rq_hdr_buf = dma_alloc_coherent(&res->pdev->dev,
						    rq->hwq.max_elements *
						    qp->rq_hdr_buf_size,
						    &qp->rq_hdr_buf_map,
						    GFP_KERNEL);
		if (!qp->rq_hdr_buf) {
			rc = -ENOMEM;
			dev_err(&res->pdev->dev,
				"QPLIB: Failed to create rq_hdr_buf");
			goto fail;
		}
	}
	return 0;

fail:
	bnxt_qplib_free_qp_hdr_buf(res, qp);
	return rc;
}

static void bnxt_qplib_service_nq(unsigned long data)
{
	struct bnxt_qplib_nq *nq = (struct bnxt_qplib_nq *)data;
	struct bnxt_qplib_hwq *hwq = &nq->hwq;
	struct nq_base *nqe, **nq_ptr;
	struct bnxt_qplib_cq *cq;
	int num_cqne_processed = 0;
	int num_srqne_processed = 0;
	int num_dbqne_processed = 0;
	u32 sw_cons, raw_cons;
	u32 type;
	int rc, budget = nq->budget;
	u64 q_handle;

	/* Service the NQ until empty */
	raw_cons = hwq->cons;
	while (budget--) {
		sw_cons = HWQ_CMP(raw_cons, hwq);
		nq_ptr = (struct nq_base **)hwq->pbl_ptr;
		nqe = &nq_ptr[NQE_PG(sw_cons)][NQE_IDX(sw_cons)];
		if (!NQE_CMP_VALID(nqe, raw_cons, hwq->max_elements))
			break;

		type = le16_to_cpu(nqe->info10_type & NQ_BASE_TYPE_MASK);
		switch (type) {
		case NQ_BASE_TYPE_CQ_NOTIFICATION:
		{
			struct nq_cn *nqcne = (struct nq_cn *)nqe;

			q_handle = le32_to_cpu(nqcne->cq_handle_low);
			q_handle |= (u64)le32_to_cpu(nqcne->cq_handle_high) << 32;
			cq = (struct bnxt_qplib_cq *)q_handle;
			bnxt_qplib_arm_cq_enable(cq);
			spin_lock_bh(&cq->compl_lock);
			if (!nq->cqn_handler(nq, (cq)))
				num_cqne_processed++;
			else
				dev_warn(&nq->pdev->dev,
					 "QPLIB: cqn - type 0x%x not handled",
					 type);
			cq->arm_state = false;
			spin_unlock_bh(&cq->compl_lock);
			break;
		}
		case NQ_BASE_TYPE_SRQ_EVENT:
		{
			struct nq_srq_event *nqsrqe =
						(struct nq_srq_event *)nqe;

			q_handle = le32_to_cpu(nqsrqe->srq_handle_low);
			q_handle |= (u64)le32_to_cpu(nqsrqe->srq_handle_high) << 32;
			bnxt_qplib_arm_srq((struct bnxt_qplib_srq *)q_handle,
					   DBR_DBR_TYPE_SRQ_ARMENA);
			if (!nq->srqn_handler(nq,
					      (struct bnxt_qplib_srq *)q_handle,
					      nqsrqe->event))
				num_srqne_processed++;
			else
				dev_warn(&nq->pdev->dev,
					 "QPLIB: SRQ event 0x%x not handled",
					 nqsrqe->event);
			break;
		}
		case NQ_BASE_TYPE_DBQ_EVENT:
			rc = bnxt_qplib_process_dbqn(nq,
						(struct nq_dbq_event *)nqe);
			num_dbqne_processed++;
			break;
		default:
			dev_warn(&nq->pdev->dev,
				 "QPLIB: nqe with opcode = 0x%x not handled",
				 type);
			break;
		}
		raw_cons++;
	}
	if (hwq->cons != raw_cons) {
		hwq->cons = raw_cons;
		NQ_DB_REARM(nq->bar_reg_iomem, hwq->cons, hwq->max_elements);
	}
	dev_dbg(&nq->pdev->dev, "QPLIB: cqn/srqn/dbqn ");
	dev_dbg(&nq->pdev->dev,
		"QPLIB: serviced 0x%x/0x%x/0x%x budget 0x%x raw_cons 0x%x",
		num_cqne_processed, num_srqne_processed, num_dbqne_processed,
		budget, raw_cons);
}

static irqreturn_t bnxt_qplib_nq_irq(int irq, void *dev_instance)
{
	struct bnxt_qplib_nq *nq = dev_instance;
	struct bnxt_qplib_hwq *hwq = &nq->hwq;
	struct nq_base **nq_ptr;
	u32 sw_cons;

	/* TODO: Ack and ARM IRQ in HW? */

	/* Prefetch the NQ element */
	sw_cons = HWQ_CMP(hwq->cons, hwq);
	nq_ptr = (struct nq_base **)nq->hwq.pbl_ptr;
	prefetch(&nq_ptr[NQE_PG(sw_cons)][NQE_IDX(sw_cons)]);

	/* Fan out to CPU affinitized kthreads? */
	tasklet_schedule(&nq->worker);

	return IRQ_HANDLED;
}

void bnxt_qplib_disable_nq(struct bnxt_qplib_nq *nq)
{
	if (nq->cqn_wq) {
		destroy_workqueue(nq->cqn_wq);
		nq->cqn_wq = NULL;
	}
	/* Make sure the HW is stopped! */
	synchronize_irq(nq->vector);
	tasklet_disable(&nq->worker);
	tasklet_kill(&nq->worker);

	if (nq->requested == true) {
		free_irq(nq->vector, nq);
		nq->requested = false;
	}
	if (nq->bar_reg_iomem)
		iounmap(nq->bar_reg_iomem);
	nq->bar_reg_iomem = NULL;

	nq->cqn_handler = NULL;
	nq->srqn_handler = NULL;
	nq->vector = 0;
}

int bnxt_qplib_enable_nq(struct pci_dev *pdev, struct bnxt_qplib_nq *nq,
			 int msix_vector, int bar_reg_offset,
			 int (*cqn_handler)(struct bnxt_qplib_nq *nq, struct bnxt_qplib_cq *),
			 int (*srqn_handler)(struct bnxt_qplib_nq *nq, struct bnxt_qplib_srq *, u8 event))
{
	resource_size_t nq_base;
	int rc = -1;

	nq->pdev = pdev;
	nq->vector = msix_vector;
	if (cqn_handler)
		nq->cqn_handler = cqn_handler;
	else
		nq->cqn_handler = &bnxt_qplib_process_cqn;

	if (srqn_handler)
		nq->srqn_handler = srqn_handler;
	else
		nq->srqn_handler = &bnxt_qplib_process_srqn;

	tasklet_init(&nq->worker, bnxt_qplib_service_nq, (unsigned long)nq);

	/* Have a task to schedule CQ notifiers in post send case */
	nq->cqn_wq  = create_singlethread_workqueue("bnxt_qplib_nq");
	if (!nq->cqn_wq)
		goto fail;

	nq->requested = false;
	rc = request_irq(nq->vector, bnxt_qplib_nq_irq, 0, "bnxt_qplib_nq", nq);
	if (rc) {
		dev_err(&nq->pdev->dev,
			"QPLIB: Failed to request IRQ for NQ rc = 0x%x", rc);
		bnxt_qplib_disable_nq(nq);
		goto fail;
	}
	nq->requested = true;
	nq->bar_reg = NQ_CONS_PCI_BAR_REGION;
	nq->bar_reg_off = bar_reg_offset;
	nq_base = pci_resource_start(pdev, nq->bar_reg);
	if (!nq_base) {
		dev_err(&nq->pdev->dev,
			"QPLIB: NQ BAR region %d resc start is 0!",
			nq->bar_reg);
		rc = -ENOMEM;
		goto fail;
	}
	nq->bar_reg_iomem = ioremap_nocache(nq_base + nq->bar_reg_off, 4);
	if (!nq->bar_reg_iomem) {
		dev_err(&nq->pdev->dev,
			"QPLIB: NQ BAR region %d mapping failed", nq->bar_reg);
		rc = -ENOMEM;
		goto fail;
	}
	NQ_DB_REARM(nq->bar_reg_iomem, nq->hwq.cons, nq->hwq.max_elements);

	dev_dbg(&nq->pdev->dev, "QPLIB: NQ max = 0x%x", nq->hwq.max_elements);

	return 0;
fail:
	bnxt_qplib_disable_nq(nq);
	return rc;
}

void bnxt_qplib_free_nq(struct bnxt_qplib_nq *nq)
{
	if (nq->hwq.max_elements)
		bnxt_qplib_free_hwq(nq->pdev, &nq->hwq);
}

int bnxt_qplib_alloc_nq(struct pci_dev *pdev, struct bnxt_qplib_nq *nq)
{
	nq->pdev = pdev;
	if (!nq->hwq.max_elements ||
	    nq->hwq.max_elements > BNXT_QPLIB_NQE_MAX_CNT)
		nq->hwq.max_elements = BNXT_QPLIB_NQE_MAX_CNT;

	if (bnxt_qplib_alloc_init_hwq(nq->pdev, &nq->hwq, NULL, 0,
				      &nq->hwq.max_elements,
				      BNXT_QPLIB_MAX_NQE_ENTRY_SIZE, 0,
				      PAGE_SIZE, HWQ_TYPE_L2_CMPL)) {
		dev_err(&pdev->dev, "QPLIB: FP NQ allocation failed");
		return -ENOMEM;
	}
	nq->budget = 8;
	return 0;
}

/* SRQ */
void bnxt_qplib_arm_srq(struct bnxt_qplib_srq *srq, u32 arm_type)
{
	struct bnxt_qplib_hwq *srq_hwq = &srq->hwq;
	struct dbr_dbr db_msg = { 0 };
	void __iomem *db;
	u32 sw_prod = 0;

	/* Ring DB */
	sw_prod = (arm_type == DBR_DBR_TYPE_SRQ_ARM) ? srq->threshold :
		   HWQ_CMP(srq_hwq->prod, srq_hwq);
	db_msg.index = cpu_to_le32((sw_prod << DBR_DBR_INDEX_SFT) &
				   DBR_DBR_INDEX_MASK);
	db_msg.type_xid = cpu_to_le32(((srq->id << DBR_DBR_XID_SFT) &
					DBR_DBR_XID_MASK) | arm_type);
	db = (arm_type == DBR_DBR_TYPE_SRQ_ARMENA) ?
		srq->dbr_base : srq->dpi->dbr;
	wmb();
	__iowrite64_copy(db, &db_msg, sizeof(db_msg) / sizeof(u64));
}

int bnxt_qplib_destroy_srq(struct bnxt_qplib_res *res,
			   struct bnxt_qplib_srq *srq)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_destroy_srq req;
	struct creq_destroy_srq_resp resp;
	u16 cmd_flags = 0;
	int rc;

	RCFW_CMD_PREP(req, DESTROY_SRQ, cmd_flags);

	/* Configure the request */
	req.srq_cid = cpu_to_le32(srq->id);

	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
					  (void *)&resp, NULL, 0);
	if (rc)
		return rc;

	bnxt_qplib_free_hwq(res->pdev, &srq->hwq);
	if (srq->swq)
		kfree(srq->swq);
	return 0;
}

int bnxt_qplib_create_srq(struct bnxt_qplib_res *res,
			  struct bnxt_qplib_srq *srq)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_create_srq req;
	struct creq_create_srq_resp resp;
	struct bnxt_qplib_pbl *pbl;
	u16 cmd_flags = 0;
	int rc;

	srq->hwq.max_elements = srq->max_wqe;
	rc = bnxt_qplib_alloc_init_hwq(res->pdev, &srq->hwq, srq->sglist,
				       srq->nmap, &srq->hwq.max_elements,
				       BNXT_QPLIB_MAX_RQE_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_QUEUE);
	if (rc)
		goto exit;

	srq->swq = kcalloc(srq->hwq.max_elements, sizeof(*srq->swq), GFP_KERNEL);
	if (!srq->swq)
		goto fail;

	RCFW_CMD_PREP(req, CREATE_SRQ, cmd_flags);

	/* Configure the request */
	req.dpi = cpu_to_le32(srq->dpi->dpi);
	req.srq_handle = cpu_to_le64(srq);

	req.srq_size = cpu_to_le32(srq->hwq.max_elements);
	pbl = &srq->hwq.pbl[PBL_LVL_0];
	req.pg_size_lvl = cpu_to_le32(
	    ((srq->hwq.level & CMDQ_CREATE_SRQ_LVL_MASK) <<
						CMDQ_CREATE_SRQ_LVL_SFT) |
	    (pbl->pg_size == ROCE_PG_SIZE_4K ? CMDQ_CREATE_SRQ_PG_SIZE_PG_4K :
	     pbl->pg_size == ROCE_PG_SIZE_8K ? CMDQ_CREATE_SRQ_PG_SIZE_PG_8K :
	     pbl->pg_size == ROCE_PG_SIZE_64K ? CMDQ_CREATE_SRQ_PG_SIZE_PG_64K :
	     pbl->pg_size == ROCE_PG_SIZE_2M ? CMDQ_CREATE_SRQ_PG_SIZE_PG_2M :
	     pbl->pg_size == ROCE_PG_SIZE_8M ? CMDQ_CREATE_SRQ_PG_SIZE_PG_8M :
	     pbl->pg_size == ROCE_PG_SIZE_1G ? CMDQ_CREATE_SRQ_PG_SIZE_PG_1G :
	     CMDQ_CREATE_SRQ_PG_SIZE_PG_4K));

	req.pbl = cpu_to_le64(pbl->pg_map_arr[0]);
	req.pd_id = cpu_to_le32(srq->pd->id);
	req.eventq_id = cpu_to_le16(srq->eventq_hw_ring_id);

	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
					  (void *)&resp, NULL, 0);
	if (rc)
		goto fail;
	srq->id = le32_to_cpu(resp.xid);
	srq->dbr_base = res->dpi_tbl.dbr_bar_reg_iomem;
	if (srq->threshold)
		bnxt_qplib_arm_srq(srq, DBR_DBR_TYPE_SRQ_ARMENA);
	srq->pre_count = 0;

	return 0;
fail:
	bnxt_qplib_free_hwq(res->pdev, &srq->hwq);
	if (srq->swq)
		kfree(srq->swq);
exit:
	return rc;
}

int bnxt_qplib_modify_srq(struct bnxt_qplib_res *res,
			  struct bnxt_qplib_srq *srq)
{
	/* The SRQ threshold is in the doorbell.index when the type is ARM */
	bnxt_qplib_arm_srq(srq, DBR_DBR_TYPE_SRQ_ARM);

	return 0;
}

int bnxt_qplib_query_srq(struct bnxt_qplib_res *res,
			 struct bnxt_qplib_srq *srq)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_query_srq req;
	struct creq_query_srq_resp resp;
	struct bnxt_qplib_rcfw_sbuf *sbuf;
	struct creq_query_srq_resp_sb *sb;
	u16 cmd_flags = 0;
	int rc = 0;

	RCFW_CMD_PREP(req, QUERY_SRQ, cmd_flags);

	/* Configure the request */
	sbuf = bnxt_qplib_rcfw_alloc_sbuf(rcfw, sizeof(*sb));
	if (!sbuf)
		return -ENOMEM;
	sb = sbuf->sb;
	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req, (void *)&resp,
					  (void *)sbuf, 0);
	/* TODO: What to do with the query? */
	bnxt_qplib_rcfw_free_sbuf(rcfw, sbuf);

	return rc;
}

int bnxt_qplib_post_srq_recv(struct bnxt_qplib_srq *srq,
			     struct bnxt_qplib_swqe *wqe)
{
	struct bnxt_qplib_hwq *srq_hwq = &srq->hwq;
	struct rq_wqe *srqe, **srqe_ptr;
	struct sq_sge *hw_sge;
#ifdef ENABLE_FP_SPINLOCK
	unsigned long flags;
#endif
	u32 sw_prod;
	int i, rc = 0;

#ifdef ENABLE_FP_SPINLOCK
	spin_lock_irqsave(&srq_hwq->lock, flags);
#endif
	if (HWQ_CMP((srq_hwq->prod + 1), srq_hwq) ==
	    HWQ_CMP(srq_hwq->cons, srq_hwq)) {
		dev_err(&srq_hwq->pdev->dev, "QPLIB: FP: SRQ (0x%x) is full!",
			srq->id);
		rc = -EINVAL;
		goto done;
	}
	sw_prod = HWQ_CMP(srq_hwq->prod, srq_hwq);
	srq->swq[sw_prod].wr_id = wqe->wr_id;

	srqe_ptr = (struct rq_wqe **)srq_hwq->pbl_ptr;
	srqe = &srqe_ptr[RQE_PG(sw_prod)][RQE_IDX(sw_prod)];

	memset(srqe, 0, BNXT_QPLIB_MAX_RQE_ENTRY_SIZE);

	/* Calculate wqe_size16 and data_len */
	for (i = 0, hw_sge = (struct sq_sge *)srqe->data;
	     i < wqe->num_sge; i++, hw_sge++) {
		hw_sge->va_or_pa = cpu_to_le64(wqe->sg_list[i].addr);
		hw_sge->l_key = cpu_to_le32(wqe->sg_list[i].lkey);
		hw_sge->size = cpu_to_le32(wqe->sg_list[i].size);
	}
	srqe->wqe_type = wqe->type;
	srqe->flags = wqe->flags;
	srqe->wqe_size = wqe->num_sge +
			((offsetof(typeof(*srqe), data) + 15) >> 4);
	srqe->wr_id[0] = cpu_to_le32(sw_prod);

	wmb();

	/* Ring DB */
	srq_hwq->prod++;
	bnxt_qplib_arm_srq(srq, DBR_DBR_TYPE_SRQ);
	if ((srq->pre_count < srq->max_wqe) &&
	    (++srq->pre_count > srq->threshold)) {
		srq->pre_count = srq->max_wqe;
		bnxt_qplib_arm_srq(srq, DBR_DBR_TYPE_SRQ_ARM);
	}
done:
#ifdef ENABLE_FP_SPINLOCK
	spin_unlock_irqrestore(&srq_hwq->lock, flags);
#endif
	return rc;
}

/* QP */
int bnxt_qplib_create_qp1(struct bnxt_qplib_res *res, struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_create_qp1 req;
	struct creq_create_qp1_resp resp;
	struct bnxt_qplib_pbl *pbl;
	struct bnxt_qplib_q *sq = &qp->sq;
	struct bnxt_qplib_q *rq = &qp->rq;
	int rc;
	u16 cmd_flags = 0;
	u32 qp_flags = 0;

	RCFW_CMD_PREP(req, CREATE_QP1, cmd_flags);

	/* General */
	req.type = qp->type;
	req.dpi = cpu_to_le32(qp->dpi->dpi);
	req.qp_handle = cpu_to_le64(qp->qp_handle);

	/* SQ */
	sq->hwq.max_elements = sq->max_wqe;
	rc = bnxt_qplib_alloc_init_hwq(res->pdev, &sq->hwq, NULL, 0,
				       &sq->hwq.max_elements,
				       BNXT_QPLIB_MAX_SQE_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_QUEUE);
	if (rc)
		goto exit;

	sq->swq = kcalloc(sq->hwq.max_elements, sizeof(*sq->swq), GFP_KERNEL);
	if (!sq->swq) {
		rc = -ENOMEM;
		goto fail_sq;
	}
	pbl = &sq->hwq.pbl[PBL_LVL_0];
	req.sq_pbl = cpu_to_le64(pbl->pg_map_arr[0]);
	req.sq_pg_size_sq_lvl =
		((sq->hwq.level & CMDQ_CREATE_QP1_SQ_LVL_MASK)
				<<  CMDQ_CREATE_QP1_SQ_LVL_SFT) |
		(pbl->pg_size == ROCE_PG_SIZE_4K ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_4K :
		 pbl->pg_size == ROCE_PG_SIZE_8K ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_8K :
		 pbl->pg_size == ROCE_PG_SIZE_64K ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_64K :
		 pbl->pg_size == ROCE_PG_SIZE_2M ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_2M :
		 pbl->pg_size == ROCE_PG_SIZE_8M ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_8M :
		 pbl->pg_size == ROCE_PG_SIZE_1G ?
				CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_1G :
		 CMDQ_CREATE_QP1_SQ_PG_SIZE_PG_4K);

	if (qp->scq)
		req.scq_cid = cpu_to_le32(qp->scq->id);

	qp_flags |= CMDQ_CREATE_QP1_QP_FLAGS_RESERVED_LKEY_ENABLE;

	/* RQ */
	if (rq->max_wqe) {
		rq->hwq.max_elements = qp->rq.max_wqe;
		rc = bnxt_qplib_alloc_init_hwq(res->pdev, &rq->hwq, NULL, 0,
					       &rq->hwq.max_elements,
					       BNXT_QPLIB_MAX_RQE_ENTRY_SIZE, 0,
					       PAGE_SIZE, HWQ_TYPE_QUEUE);
		if (rc)
			goto fail_sq;

		rq->swq = kcalloc(rq->hwq.max_elements, sizeof(*rq->swq),
				  GFP_KERNEL);
		if (!rq->swq) {
			rc = -ENOMEM;
			goto fail_rq;
		}
		pbl = &rq->hwq.pbl[PBL_LVL_0];
		req.rq_pbl = cpu_to_le64(pbl->pg_map_arr[0]);
		req.rq_pg_size_rq_lvl =
			((rq->hwq.level & CMDQ_CREATE_QP1_RQ_LVL_MASK) <<
			 CMDQ_CREATE_QP1_RQ_LVL_SFT) |
				(pbl->pg_size == ROCE_PG_SIZE_4K ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_4K :
				 pbl->pg_size == ROCE_PG_SIZE_8K ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_8K :
				 pbl->pg_size == ROCE_PG_SIZE_64K ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_64K :
				 pbl->pg_size == ROCE_PG_SIZE_2M ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_2M :
				 pbl->pg_size == ROCE_PG_SIZE_8M ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_8M :
				 pbl->pg_size == ROCE_PG_SIZE_1G ?
					CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_1G :
				 CMDQ_CREATE_QP1_RQ_PG_SIZE_PG_4K);
		if (qp->rcq)
			req.rcq_cid = cpu_to_le32(qp->rcq->id);
	} else {
		/* SRQ */
		if (qp->srq) {
			qp_flags |= CMDQ_CREATE_QP1_QP_FLAGS_SRQ_USED;
			req.srq_cid = cpu_to_le32(qp->srq->id);
		}
	}
	/* Header buffer - allow hdr_buf pass in */
	rc = bnxt_qplib_alloc_qp_hdr_buf(res, qp);
	if (rc) {
		rc = -ENOMEM;
		goto fail;
	}

	req.qp_flags = cpu_to_le32(qp_flags);
	req.sq_size = cpu_to_le32(sq->hwq.max_elements);
	req.rq_size = cpu_to_le32(rq->hwq.max_elements);
	req.sq_fwo_sq_sge =
		cpu_to_le16((sq->max_sge & CMDQ_CREATE_QP1_SQ_SGE_MASK) <<
			    CMDQ_CREATE_QP1_SQ_SGE_SFT);
	req.rq_fwo_rq_sge =
		cpu_to_le16((rq->max_sge & CMDQ_CREATE_QP1_RQ_SGE_MASK) <<
			    CMDQ_CREATE_QP1_RQ_SGE_SFT);
	req.pd_id = cpu_to_le32(qp->pd->id);

	rc= bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
					 (void *)&resp, NULL, 0);
	if (rc)
		goto fail;
	qp->id = le32_to_cpu(resp.xid);
	qp->cur_qp_state = CMDQ_MODIFY_QP_NEW_STATE_RESET;

	return 0;

fail:
	bnxt_qplib_free_qp_hdr_buf(res, qp);
fail_rq:
	bnxt_qplib_free_hwq(res->pdev, &rq->hwq);
	if (rq->swq)
		kfree(rq->swq);
fail_sq:
	bnxt_qplib_free_hwq(res->pdev, &sq->hwq);
	if (sq->swq)
		kfree(sq->swq);
exit:
	return rc;
}

int bnxt_qplib_create_qp(struct bnxt_qplib_res *res, struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct sq_send *hw_sq_send_hdr, **hw_sq_send_ptr;
	struct cmdq_create_qp req;
	struct creq_create_qp_resp resp;
	struct bnxt_qplib_pbl *pbl;
	struct sq_psn_search **psn_search_ptr;
	long long unsigned int psn_search, poff = 0;
	struct bnxt_qplib_q *sq = &qp->sq;
	struct bnxt_qplib_q *rq = &qp->rq;
	struct bnxt_qplib_hwq *xrrq;
	int i, rc, req_size, psn_sz;
	u16 cmd_flags = 0, max_ssge;
	u32 sw_prod, qp_flags = 0;

	RCFW_CMD_PREP(req, CREATE_QP, cmd_flags);

	/* General */
	req.type = qp->type;
	req.dpi = cpu_to_le32(qp->dpi->dpi);
	req.qp_handle = cpu_to_le64(qp->qp_handle);

	/* SQ */
	psn_sz = (qp->type == CMDQ_CREATE_QP_TYPE_RC) ?
		 sizeof(struct sq_psn_search) : 0;
	sq->hwq.max_elements = sq->max_wqe;
	rc = bnxt_qplib_alloc_init_hwq(res->pdev, &sq->hwq, sq->sglist,
				       sq->nmap, &sq->hwq.max_elements,
				       BNXT_QPLIB_MAX_SQE_ENTRY_SIZE,
				       psn_sz,
				       PAGE_SIZE, HWQ_TYPE_QUEUE);
	if (rc)
		goto exit;

	sq->swq = kcalloc(sq->hwq.max_elements, sizeof(*sq->swq), GFP_KERNEL);
	if (!sq->swq) {
		rc = -ENOMEM;
		goto fail_sq;
	}
	hw_sq_send_ptr = (struct sq_send **)sq->hwq.pbl_ptr;
	if (psn_sz) {
		psn_search_ptr = (struct sq_psn_search **)
				  &hw_sq_send_ptr[SQE_PG(sq->hwq.max_elements)];
		psn_search = (long long unsigned int)
			      &hw_sq_send_ptr[SQE_PG(sq->hwq.max_elements)]
			      [SQE_IDX(sq->hwq.max_elements)];
		if (psn_search & ~PAGE_MASK) {
			/* If the psn_search does not start on a page boundary,
			 * then calculate the offset */
			poff = (psn_search & ~PAGE_MASK) /
				BNXT_QPLIB_MAX_PSNE_ENTRY_SIZE;
		}
		for (i = 0; i < sq->hwq.max_elements; i++)
			sq->swq[i].psn_search =
				&psn_search_ptr[PSNE_PG(i + poff)]
					       [PSNE_IDX(i + poff)];
	}
	pbl = &sq->hwq.pbl[PBL_LVL_0];
	req.sq_pbl = cpu_to_le64(pbl->pg_map_arr[0]);
	req.sq_pg_size_sq_lvl =
		((sq->hwq.level & CMDQ_CREATE_QP_SQ_LVL_MASK)
				 <<  CMDQ_CREATE_QP_SQ_LVL_SFT) |
		(pbl->pg_size == ROCE_PG_SIZE_4K ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_4K :
		 pbl->pg_size == ROCE_PG_SIZE_8K ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_8K :
		 pbl->pg_size == ROCE_PG_SIZE_64K ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_64K :
		 pbl->pg_size == ROCE_PG_SIZE_2M ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_2M :
		 pbl->pg_size == ROCE_PG_SIZE_8M ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_8M :
		 pbl->pg_size == ROCE_PG_SIZE_1G ?
				CMDQ_CREATE_QP_SQ_PG_SIZE_PG_1G :
		 CMDQ_CREATE_QP_SQ_PG_SIZE_PG_4K);

	/* initialize all SQ WQEs to LOCAL_INVALID (sq prep for hw fetch) */
	hw_sq_send_ptr = (struct sq_send **)sq->hwq.pbl_ptr;
	for (sw_prod = 0; sw_prod < sq->hwq.max_elements; sw_prod++) {
		hw_sq_send_hdr = &hw_sq_send_ptr[SQE_PG(sw_prod)][SQE_IDX(sw_prod)];
		hw_sq_send_hdr->wqe_type = SQ_BASE_WQE_TYPE_LOCAL_INVALID;
	}

	if (qp->scq)
		req.scq_cid = cpu_to_le32(qp->scq->id);

	/* TODO: Add appropriate Create QP flags */
	qp_flags |= CMDQ_CREATE_QP_QP_FLAGS_RESERVED_LKEY_ENABLE;
	qp_flags |= CMDQ_CREATE_QP_QP_FLAGS_FR_PMR_ENABLED;
	if (qp->sig_type)
		qp_flags |= CMDQ_CREATE_QP_QP_FLAGS_FORCE_COMPLETION;

	/* RQ */
	if (rq->max_wqe) {
		rq->hwq.max_elements = rq->max_wqe;
		rc = bnxt_qplib_alloc_init_hwq(res->pdev, &rq->hwq, rq->sglist,
					       rq->nmap, &rq->hwq.max_elements,
					       BNXT_QPLIB_MAX_RQE_ENTRY_SIZE, 0,
					       PAGE_SIZE, HWQ_TYPE_QUEUE);
		if (rc)
			goto fail_sq;

		rq->swq = kcalloc(rq->hwq.max_elements, sizeof(*rq->swq),
				  GFP_KERNEL);
		if (!rq->swq) {
			rc = -ENOMEM;
			goto fail_rq;
		}
		pbl = &rq->hwq.pbl[PBL_LVL_0];
		req.rq_pbl = cpu_to_le64(pbl->pg_map_arr[0]);
		req.rq_pg_size_rq_lvl =
			((rq->hwq.level & CMDQ_CREATE_QP_RQ_LVL_MASK) <<
			 CMDQ_CREATE_QP_RQ_LVL_SFT) |
				(pbl->pg_size == ROCE_PG_SIZE_4K ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_4K :
				 pbl->pg_size == ROCE_PG_SIZE_8K ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_8K :
				 pbl->pg_size == ROCE_PG_SIZE_64K ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_64K :
				 pbl->pg_size == ROCE_PG_SIZE_2M ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_2M :
				 pbl->pg_size == ROCE_PG_SIZE_8M ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_8M :
				 pbl->pg_size == ROCE_PG_SIZE_1G ?
					CMDQ_CREATE_QP_RQ_PG_SIZE_PG_1G :
				 CMDQ_CREATE_QP_RQ_PG_SIZE_PG_4K);
	} else {
		/* SRQ */
		if (qp->srq) {
			qp_flags |= CMDQ_CREATE_QP_QP_FLAGS_SRQ_USED;
			req.srq_cid = cpu_to_le32(qp->srq->id);
		}
	}

	if (qp->rcq)
		req.rcq_cid = cpu_to_le32(qp->rcq->id);
	req.qp_flags = cpu_to_le32(qp_flags);
	req.sq_size = cpu_to_le32(sq->hwq.max_elements);
	req.rq_size = cpu_to_le32(rq->hwq.max_elements);
	qp->sq_hdr_buf = NULL;
	qp->rq_hdr_buf = NULL;

	rc = bnxt_qplib_alloc_qp_hdr_buf(res, qp);
	if (rc)
		goto fail_rq;

	/* CTRL-22434: Irrespective of the requested SGE count on the SQ
	 * always create the QP with max send sges possible if the requested
	 * inline size is greater than 0.
	 */
	max_ssge = qp->max_inline_data ? 6 : sq->max_sge;
	req.sq_fwo_sq_sge = cpu_to_le16(
				((max_ssge & CMDQ_CREATE_QP_SQ_SGE_MASK)
				 << CMDQ_CREATE_QP_SQ_SGE_SFT) | 0);
	req.rq_fwo_rq_sge = cpu_to_le16(
				((rq->max_sge & CMDQ_CREATE_QP_RQ_SGE_MASK)
				 << CMDQ_CREATE_QP_RQ_SGE_SFT) | 0);
	/* ORRQ and IRRQ */
	if (psn_sz) {
		xrrq = &qp->orrq;
		xrrq->max_elements =
			ORD_LIMIT_TO_ORRQ_SLOTS(qp->max_rd_atomic);
		req_size = xrrq->max_elements *
			   BNXT_QPLIB_MAX_ORRQE_ENTRY_SIZE + PAGE_SIZE - 1;
		req_size &= ~(PAGE_SIZE - 1);
		rc = bnxt_qplib_alloc_init_hwq(res->pdev, xrrq, NULL, 0,
				&xrrq->max_elements,
				BNXT_QPLIB_MAX_ORRQE_ENTRY_SIZE, 0,
				req_size, HWQ_TYPE_CTX);
		if (rc)
			goto fail_buf_free;
		pbl = &xrrq->pbl[PBL_LVL_0];
		req.orrq_addr = cpu_to_le64(pbl->pg_map_arr[0]);

		xrrq = &qp->irrq;
		xrrq->max_elements = IRD_LIMIT_TO_IRRQ_SLOTS(
						qp->max_dest_rd_atomic);
		req_size = xrrq->max_elements *
			   BNXT_QPLIB_MAX_IRRQE_ENTRY_SIZE + PAGE_SIZE - 1;
		req_size &= ~(PAGE_SIZE - 1);

		rc = bnxt_qplib_alloc_init_hwq(res->pdev, xrrq, NULL, 0,
				&xrrq->max_elements,
				BNXT_QPLIB_MAX_IRRQE_ENTRY_SIZE, 0,
				req_size, HWQ_TYPE_CTX);
		if (rc)
			goto fail_orrq;

		pbl = &xrrq->pbl[PBL_LVL_0];
		req.irrq_addr = cpu_to_le64(pbl->pg_map_arr[0]);
	}
	req.pd_id = cpu_to_le32(qp->pd->id);

	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
					  (void *)&resp, NULL, 0);
	if (rc)
		goto fail;
	qp->id = le32_to_cpu(resp.xid);
	qp->cur_qp_state = CMDQ_MODIFY_QP_NEW_STATE_RESET;

	return 0;

fail:
	if (qp->irrq.max_elements)
		bnxt_qplib_free_hwq(res->pdev, &qp->irrq);
fail_orrq:
	if (qp->orrq.max_elements)
		bnxt_qplib_free_hwq(res->pdev, &qp->orrq);
fail_buf_free:
	bnxt_qplib_free_qp_hdr_buf(res, qp);
fail_rq:
	bnxt_qplib_free_hwq(res->pdev, &rq->hwq);
	if (rq->swq)
		kfree(rq->swq);
fail_sq:
	bnxt_qplib_free_hwq(res->pdev, &sq->hwq);
	if (sq->swq)
		kfree(sq->swq);
exit:
	return rc;
}

static void __filter_modify_flags(struct bnxt_qplib_qp *qp)
{
	switch (qp->cur_qp_state) {
	case CMDQ_MODIFY_QP_NEW_STATE_RESET:
		switch (qp->state) {
		case CMDQ_MODIFY_QP_NEW_STATE_INIT:
			break;
		default:
			break;
		}
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_INIT:
		switch (qp->state) {
		case CMDQ_MODIFY_QP_NEW_STATE_RTR:
			/* INIT->RTR, configure the path_mtu to the default
			   2048 if not being requested */
			if (!(qp->modify_flags &
			      CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU)) {
				qp->modify_flags |=
					CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU;
				qp->path_mtu = CMDQ_MODIFY_QP_PATH_MTU_MTU_2048;
			}
			qp->modify_flags &=
				~CMDQ_MODIFY_QP_MODIFY_MASK_VLAN_ID;
			/* Bono FW requires the max_dest_rd_atomic to be >= 1 */
			if (qp->max_dest_rd_atomic < 1)
				qp->max_dest_rd_atomic = 1;
			/* TODO: Bono FW 0.0.12.0+ does not allow SRC_MAC
			   modification */
			qp->modify_flags &= ~CMDQ_MODIFY_QP_MODIFY_MASK_SRC_MAC;
			/* Bono FW 20.6.5 requires SGID_INDEX to be configured */
			if (!(qp->modify_flags &
			      CMDQ_MODIFY_QP_MODIFY_MASK_SGID_INDEX)) {
				qp->modify_flags |=
					CMDQ_MODIFY_QP_MODIFY_MASK_SGID_INDEX;
				qp->ah.sgid_index = 0;
			}
#ifdef ENABLE_ROCE_TOS
			if (qp->tos_ecn != 0)
				qp->modify_flags |=
					CMDQ_MODIFY_QP_MODIFY_MASK_TOS_ECN |
					CMDQ_MODIFY_QP_MODIFY_MASK_ENABLE_CC;
			if (qp->tos_dscp > 0 && qp->tos_dscp <= 0x3F)
				qp->modify_flags |=
					CMDQ_MODIFY_QP_MODIFY_MASK_TOS_DSCP;
#endif
			break;
		default:
			break;
		}
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_RTR:
		switch (qp->state) {
		case CMDQ_MODIFY_QP_NEW_STATE_RTS:
			/* Bono FW requires the max_rd_atomic to be >= 1 */
			if (qp->max_rd_atomic < 1)
				qp->max_rd_atomic = 1;
			/* TODO: Bono FW 0.0.12.0+ does not allow PKEY_INDEX,
			   DGID, FLOW_LABEL, SGID_INDEX, HOP_LIMIT,
			   TRAFFIC_CLASS, DEST_MAC, PATH_MTU, RQ_PSN,
			   MIN_RNR_TIMER, MAX_DEST_RD_ATOMIC, DEST_QP_ID
			   modification */
			qp->modify_flags &=
				~(CMDQ_MODIFY_QP_MODIFY_MASK_PKEY |
				  CMDQ_MODIFY_QP_MODIFY_MASK_DGID |
				  CMDQ_MODIFY_QP_MODIFY_MASK_FLOW_LABEL |
				  CMDQ_MODIFY_QP_MODIFY_MASK_SGID_INDEX |
				  CMDQ_MODIFY_QP_MODIFY_MASK_HOP_LIMIT |
				  CMDQ_MODIFY_QP_MODIFY_MASK_TRAFFIC_CLASS |
				  CMDQ_MODIFY_QP_MODIFY_MASK_DEST_MAC |
				  CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU |
				  CMDQ_MODIFY_QP_MODIFY_MASK_RQ_PSN |
				  CMDQ_MODIFY_QP_MODIFY_MASK_MIN_RNR_TIMER |
				  CMDQ_MODIFY_QP_MODIFY_MASK_MAX_DEST_RD_ATOMIC |
#ifdef ENABLE_ROCE_TOS
				  CMDQ_MODIFY_QP_MODIFY_MASK_ENABLE_CC |
				  CMDQ_MODIFY_QP_MODIFY_MASK_TOS_ECN |
				  CMDQ_MODIFY_QP_MODIFY_MASK_TOS_DSCP |
#endif
				  CMDQ_MODIFY_QP_MODIFY_MASK_DEST_QP_ID);
			break;
		default:
			break;
		}
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_RTS:
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_SQD:
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_SQE:
		break;
	case CMDQ_MODIFY_QP_NEW_STATE_ERR:
		break;
	default:
		break;
	}
}

int bnxt_qplib_modify_qp(struct bnxt_qplib_res *res, struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_modify_qp req;
	struct creq_modify_qp_resp resp;
	u16 cmd_flags = 0, pkey;
	u32 temp32[4];
	u32 bmask;
	int rc;

	RCFW_CMD_PREP(req, MODIFY_QP, cmd_flags);

	/* Filter out the qp_attr_mask based on the state->new transition */
	__filter_modify_flags(qp);
	bmask = qp->modify_flags;
	req.modify_mask = cpu_to_le64(qp->modify_flags);
	req.qp_cid = cpu_to_le32(qp->id);
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_STATE) {
		req.network_type_en_sqd_async_notify_new_state =
				(qp->state & CMDQ_MODIFY_QP_NEW_STATE_MASK) |
				(qp->en_sqd_async_notify == true ?
					CMDQ_MODIFY_QP_EN_SQD_ASYNC_NOTIFY : 0);
	}
	req.network_type_en_sqd_async_notify_new_state |= qp->nw_type;

	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_ACCESS) {
		req.access = qp->access;
	}
	/* TODO: Instead of supplying the pkey_index to Bono, provide the actual
	   pkey instead! */
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_PKEY) {
		//req.pkey_index = cpu_to_le16(qp->pkey_index);
		if (!bnxt_qplib_get_pkey(res, &res->pkey_tbl, qp->pkey_index, &pkey)) {
			req.pkey = cpu_to_le16(pkey);
		}
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_QKEY) {
		req.qkey = cpu_to_le32(qp->qkey);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_DGID) {
		memcpy(temp32, qp->ah.dgid.data, sizeof(struct bnxt_qplib_gid));
		req.dgid[0] = cpu_to_le32(temp32[0]);
		req.dgid[1] = cpu_to_le32(temp32[1]);
		req.dgid[2] = cpu_to_le32(temp32[2]);
		req.dgid[3] = cpu_to_le32(temp32[3]);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_FLOW_LABEL) {
		req.flow_label = cpu_to_le32(qp->ah.flow_label);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_SGID_INDEX) {
		req.sgid_index = cpu_to_le16(res->sgid_tbl.hw_id[qp->ah.sgid_index]);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_HOP_LIMIT) {
		req.hop_limit = qp->ah.hop_limit;
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_TRAFFIC_CLASS) {
		req.traffic_class = qp->ah.traffic_class;
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_DEST_MAC) {
		memcpy(req.dest_mac, qp->ah.dmac, 6);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_PATH_MTU) {
		req.path_mtu = cpu_to_le16(qp->path_mtu);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_TIMEOUT) {
		req.timeout = qp->timeout;
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_RETRY_CNT) {
		req.retry_cnt = qp->retry_cnt;
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_RNR_RETRY) {
		req.rnr_retry = qp->rnr_retry;
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_MIN_RNR_TIMER) {
		req.min_rnr_timer = qp->min_rnr_timer;
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_RQ_PSN) {
		req.rq_psn = cpu_to_le32(qp->rq.psn);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_SQ_PSN) {
		req.sq_psn = cpu_to_le32(qp->sq.psn);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_MAX_RD_ATOMIC) {
		req.max_rd_atomic =
			ORD_LIMIT_TO_ORRQ_SLOTS(qp->max_rd_atomic);
	}
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_MAX_DEST_RD_ATOMIC) {
		req.max_dest_rd_atomic =
			IRD_LIMIT_TO_IRRQ_SLOTS(qp->max_dest_rd_atomic);
	}
	req.sq_size = cpu_to_le32(qp->sq.hwq.max_elements);
	req.rq_size = cpu_to_le32(qp->rq.hwq.max_elements);
	req.sq_sge = cpu_to_le16(qp->sq.max_sge);
	req.rq_sge = cpu_to_le16(qp->rq.max_sge);
	req.max_inline_data = cpu_to_le32(qp->max_inline_data);
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_DEST_QP_ID)
		req.dest_qp_id = cpu_to_le32(qp->dest_qpn);
#ifdef ENABLE_ROCE_TOS
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_ENABLE_CC)
		req.enable_cc = CMDQ_MODIFY_QP_ENABLE_CC;
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_TOS_ECN)
		req.tos_dscp_tos_ecn =
			((qp->tos_ecn << CMDQ_MODIFY_QP_TOS_ECN_SFT) &
			 CMDQ_MODIFY_QP_TOS_ECN_MASK);
	if (bmask & CMDQ_MODIFY_QP_MODIFY_MASK_TOS_DSCP)
		req.tos_dscp_tos_ecn |=
			((qp->tos_dscp << CMDQ_MODIFY_QP_TOS_DSCP_SFT) &
			 CMDQ_MODIFY_QP_TOS_DSCP_MASK);
#endif
	/* TODO: This src_mac field is never used */
	//memcpy(req.src_mac, qp->smac, 6);
	req.vlan_pcp_vlan_dei_vlan_id = cpu_to_le16(qp->vlan_id);
	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
					  (void *)&resp, NULL, 0);
	if (rc)
		return rc;
	qp->cur_qp_state = qp->state;
	return 0;
}

int bnxt_qplib_query_qp(struct bnxt_qplib_res *res, struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_query_qp req;
	struct creq_query_qp_resp resp;
	struct bnxt_qplib_rcfw_sbuf *sbuf;
	struct creq_query_qp_resp_sb *sb;
	u16 cmd_flags = 0;
	u32 temp32[4];
	int i, rc;

	RCFW_CMD_PREP(req, QUERY_QP, cmd_flags);

	sbuf = bnxt_qplib_rcfw_alloc_sbuf(rcfw, sizeof(*sb));
	if (!sbuf)
		return -ENOMEM;
	sb = sbuf->sb;
	req.qp_cid = cpu_to_le32(qp->id);
	req.resp_size = sizeof(*sb) / BNXT_QPLIB_CMDQE_UNITS;
	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req, (void *)&resp,
					  (void *)sbuf, 0);
	if (rc)
		goto bail;
	/* Extract the context from the side buffer */
	qp->state = sb->en_sqd_async_notify_state &
			CREQ_QUERY_QP_RESP_SB_STATE_MASK;
	qp->en_sqd_async_notify = sb->en_sqd_async_notify_state &
				  CREQ_QUERY_QP_RESP_SB_EN_SQD_ASYNC_NOTIFY ?
				  true : false;
	qp->access = sb->access;
	qp->pkey_index = le16_to_cpu(sb->pkey);
	qp->qkey = le32_to_cpu(sb->qkey);

	temp32[0] = le32_to_cpu(sb->dgid[0]);
	temp32[1] = le32_to_cpu(sb->dgid[1]);
	temp32[2] = le32_to_cpu(sb->dgid[2]);
	temp32[3] = le32_to_cpu(sb->dgid[3]);
	memcpy(qp->ah.dgid.data, temp32, sizeof(qp->ah.dgid.data));

	qp->ah.flow_label = le32_to_cpu(sb->flow_label);

	qp->ah.sgid_index = 0;
	for (i = 0; i < res->sgid_tbl.max; i++) {
		if (res->sgid_tbl.hw_id[i] == le16_to_cpu(sb->sgid_index)) {
			qp->ah.sgid_index = i;
			break;
		}
	}
	if (i == res->sgid_tbl.max)
		dev_warn(&res->pdev->dev, "QPLIB: SGID not found??");

	qp->ah.hop_limit = sb->hop_limit;
	qp->ah.traffic_class = sb->traffic_class;
	memcpy(qp->ah.dmac, sb->dest_mac, 6);
	qp->ah.vlan_id = le16_to_cpu((sb->path_mtu_dest_vlan_id &
				CREQ_QUERY_QP_RESP_SB_VLAN_ID_MASK) >>
				CREQ_QUERY_QP_RESP_SB_VLAN_ID_SFT);
	qp->path_mtu = sb->path_mtu_dest_vlan_id &
				    CREQ_QUERY_QP_RESP_SB_PATH_MTU_MASK;
	qp->timeout = sb->timeout;
	qp->retry_cnt = sb->retry_cnt;
	qp->rnr_retry = sb->rnr_retry;
	qp->min_rnr_timer = sb->min_rnr_timer;
	qp->rq.psn = le32_to_cpu(sb->rq_psn);
	qp->max_rd_atomic = ORRQ_SLOTS_TO_ORD_LIMIT(sb->max_rd_atomic);
	qp->sq.psn = le32_to_cpu(sb->sq_psn);
	qp->max_dest_rd_atomic =
			IRRQ_SLOTS_TO_IRD_LIMIT(sb->max_dest_rd_atomic);
	qp->sq.max_wqe = qp->sq.hwq.max_elements;
	qp->rq.max_wqe = qp->rq.hwq.max_elements;
	qp->sq.max_sge = le16_to_cpu(sb->sq_sge);
	qp->rq.max_sge = le32_to_cpu(sb->rq_sge);
	qp->max_inline_data = le32_to_cpu(sb->max_inline_data);
	qp->dest_qpn = le32_to_cpu(sb->dest_qp_id);
	memcpy(qp->smac, sb->src_mac, 6);
	qp->vlan_id = le16_to_cpu(sb->vlan_pcp_vlan_dei_vlan_id);
bail:
	bnxt_qplib_rcfw_free_sbuf(rcfw, sbuf);
	return rc;
}

static void __clean_cq(struct bnxt_qplib_cq *cq, u64 qp)
{
	struct bnxt_qplib_hwq *cq_hwq = &cq->hwq;
	struct cq_base *hw_cqe, **hw_cqe_ptr;
	int i;

	for (i = 0; i < cq_hwq->max_elements; i++) {
		hw_cqe_ptr = (struct cq_base **)cq_hwq->pbl_ptr;
		hw_cqe = &hw_cqe_ptr[CQE_PG(i)][CQE_IDX(i)];
		if (!CQE_CMP_VALID(hw_cqe, i, cq_hwq->max_elements))
			continue;
		switch (hw_cqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK) {
		case CQ_BASE_CQE_TYPE_REQ:
		case CQ_BASE_CQE_TYPE_TERMINAL:
		{
			struct cq_req *cqe = (struct cq_req *)hw_cqe;

			if (qp == le64_to_cpu(cqe->qp_handle))
				cqe->qp_handle = 0;
			break;
		}
		case CQ_BASE_CQE_TYPE_RES_RC:
		case CQ_BASE_CQE_TYPE_RES_UD:
		case CQ_BASE_CQE_TYPE_RES_RAWETH_QP1:
		{
			struct cq_res_rc *cqe = (struct cq_res_rc *)hw_cqe;

			if (qp == le64_to_cpu(cqe->qp_handle))
				cqe->qp_handle = 0;
			break;
		}
		default:
			break;
		}
	}
}

static unsigned long bnxt_qplib_lock_cqs(struct bnxt_qplib_qp *qp)
{
	unsigned long flags;

	spin_lock_irqsave(&qp->scq->hwq.lock, flags);
	if (qp->rcq && qp->rcq != qp->scq)
		spin_lock(&qp->rcq->hwq.lock);

	return flags;
}

static void bnxt_qplib_unlock_cqs(struct bnxt_qplib_qp *qp,
				  unsigned long flags)
{
	if (qp->rcq && qp->rcq != qp->scq)
		spin_unlock(&qp->rcq->hwq.lock);
	spin_unlock_irqrestore(&qp->scq->hwq.lock, flags);
}

int bnxt_qplib_destroy_qp(struct bnxt_qplib_res *res,
			  struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_destroy_qp req;
	struct creq_destroy_qp_resp resp;
	unsigned long flags;
	u16 cmd_flags = 0;
	int rc;

	RCFW_CMD_PREP(req, DESTROY_QP, cmd_flags);

	req.qp_cid = cpu_to_le32(qp->id);
	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
					  (void *)&resp, NULL, 0);
	if (rc)
		return rc;

	/* Must walk the associated CQs to nullified the QP ptr */
	flags = bnxt_qplib_lock_cqs(qp);
	__clean_cq(qp->scq, (u64)qp);
	if (qp->rcq != qp->scq)
		__clean_cq(qp->rcq, (u64)qp);
	bnxt_qplib_unlock_cqs(qp, flags);

	bnxt_qplib_free_qp_hdr_buf(res, qp);
	bnxt_qplib_free_hwq(res->pdev, &qp->sq.hwq);
	if (qp->sq.swq)
		kfree(qp->sq.swq);

	bnxt_qplib_free_hwq(res->pdev, &qp->rq.hwq);
	if (qp->rq.swq)
		kfree(qp->rq.swq);

	if (qp->irrq.max_elements)
		bnxt_qplib_free_hwq(res->pdev, &qp->irrq);
	if (qp->orrq.max_elements)
		bnxt_qplib_free_hwq(res->pdev, &qp->orrq);

	return 0;
}

void *bnxt_qplib_get_qp1_sq_buf(struct bnxt_qplib_qp *qp,
				struct bnxt_qplib_sge *sge)
{
	struct bnxt_qplib_q *sq = &qp->sq;
	u32 sw_prod;

	memset(sge, 0, sizeof(*sge));

	if (qp->sq_hdr_buf) {
		sw_prod = HWQ_CMP(sq->hwq.prod, &sq->hwq);
		sge->addr = (dma_addr_t)(qp->sq_hdr_buf_map +
					 sw_prod * qp->sq_hdr_buf_size);
		sge->lkey = 0xFFFFFFFF;
		sge->size = qp->sq_hdr_buf_size;
		return qp->sq_hdr_buf + sw_prod * sge->size;
	}
	return NULL;
}

#ifdef ENABLE_SHADOW_QP
u32 bnxt_qplib_get_rq_prod_index(struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *rq = &qp->rq;

	return HWQ_CMP(rq->hwq.prod, &rq->hwq);
}
#endif

dma_addr_t bnxt_qplib_get_qp_buf_from_index(struct bnxt_qplib_qp *qp, u32 index)
{
	return (qp->rq_hdr_buf_map + index * qp->rq_hdr_buf_size);
}

void *bnxt_qplib_get_qp1_rq_buf(struct bnxt_qplib_qp *qp,
				struct bnxt_qplib_sge *sge)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	u32 sw_prod;

	memset(sge, 0, sizeof(*sge));

	if (qp->rq_hdr_buf) {
		sw_prod = HWQ_CMP(rq->hwq.prod, &rq->hwq);
		sge->addr = (dma_addr_t)(qp->rq_hdr_buf_map +
					 sw_prod * qp->rq_hdr_buf_size);
		sge->lkey = 0xFFFFFFFF;
		sge->size = qp->rq_hdr_buf_size;
		return qp->rq_hdr_buf + sw_prod * sge->size;
	}
	return NULL;
}

void bnxt_qplib_post_send_db(struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *sq = &qp->sq;
	struct dbr_dbr db_msg = { 0 };
	u32 sw_prod;

	sw_prod = HWQ_CMP(sq->hwq.prod, &sq->hwq);

	db_msg.index = cpu_to_le32((sw_prod << DBR_DBR_INDEX_SFT) &
				   DBR_DBR_INDEX_MASK);
	db_msg.type_xid =
		cpu_to_le32(((qp->id << DBR_DBR_XID_SFT) & DBR_DBR_XID_MASK) |
			    DBR_DBR_TYPE_SQ);
	wmb();
	__iowrite64_copy(qp->dpi->dbr, &db_msg, sizeof(db_msg) / sizeof(u64));
}

int bnxt_qplib_post_send(struct bnxt_qplib_qp *qp,
			 struct bnxt_qplib_swqe *wqe)
{
	struct bnxt_qplib_q *sq = &qp->sq;
	struct bnxt_qplib_swq *swq;
	struct sq_send *hw_sq_send_hdr, **hw_sq_send_ptr;
	struct sq_sge *hw_sge;
	struct bnxt_qplib_nq_work *nq_work = NULL;
	bool sch_handler = false;
#ifdef ENABLE_FP_SPINLOCK
	unsigned long flags;
#endif
	u32 sw_prod;
	u8 wqe_size16;
	int i, rc = 0, data_len = 0, pkt_num = 0;
	u32 temp32;

#ifdef ENABLE_FP_SPINLOCK
	spin_lock_irqsave(&sq->hwq.lock, flags);
#endif
	/* TODO: Allow the posting of WQEs in the ERR state but only to
		 the flush queue which will get completed in poll_cq */
	if (qp->state != CMDQ_MODIFY_QP_NEW_STATE_RTS) {
		if (qp->state == CMDQ_MODIFY_QP_NEW_STATE_ERR) {
			sch_handler = true;
			dev_dbg(&sq->hwq.pdev->dev,
				"%s Error QP. Scheduling for poll_cq\n",
				__func__);
			goto queue_err;
		}
		dev_err(&sq->hwq.pdev->dev,
			"QPLIB: FP: QP (0x%x) is in the 0x%x state",
			qp->id, qp->state);
		rc = -EINVAL;
		goto done;
	}
	if (bnxt_qplib_queue_full(sq)) {
		dev_err(&sq->hwq.pdev->dev,
			"QPLIB: FP: QP (0x%x) SQ is full!", qp->id);
		dev_err(&sq->hwq.pdev->dev,
			"QPLIB: prod = %#x cons = %#x qdepth = %#x delta = %#x",
			(sq->hwq.prod & (sq->hwq.max_elements - 1)),
			(sq->hwq.cons & (sq->hwq.max_elements - 1)),
			sq->hwq.max_elements, sq->q_full_delta);
		dev_err(&sq->hwq.pdev->dev,
			"QPLIB: phantom_wqe_cnt: %d phantom_cqe_cnt: %d\n",
			sq->phantom_wqe_cnt, sq->phantom_cqe_cnt);
		rc = -ENOMEM;
		goto done;
	}
	sw_prod = HWQ_CMP(sq->hwq.prod, &sq->hwq);
	swq = &sq->swq[sw_prod];
	swq->wr_id = wqe->wr_id;
	swq->type = wqe->type;
	swq->flags = wqe->flags;
	if (qp->sig_type)
		swq->flags |= SQ_SEND_FLAGS_SIGNAL_COMP;
	swq->start_psn = sq->psn & BTH_PSN_MASK;

	dev_dbg(&sq->hwq.pdev->dev,
		"QPLIB: FP: QP(0x%x) post SQ wr_id[%d] = 0x%llx",
		qp->id, sw_prod, swq->wr_id);

	hw_sq_send_ptr = (struct sq_send **)sq->hwq.pbl_ptr;
	hw_sq_send_hdr = &hw_sq_send_ptr[SQE_PG(sw_prod)][SQE_IDX(sw_prod)];

	memset(hw_sq_send_hdr, 0, BNXT_QPLIB_MAX_SQE_ENTRY_SIZE);

	if (wqe->flags & BNXT_QPLIB_SWQE_FLAGS_INLINE) {
		/* Copy the inline data */
		if (wqe->inline_len > BNXT_QPLIB_SWQE_MAX_INLINE_LENGTH) {
			dev_warn(&sq->hwq.pdev->dev,
				 "QPLIB: Inline data length > 96 detected");
			data_len = BNXT_QPLIB_SWQE_MAX_INLINE_LENGTH;
		} else {
			data_len = wqe->inline_len;
		}
		memcpy(hw_sq_send_hdr->data, wqe->inline_data, data_len);
		wqe_size16 = (data_len + 15) >> 4;
	} else {
		for (i = 0, hw_sge = (struct sq_sge *)hw_sq_send_hdr->data;
		     i < wqe->num_sge; i++, hw_sge++) {
			hw_sge->va_or_pa = cpu_to_le64(wqe->sg_list[i].addr);
			hw_sge->l_key = cpu_to_le32(wqe->sg_list[i].lkey);
			hw_sge->size = cpu_to_le32(wqe->sg_list[i].size);
			data_len += hw_sge->size;
		}
		/* Each SGE entry = 1 WQE size16 */
		wqe_size16 = wqe->num_sge;
		/* HW requires wqe size has room for atleast one SGE even if
		 * none was supplied by ULP
		 */
		if (!wqe->num_sge)
			wqe_size16++;
	}

	/* Specifics */
	switch (wqe->type) {
	case BNXT_QPLIB_SWQE_TYPE_SEND:
		if (qp->type == CMDQ_CREATE_QP_TYPE_RAW_ETHERTYPE ||
		    qp->type == CMDQ_CREATE_QP1_TYPE_GSI) {
			/* Assemble info for Raw Ethertype QPs */
			struct sq_send_raweth_qp1 *sqe =
				(struct sq_send_raweth_qp1 *)hw_sq_send_hdr;

			sqe->wqe_type = wqe->type;
			sqe->flags = wqe->flags;
			sqe->wqe_size = wqe_size16 +
				((offsetof(typeof(*sqe), data) + 15) >> 4);
			sqe->cfa_action = cpu_to_le16(wqe->rawqp1.cfa_action);
			sqe->lflags = cpu_to_le16(wqe->rawqp1.lflags);
			sqe->length = cpu_to_le32(data_len);
			sqe->cfa_meta = cpu_to_le32((wqe->rawqp1.cfa_meta &
				SQ_SEND_RAWETH_QP1_CFA_META_VLAN_VID_MASK) <<
				SQ_SEND_RAWETH_QP1_CFA_META_VLAN_VID_SFT);

			dev_dbg(&sq->hwq.pdev->dev,
				"QPLIB: FP: RAW/QP1 Send WQE:\n"
				"\twqe_type = 0x%x\n"
				"\tflags = 0x%x\n"
				"\twqe_size = 0x%x\n"
				"\tlflags = 0x%x\n"
				"\tcfa_action = 0x%x\n"
				"\tlength = 0x%x\n"
				"\tcfa_meta = 0x%x",
				sqe->wqe_type, sqe->flags, sqe->wqe_size,
				sqe->lflags, sqe->cfa_action,
				sqe->length, sqe->cfa_meta);
			break;
		}
		/* else, just fall thru */
	case BNXT_QPLIB_SWQE_TYPE_SEND_WITH_IMM:
	case BNXT_QPLIB_SWQE_TYPE_SEND_WITH_INV:
	{
		struct sq_send *sqe = (struct sq_send *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->wqe_size = wqe_size16 +
				((offsetof(typeof(*sqe), data) + 15) >> 4);
		sqe->inv_key_or_imm_data = cpu_to_le32(
						wqe->send.imm_data_or_inv_key);
		if (qp->type == CMDQ_CREATE_QP_TYPE_UD) {
			sqe->q_key = cpu_to_le32(wqe->send.q_key);
			sqe->dst_qp = cpu_to_le32(
					wqe->send.dst_qp & SQ_SEND_DST_QP_MASK);
			sqe->length = cpu_to_le32(data_len);
			sqe->avid = cpu_to_le32(wqe->send.avid &
						SQ_SEND_AVID_MASK);
			sq->psn = (sq->psn + 1) & BTH_PSN_MASK;
		} else {
			sqe->length = cpu_to_le32(data_len);
			sqe->dst_qp = 0;
			sqe->avid = 0;
			if (qp->mtu)
				pkt_num = (data_len + qp->mtu - 1) / qp->mtu;
			if (!pkt_num)
				pkt_num = 1;
			sq->psn = (sq->psn + pkt_num) & BTH_PSN_MASK;
		}
		dev_dbg(&sq->hwq.pdev->dev,
			"QPLIB: FP: Send WQE:\n"
			"\twqe_type = 0x%x\n"
			"\tflags = 0x%x\n"
			"\twqe_size = 0x%x\n"
			"\tinv_key/immdata = 0x%x\n"
			"\tq_key = 0x%x\n"
			"\tdst_qp = 0x%x\n"
			"\tlength = 0x%x\n"
			"\tavid = 0x%x",
			sqe->wqe_type, sqe->flags, sqe->wqe_size,
			sqe->inv_key_or_imm_data, sqe->q_key, sqe->dst_qp,
			sqe->length, sqe->avid);
		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_RDMA_WRITE:
	case BNXT_QPLIB_SWQE_TYPE_RDMA_WRITE_WITH_IMM:
	case BNXT_QPLIB_SWQE_TYPE_RDMA_READ:
	{
		struct sq_rdma *sqe = (struct sq_rdma *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->wqe_size = wqe_size16 +
				((offsetof(typeof(*sqe), data) + 15) >> 4);
		sqe->imm_data = cpu_to_le32(wqe->rdma.imm_data_or_inv_key);
		sqe->length = cpu_to_le32((u32)data_len);
		sqe->remote_va = cpu_to_le64(wqe->rdma.remote_va);
		sqe->remote_key = cpu_to_le32(wqe->rdma.r_key);
		if (qp->mtu)
			pkt_num = (data_len + qp->mtu - 1) / qp->mtu;
		if (!pkt_num)
			pkt_num = 1;
		sq->psn = (sq->psn + pkt_num) & BTH_PSN_MASK;

		dev_dbg(&sq->hwq.pdev->dev,
			"QPLIB: FP: RDMA WQE:\n"
			"\twqe_type = 0x%x\n"
			"\tflags = 0x%x\n"
			"\twqe_size = 0x%x\n"
			"\timmdata = 0x%x\n"
			"\tlength = 0x%x\n"
			"\tremote_va = 0x%llx\n"
			"\tremote_key = 0x%x",
			sqe->wqe_type, sqe->flags, sqe->wqe_size,
			sqe->imm_data, sqe->length, sqe->remote_va,
			sqe->remote_key);
		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_ATOMIC_CMP_AND_SWP:
	case BNXT_QPLIB_SWQE_TYPE_ATOMIC_FETCH_AND_ADD:
	{
		struct sq_atomic *sqe = (struct sq_atomic *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->remote_key = cpu_to_le32(wqe->atomic.r_key);
		sqe->remote_va = cpu_to_le64(wqe->atomic.remote_va);
		sqe->swap_data = cpu_to_le64(wqe->atomic.swap_data);
		sqe->cmp_data = cpu_to_le64(wqe->atomic.cmp_data);
		if (qp->mtu)
			pkt_num = (data_len + qp->mtu - 1) / qp->mtu;
		if (!pkt_num)
			pkt_num = 1;
		sq->psn = (sq->psn + pkt_num) & BTH_PSN_MASK;
		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_LOCAL_INV:
	{
		struct sq_localinvalidate *sqe =
				(struct sq_localinvalidate *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->inv_l_key = cpu_to_le32(wqe->local_inv.inv_l_key);

		dev_dbg(&sq->hwq.pdev->dev,
			"QPLIB: FP: LOCAL INV WQE:\n"
			"\twqe_type = 0x%x\n"
			"\tflags = 0x%x\n"
			"\tinv_l_key = 0x%x",
			sqe->wqe_type, sqe->flags, sqe->inv_l_key);
		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_FAST_REG_MR:
	{
		struct sq_fr_pmr *sqe = (struct sq_fr_pmr *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->access_cntl = wqe->frmr.access_cntl |
				   SQ_FR_PMR_ACCESS_CNTL_LOCAL_WRITE;
		sqe->zero_based_page_size_log =
			(wqe->frmr.pg_sz_log & SQ_FR_PMR_PAGE_SIZE_LOG_MASK) <<
			SQ_FR_PMR_PAGE_SIZE_LOG_SFT |
			(wqe->frmr.zero_based == true ? SQ_FR_PMR_ZERO_BASED : 0);
		sqe->l_key = cpu_to_le32(wqe->frmr.l_key);
		/* TODO: OFED only provides length of MR up to 32-bits for FRMR */
		temp32 = cpu_to_le32(wqe->frmr.length);
		memcpy(sqe->length, &temp32, sizeof(wqe->frmr.length));
		sqe->numlevels_pbl_page_size_log =
			((wqe->frmr.pbl_pg_sz_log <<
					SQ_FR_PMR_PBL_PAGE_SIZE_LOG_SFT) &
					SQ_FR_PMR_PBL_PAGE_SIZE_LOG_MASK) |
			((wqe->frmr.levels << SQ_FR_PMR_NUMLEVELS_SFT) &
					SQ_FR_PMR_NUMLEVELS_MASK);

		for (i = 0; i < wqe->frmr.page_list_len; i++)
			wqe->frmr.pbl_ptr[i] = cpu_to_le64(
						wqe->frmr.page_list[i] |
						PTU_PTE_VALID);
		sqe->pblptr = cpu_to_le64(wqe->frmr.pbl_dma_ptr);
		sqe->va = cpu_to_le64(wqe->frmr.va);

		dev_dbg(&sq->hwq.pdev->dev,
			"QPLIB: FP: FRMR WQE:\n"
			"\twqe_type = 0x%x\n"
			"\tflags = 0x%x\n"
			"\taccess_cntl = 0x%x\n"
			"\tzero_based_page_size_log = 0x%x\n"
			"\tl_key = 0x%x\n"
			"\tlength = 0x%x\n"
			"\tnumlevels_pbl_page_size_log = 0x%x\n"
			"\tpblptr = 0x%llx\n"
			"\tva = 0x%llx",
			sqe->wqe_type, sqe->flags, sqe->access_cntl,
			sqe->zero_based_page_size_log, sqe->l_key,
			*(u32 *)sqe->length, sqe->numlevels_pbl_page_size_log,
			sqe->pblptr, sqe->va);
		break;
	}
	case BNXT_QPLIB_SWQE_TYPE_BIND_MW:
	{
		struct sq_bind *sqe = (struct sq_bind *)hw_sq_send_hdr;

		sqe->wqe_type = wqe->type;
		sqe->flags = wqe->flags;
		sqe->access_cntl = wqe->bind.access_cntl;
		sqe->mw_type_zero_based = wqe->bind.mw_type |
			(wqe->bind.zero_based == true ? SQ_BIND_ZERO_BASED : 0);
		sqe->parent_l_key = cpu_to_le32(wqe->bind.parent_l_key);
		sqe->l_key = cpu_to_le32(wqe->bind.r_key);
		sqe->va = cpu_to_le64(wqe->bind.va);
		/* TODO: OFED only provides length of MR up to 32-bits for Bind */
		temp32 = cpu_to_le32(wqe->bind.length);
		memcpy(&sqe->length, &temp32, sizeof(wqe->bind.length));
		dev_dbg(&sq->hwq.pdev->dev,
			"QPLIB: FP: BIND WQE:\n"
			"\twqe_type = 0x%x\n"
			"\tflags = 0x%x\n"
			"\taccess_cntl = 0x%x\n"
			"\tmw_type_zero_based = 0x%x\n"
			"\tparent_l_key = 0x%x\n"
			"\tl_key = 0x%x\n"
			"\tva = 0x%llx\n"
			"\tlength = 0x%llx",
			sqe->wqe_type, sqe->flags, sqe->access_cntl,
			sqe->mw_type_zero_based, sqe->parent_l_key,
			sqe->l_key, sqe->va, (u64)sqe->length[0]);
		break;
	}
	default:
		/* Bad wqe, return error */
		rc = -EINVAL;
		goto done;
	}
	swq->next_psn = sq->psn & BTH_PSN_MASK;
	if (swq->psn_search) {
		swq->psn_search->opcode_start_psn = cpu_to_le32(
			((swq->start_psn << SQ_PSN_SEARCH_START_PSN_SFT) &
			 SQ_PSN_SEARCH_START_PSN_MASK) |
			((wqe->type << SQ_PSN_SEARCH_OPCODE_SFT) &
			 SQ_PSN_SEARCH_OPCODE_MASK));
		swq->psn_search->flags_next_psn = cpu_to_le32(
			((swq->next_psn << SQ_PSN_SEARCH_NEXT_PSN_SFT) &
			 SQ_PSN_SEARCH_NEXT_PSN_MASK));
	}
#ifdef ENABLE_DEBUG_SGE
	for (i = 0, hw_sge = (struct sq_sge *)hw_sq_send_hdr->data;
	     i < wqe->num_sge; i++, hw_sge++)
		dev_dbg(&sq->hwq.pdev->dev,
			"QPLIB: FP: va/pa=0x%llx lkey=0x%x size=0x%x",
			hw_sge->va_or_pa, hw_sge->l_key, hw_sge->size);
#endif
queue_err:

	if (sch_handler) {
		/* Store the ULP info in the software structures */
		sw_prod = HWQ_CMP(sq->hwq.prod, &sq->hwq);
		swq = &sq->swq[sw_prod];
		swq->wr_id = wqe->wr_id;
		swq->type = wqe->type;
		swq->flags = wqe->flags;
		if (qp->sig_type)
			swq->flags |= SQ_SEND_FLAGS_SIGNAL_COMP;
		swq->start_psn = sq->psn & BTH_PSN_MASK;
	}
	sq->hwq.prod++;

	qp->wqe_cnt++;

done:
#ifdef ENABLE_FP_SPINLOCK
	spin_unlock_irqrestore(&sq->hwq.lock, flags);
#endif

	if (sch_handler) {
		nq_work = kzalloc(sizeof(*nq_work), GFP_ATOMIC);
		if (nq_work) {
			nq_work->cq = qp->scq;
			nq_work->nq = qp->scq->nq;
			INIT_WORK(&nq_work->work, bnxt_qpn_cqn_sched_task);
			queue_work(qp->scq->nq->cqn_wq, &nq_work->work);
		} else {
			dev_err(&sq->hwq.pdev->dev,
				"QPLIB: FP: Failed to allocate SQ nq_work!");
			rc = -ENOMEM;
		}
	}
	return rc;
}

void bnxt_qplib_post_recv_db(struct bnxt_qplib_qp *qp)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	struct dbr_dbr db_msg = { 0 };
	u32 sw_prod;

	sw_prod = HWQ_CMP(rq->hwq.prod, &rq->hwq);
	db_msg.index = cpu_to_le32((sw_prod << DBR_DBR_INDEX_SFT) &
				   DBR_DBR_INDEX_MASK);
	db_msg.type_xid =
		cpu_to_le32(((qp->id << DBR_DBR_XID_SFT) & DBR_DBR_XID_MASK) |
			    DBR_DBR_TYPE_RQ);
	wmb();
	__iowrite64_copy(qp->dpi->dbr, &db_msg, sizeof(db_msg) / sizeof(u64));
}

int bnxt_qplib_post_recv(struct bnxt_qplib_qp *qp,
			 struct bnxt_qplib_swqe *wqe)
{
	struct bnxt_qplib_q *rq = &qp->rq;
	struct rq_wqe *rqe, **rqe_ptr;
	struct sq_sge *hw_sge;
	struct bnxt_qplib_nq_work *nq_work = NULL;
	bool sch_handler = false;
#ifdef ENABLE_FP_SPINLOCK
	unsigned long flags;
#endif
	u32 sw_prod;
	int i, rc = 0;

#ifdef ENABLE_FP_SPINLOCK
	spin_lock_irqsave(&rq->hwq.lock, flags);
#endif
	if (qp->state == CMDQ_MODIFY_QP_NEW_STATE_ERR) {
		sch_handler = true;
		dev_dbg(&rq->hwq.pdev->dev,
			"%s Error QP. Scheduling for poll_cq\n",
			__func__);
		goto queue_err;
	}
	if (bnxt_qplib_queue_full(rq)) {
		dev_err(&rq->hwq.pdev->dev,
			"QPLIB: FP: QP (0x%x) RQ is full!", qp->id);
		rc = -EINVAL;
		goto done;
	}
	sw_prod = HWQ_CMP(rq->hwq.prod, &rq->hwq);
	rq->swq[sw_prod].wr_id = wqe->wr_id;

	dev_dbg(&rq->hwq.pdev->dev,
		"QPLIB: FP: post RQ wr_id[%d] = 0x%llx",
		sw_prod, rq->swq[sw_prod].wr_id);

	rqe_ptr = (struct rq_wqe **)rq->hwq.pbl_ptr;
	rqe = &rqe_ptr[RQE_PG(sw_prod)][RQE_IDX(sw_prod)];

	memset(rqe, 0, BNXT_QPLIB_MAX_RQE_ENTRY_SIZE);

	/* Calculate wqe_size16 and data_len */
	for (i = 0, hw_sge = (struct sq_sge *)rqe->data;
	     i < wqe->num_sge; i++, hw_sge++) {
		hw_sge->va_or_pa = cpu_to_le64(wqe->sg_list[i].addr);
		hw_sge->l_key = cpu_to_le32(wqe->sg_list[i].lkey);
		hw_sge->size = cpu_to_le32(wqe->sg_list[i].size);
#ifdef ENABLE_DEBUG_SGE
		dev_dbg(&rq->hwq.pdev->dev,
			"QPLIB: FP: va/pa=0x%llx lkey=0x%x size=0x%x",
			hw_sge->va_or_pa, hw_sge->l_key, hw_sge->size);
#endif
	}
	rqe->wqe_type = wqe->type;
	rqe->flags = wqe->flags;
	rqe->wqe_size = wqe->num_sge +
			((offsetof(typeof(*rqe), data) + 15) >> 4);

	/* HW requires wqe size has room for atleast one SGE even if none
	 * was supplied by ULP
	 */
	if (!wqe->num_sge)
		rqe->wqe_size++;
	//Supply the rqe->wr_id index to the wr_id_tbl for now
	rqe->wr_id[0] = cpu_to_le32(sw_prod);

queue_err:
	if (sch_handler) {
		/* Store the ULP info in the software structures */
		sw_prod = HWQ_CMP(rq->hwq.prod, &rq->hwq);
		rq->swq[sw_prod].wr_id = wqe->wr_id;
	}

	rq->hwq.prod++;
done:
#ifdef ENABLE_FP_SPINLOCK
	spin_unlock_irqrestore(&rq->hwq.lock, flags);
#endif
	if (sch_handler) {
		nq_work = kzalloc(sizeof(*nq_work), GFP_ATOMIC);
		if (nq_work) {
			nq_work->cq = qp->rcq;
			nq_work->nq = qp->rcq->nq;
			INIT_WORK(&nq_work->work, bnxt_qpn_cqn_sched_task);
			queue_work(qp->rcq->nq->cqn_wq, &nq_work->work);
		} else {
			dev_err(&rq->hwq.pdev->dev,
				"QPLIB: FP: Failed to allocate RQ nq_work!");
			rc = -ENOMEM;
		}
	}
	return rc;
}

/* CQ */

/* Spinlock must be held */
static void bnxt_qplib_arm_cq_enable(struct bnxt_qplib_cq *cq)
{
	struct dbr_dbr db_msg = { 0 };

	db_msg.type_xid =
		cpu_to_le32(((cq->id << DBR_DBR_XID_SFT) & DBR_DBR_XID_MASK) |
			    DBR_DBR_TYPE_CQ_ARMENA);
	wmb();
	__iowrite64_copy(cq->dbr_base, &db_msg, sizeof(db_msg) / sizeof(u64));
}

static void bnxt_qplib_arm_cq(struct bnxt_qplib_cq *cq, u32 arm_type)
{
	struct bnxt_qplib_hwq *cq_hwq = &cq->hwq;
	struct dbr_dbr db_msg = { 0 };
	u32 sw_cons;

	/* Ring DB */
	sw_cons = HWQ_CMP(cq_hwq->cons, cq_hwq);
	db_msg.index = cpu_to_le32((sw_cons << DBR_DBR_INDEX_SFT) &
				    DBR_DBR_INDEX_MASK);
	db_msg.type_xid =
		cpu_to_le32(((cq->id << DBR_DBR_XID_SFT) & DBR_DBR_XID_MASK) |
			    arm_type);
	wmb();
	__iowrite64_copy(cq->dpi->dbr, &db_msg, sizeof(db_msg) / sizeof(u64));
}

int bnxt_qplib_create_cq(struct bnxt_qplib_res *res, struct bnxt_qplib_cq *cq)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_create_cq req;
	struct creq_create_cq_resp resp;
	struct bnxt_qplib_pbl *pbl;
	u16 cmd_flags = 0;
	int rc;

	cq->hwq.max_elements = cq->max_wqe;
	rc = bnxt_qplib_alloc_init_hwq(res->pdev, &cq->hwq, cq->sghead,
				       cq->nmap, &cq->hwq.max_elements,
				       BNXT_QPLIB_MAX_CQE_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_QUEUE);
	if (rc)
		goto exit;

	RCFW_CMD_PREP(req, CREATE_CQ, cmd_flags);

	if (!cq->dpi) {
		dev_err(&rcfw->pdev->dev,
			"QPLIB: FP: CREATE_CQ failed due to NULL DPI");
		return -EINVAL;
	}
	req.dpi = cpu_to_le32(cq->dpi->dpi);
	req.cq_handle = cpu_to_le64(cq->cq_handle);

	req.cq_size = cpu_to_le32(cq->hwq.max_elements);
	pbl = &cq->hwq.pbl[PBL_LVL_0];
	req.pg_size_lvl = cpu_to_le32(
	    ((cq->hwq.level & CMDQ_CREATE_CQ_LVL_MASK) <<
						CMDQ_CREATE_CQ_LVL_SFT) |
	    (pbl->pg_size == ROCE_PG_SIZE_4K ? CMDQ_CREATE_CQ_PG_SIZE_PG_4K :
	     pbl->pg_size == ROCE_PG_SIZE_8K ? CMDQ_CREATE_CQ_PG_SIZE_PG_8K :
	     pbl->pg_size == ROCE_PG_SIZE_64K ? CMDQ_CREATE_CQ_PG_SIZE_PG_64K :
	     pbl->pg_size == ROCE_PG_SIZE_2M ? CMDQ_CREATE_CQ_PG_SIZE_PG_2M :
	     pbl->pg_size == ROCE_PG_SIZE_8M ? CMDQ_CREATE_CQ_PG_SIZE_PG_8M :
	     pbl->pg_size == ROCE_PG_SIZE_1G ? CMDQ_CREATE_CQ_PG_SIZE_PG_1G :
	     CMDQ_CREATE_CQ_PG_SIZE_PG_4K));

	req.pbl = cpu_to_le64(pbl->pg_map_arr[0]);

	req.cq_fco_cnq_id = cpu_to_le16(
			((cq->cnq_hw_ring_id & CMDQ_CREATE_CQ_CNQ_ID_MASK) <<
			 CMDQ_CREATE_CQ_CNQ_ID_SFT) | 0);

	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
					  (void *)&resp, NULL, 0);
	if (rc)
		goto fail;
	cq->id = le32_to_cpu(resp.xid);
	cq->dbr_base = res->dpi_tbl.dbr_bar_reg_iomem;
	cq->period = BNXT_QPLIB_QUEUE_START_PERIOD;
	init_waitqueue_head(&cq->waitq);
	INIT_LIST_HEAD(&cq->sqf_head);
	INIT_LIST_HEAD(&cq->rqf_head);

	bnxt_qplib_arm_cq_enable(cq);
	return 0;

fail:
	bnxt_qplib_free_hwq(res->pdev, &cq->hwq);
exit:
	return rc;
}

int bnxt_qplib_modify_cq(struct bnxt_qplib_res *res, struct bnxt_qplib_cq *cq)
{
//	struct bnxt_qplib_rcfw *rcfw = res->rcfw;

	/* TODO: Modify CQ threshold are passed to the HW via DBR */
	return 0;
}

void bnxt_qplib_resize_cq_complete(struct bnxt_qplib_res *res,
				   struct bnxt_qplib_cq *cq)
{
	bnxt_qplib_free_hwq(res->pdev, &cq->hwq);
	memcpy(&cq->hwq, &cq->resize_hwq, sizeof(cq->hwq));

	/* Tell HW to switch over to the new CQ */
	if (!cq->resize_hwq.is_user)
		bnxt_qplib_arm_cq(cq, DBR_DBR_TYPE_CQ_CUTOFF_ACK);
}

int bnxt_qplib_resize_cq(struct bnxt_qplib_res *res, struct bnxt_qplib_cq *cq,
			 int new_cqes)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_resize_cq req;
	struct creq_resize_cq_resp resp;
	struct bnxt_qplib_pbl *pbl;
	u16 cmd_flags = 0, count = -1;
	int rc;

	RCFW_CMD_PREP(req, RESIZE_CQ, cmd_flags);

	cq->resize_hwq.max_elements = new_cqes;
	rc = bnxt_qplib_alloc_init_hwq(res->pdev, &cq->resize_hwq, cq->sghead,
				       cq->nmap, &cq->resize_hwq.max_elements,
				       BNXT_QPLIB_MAX_CQE_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_QUEUE);
	if (rc)
		return rc;

	dev_dbg(&rcfw->pdev->dev, "QPLIB: FP: %s: pbl_lvl: %d\n", __func__,
		cq->resize_hwq.level);
	req.cq_cid = cpu_to_le32(cq->id);
	pbl = &cq->resize_hwq.pbl[PBL_LVL_0];
	req.new_cq_size_pg_size_lvl = cpu_to_le32(
	    ((cq->resize_hwq.level & CMDQ_RESIZE_CQ_LVL_MASK) <<
						CMDQ_RESIZE_CQ_LVL_SFT) |
	    (pbl->pg_size == ROCE_PG_SIZE_4K ? CMDQ_RESIZE_CQ_PG_SIZE_PG_4K :
	     pbl->pg_size == ROCE_PG_SIZE_8K ? CMDQ_RESIZE_CQ_PG_SIZE_PG_8K :
	     pbl->pg_size == ROCE_PG_SIZE_64K ? CMDQ_RESIZE_CQ_PG_SIZE_PG_64K :
	     pbl->pg_size == ROCE_PG_SIZE_2M ? CMDQ_RESIZE_CQ_PG_SIZE_PG_2M :
	     pbl->pg_size == ROCE_PG_SIZE_8M ? CMDQ_RESIZE_CQ_PG_SIZE_PG_8M :
	     pbl->pg_size == ROCE_PG_SIZE_1G ? CMDQ_RESIZE_CQ_PG_SIZE_PG_1G :
	     CMDQ_RESIZE_CQ_PG_SIZE_PG_4K) | cq->resize_hwq.max_elements);
	req.new_pbl = cpu_to_le64(pbl->pg_map_arr[0]);

	if (!cq->resize_hwq.is_user)
		set_bit(CQ_FLAGS_RESIZE_IN_PROG, &cq->flags);

	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
					  (void *)&resp, NULL, 0);
	if (rc)
		goto fail;

	if (!cq->resize_hwq.is_user) {
wait:
		/* Wait here for the HW to switch the CQ over */
		if (wait_event_interruptible_timeout(cq->waitq,
		    !test_bit(CQ_FLAGS_RESIZE_IN_PROG, &cq->flags),
		    msecs_to_jiffies(CQ_RESIZE_WAIT_TIME_MS)) ==
		    -ERESTARTSYS && count--)
			goto wait;

		if (test_bit(CQ_FLAGS_RESIZE_IN_PROG, &cq->flags)) {
			dev_err(&rcfw->pdev->dev,
				"QPLIB: FP: RESIZE_CQ timed out");
			rc = -ETIMEDOUT;
			goto fail;
		}

		bnxt_qplib_resize_cq_complete(res, cq);
	}

	return 0;
fail:
	if (!cq->resize_hwq.is_user) {
		bnxt_qplib_free_hwq(res->pdev, &cq->resize_hwq);
		clear_bit(CQ_FLAGS_RESIZE_IN_PROG, &cq->flags);
	}
	return rc;
}

int bnxt_qplib_destroy_cq(struct bnxt_qplib_res *res, struct bnxt_qplib_cq *cq)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_destroy_cq req;
	struct creq_destroy_cq_resp resp;
	u16 cmd_flags = 0;
	int rc;

	RCFW_CMD_PREP(req, DESTROY_CQ, cmd_flags);

	req.cq_cid = cpu_to_le32(cq->id);
	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req,
					  (void *)&resp, NULL, 0);
	if (rc)
		return rc;
	bnxt_qplib_free_hwq(res->pdev, &cq->hwq);

	return 0;
}

static int __flush_sq(struct bnxt_qplib_q *sq, struct bnxt_qplib_qp *qp,
		      struct bnxt_qplib_cqe **pcqe, int *budget)
{
	u32 sw_prod, sw_cons;
	struct bnxt_qplib_cqe *cqe;
	int rc = 0;

	/* Now complete all outstanding SQEs with FLUSHED_ERR */
	sw_prod = HWQ_CMP(sq->hwq.prod, &sq->hwq);
	cqe = *pcqe;
	while (*budget) {
		sw_cons = HWQ_CMP(sq->hwq.cons, &sq->hwq);
		if (sw_cons == sw_prod) {
			break;
		}
		memset(cqe, 0, sizeof(*cqe));
		cqe->status = CQ_REQ_STATUS_WORK_REQUEST_FLUSHED_ERR;
		cqe->opcode = CQ_BASE_CQE_TYPE_REQ;
		cqe->qp_handle = (u64)qp;
		cqe->wr_id = sq->swq[sw_cons].wr_id;
		cqe->src_qp = qp->id;
		cqe->type = sq->swq[sw_cons].type;
		dev_dbg(&sq->hwq.pdev->dev,
			"QPLIB: FP: CQ Processed terminal Req ");
		dev_dbg(&sq->hwq.pdev->dev,
			"QPLIB: wr_id[%d] = 0x%llx with status 0x%x",
			sw_cons, cqe->wr_id, cqe->status);
		cqe++;
		(*budget)--;
		sq->hwq.cons++;
	}
	*pcqe = cqe;
	if (!budget && HWQ_CMP(sq->hwq.cons, &sq->hwq) != sw_prod)
		/* Out of budget */
		rc = -EAGAIN;
	dev_dbg(&sq->hwq.pdev->dev, "QPLIB: FP: Flush SQ rc = 0x%x", rc);

	return rc;
}

static int __flush_rq(struct bnxt_qplib_q *rq, struct bnxt_qplib_qp *qp,
		      struct bnxt_qplib_cqe **pcqe, int *budget)
{
	struct bnxt_qplib_cqe *cqe;
	u32 sw_prod, sw_cons;
	int rc = 0;
	int opcode = 0;

	switch (qp->type) {
	case CMDQ_CREATE_QP1_TYPE_GSI:
		opcode = CQ_BASE_CQE_TYPE_RES_RAWETH_QP1;
		break;
	case CMDQ_CREATE_QP_TYPE_RC:
		opcode = CQ_BASE_CQE_TYPE_RES_RC;
		break;
	case CMDQ_CREATE_QP_TYPE_UD:
		opcode = CQ_BASE_CQE_TYPE_RES_UD;
		break;
	}

	/* Flush the rest of the RQ */
	sw_prod = HWQ_CMP(rq->hwq.prod, &rq->hwq);
	cqe = *pcqe;
	while (*budget) {
		sw_cons = HWQ_CMP(rq->hwq.cons, &rq->hwq);
		if (sw_cons == sw_prod)
			break;
		memset(cqe, 0, sizeof(*cqe));
		cqe->status =
		    CQ_RES_RC_STATUS_WORK_REQUEST_FLUSHED_ERR;
		cqe->opcode = opcode;
		cqe->qp_handle = (u64)qp;
		cqe->wr_id = rq->swq[sw_cons].wr_id;
		dev_dbg(&rq->hwq.pdev->dev, "QPLIB: FP: CQ Processed Res RC ");
		dev_dbg(&rq->hwq.pdev->dev,
			"QPLIB: rq[%d] = 0x%llx with status 0x%x",
			sw_cons, cqe->wr_id, cqe->status);
		cqe++;
		(*budget)--;
		rq->hwq.cons++;
	}
	*pcqe = cqe;
	if (!*budget && HWQ_CMP(rq->hwq.cons, &rq->hwq) != sw_prod)
		/* Out of budget */
		rc = -EAGAIN;

	dev_dbg(&rq->hwq.pdev->dev, "QPLIB: FP: Flush RQ rc = 0x%x", rc);
	return rc;
}

/* Note: SQE is valid from sw_sq_cons up to cqe_sq_cons (exclusive)
 *       CQE is track from sw_cq_cons to max_element but valid only if VALID=1
 */
static int do_wa9060(struct bnxt_qplib_qp *qp, struct bnxt_qplib_cq *cq,
		     u32 cq_cons, u32 sw_sq_cons, u32 cqe_sq_cons)
{
	struct bnxt_qplib_q *sq = &qp->sq;
	struct bnxt_qplib_swq *swq;
#ifdef WA9060_DELAY
	int diff, delay;
#else
	u32 peek_sw_cq_cons, peek_raw_cq_cons, peek_sq_cons_idx;
	struct cq_base *peek_hwcqe, **peek_hw_cqe_ptr;
	struct cq_req *peek_req_hwcqe;
	struct cq_terminal *peek_term_hwcqe;
	struct bnxt_qplib_qp *peek_qp;
	struct bnxt_qplib_q *peek_sq;
	int i, rc = 0;
#endif

	/* Normal mode */
#ifdef WA9060_DELAY
	/* Check for the psn_search marking before completing */
	swq = &sq->swq[sw_sq_cons];
	if (swq->psn_search &&
	    swq->psn_search->flags_next_psn & 0x80000000) {
		/* Unmark */
		swq->psn_search->flags_next_psn &= ~0x80000000;
		dev_dbg(&cq->hwq.pdev->dev,
			"FP: Process Req cq_cons=0x%x qp=0x%x sq cons sw=0x%x cqe=0x%x marked!\n",
			cq_cons, qp->id, sw_sq_cons, cqe_sq_cons);
		/* Delay statically from sw_sq_cons to cqe_sq_cons */
		if (sw_sq_cons <= cqe_sq_cons)
			diff = cqe_sq_cons - sw_sq_cons;
		else
			diff = sq->hwq.max_elements - sw_sq_cons + cqe_sq_cons;
		/* Delay a max of 30ms */
		delay = min_t(int, diff >> 1, 30);
		dev_dbg(&cq->hwq.pdev->dev, "WA 9060, diff = 0x%x delay = 0x%x\n",
			diff, delay);
		mdelay(delay);
	}
	return 0;
#else
	/* Check for the psn_search marking before completing */
	swq = &sq->swq[sw_sq_cons];
	if (swq->psn_search &&
	    swq->psn_search->flags_next_psn & 0x80000000) {
		/* Unmark */
		swq->psn_search->flags_next_psn &= ~0x80000000;
		dev_dbg(&cq->hwq.pdev->dev,
			"FP: Process Req cq_cons=0x%x qp=0x%x sq cons sw=0x%x cqe=0x%x marked!\n",
			cq_cons, qp->id, sw_sq_cons, cqe_sq_cons);
		sq->condition = true;
		sq->send_phantom = true;

		/* TODO: Only ARM if the previous SQE is ARMALL */
		bnxt_qplib_arm_cq(cq, DBR_DBR_TYPE_CQ_ARMALL);

		rc = -EAGAIN;
		goto out;
	}
	if (sq->condition == true) {
		/* Peek at the completions */
		peek_raw_cq_cons = cq->hwq.cons;
		peek_sw_cq_cons = cq_cons;
		i = cq->hwq.max_elements;
		while (i--) {
			peek_sw_cq_cons = HWQ_CMP((peek_sw_cq_cons), &cq->hwq);
			peek_hw_cqe_ptr = (struct cq_base **)cq->hwq.pbl_ptr;
			peek_hwcqe = &peek_hw_cqe_ptr[CQE_PG(peek_sw_cq_cons)]
						     [CQE_IDX(peek_sw_cq_cons)];
			/* If the next hwcqe is VALID */
			if (CQE_CMP_VALID(peek_hwcqe, peek_raw_cq_cons,
					  cq->hwq.max_elements)) {
				/* If the next hwcqe is a REQ */
				switch (peek_hwcqe->cqe_type_toggle &
					CQ_BASE_CQE_TYPE_MASK) {
				case CQ_BASE_CQE_TYPE_REQ:
					peek_req_hwcqe = (struct cq_req *)
							 peek_hwcqe;
					peek_qp = (struct bnxt_qplib_qp *)
						le64_to_cpu(
						peek_req_hwcqe->qp_handle);
					peek_sq = &peek_qp->sq;
					peek_sq_cons_idx = HWQ_CMP(le16_to_cpu(
						peek_req_hwcqe->sq_cons_idx - 1)
						, &sq->hwq);
					/* If the hwcqe's sq's wr_id matches */
					if (peek_sq == sq &&
					    sq->swq[peek_sq_cons_idx].wr_id ==
					    BNXT_QPLIB_FENCE_WRID) {
						/* Unbreak only if the phantom
						   comes back */
						dev_dbg(&cq->hwq.pdev->dev,
							"FP: Process Req qp=0x%x current sq cons sw=0x%x cqe=0x%x",
							qp->id, sw_sq_cons,
							cqe_sq_cons);
						sq->condition = false;
						sq->single = true;
						sq->phantom_cqe_cnt++;
						dev_dbg(&cq->hwq.pdev->dev,
							"qp %#x condition restored at peek cq_cons=%#x sq_cons_idx %#x, phantom_cqe_cnt: %d unmark\n",
							peek_qp->id,
							peek_sw_cq_cons,
							peek_sq_cons_idx,
							sq->phantom_cqe_cnt);
						rc = 0;
						goto out;
					}
					break;

				case CQ_BASE_CQE_TYPE_TERMINAL:
					/* In case the QP has gone into the
					   error state */
					peek_term_hwcqe = (struct cq_terminal *)
							  peek_hwcqe;
					peek_qp = (struct bnxt_qplib_qp *)
						le64_to_cpu(
						peek_term_hwcqe->qp_handle);
					if (peek_qp == qp) {
						sq->condition = false;
						rc = 0;
						goto out;
					}
					break;
				default:
					break;
				}
				/* Valid but not the phantom, so keep looping */
			} else {
				/* Not valid yet, just exit and wait */
				rc = -EINVAL;
				goto out;
			}
			peek_sw_cq_cons++;
			peek_raw_cq_cons++;
		}
		dev_err(&cq->hwq.pdev->dev,
			"Should not have come here! cq_cons=0x%x qp=0x%x sq cons sw=0x%x hw=0x%x",
			cq_cons, qp->id, sw_sq_cons, cqe_sq_cons);
		rc = -EINVAL;
	}
out:
	return rc;
#endif
}

static int bnxt_qplib_cq_process_req(struct bnxt_qplib_cq *cq,
				     struct cq_req *hwcqe,
				     struct bnxt_qplib_cqe **pcqe, int *budget,
				     u32 cq_cons, struct bnxt_qplib_qp **lib_qp)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *sq;
	struct bnxt_qplib_cqe *cqe;
	u32 sw_sq_cons, cqe_sq_cons;
#ifdef ENABLE_FP_SPINLOCK
	unsigned long flags;
#endif
	struct bnxt_qplib_swq *swq;
	int rc = 0;

	qp = (struct bnxt_qplib_qp *)le64_to_cpu(hwcqe->qp_handle);
	dev_dbg(&cq->hwq.pdev->dev, "FP: Process Req qp=0x%p", qp);
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: Process Req qp is NULL");
		return -EINVAL;
	}
	sq = &qp->sq;

	cqe_sq_cons = HWQ_CMP(le16_to_cpu(hwcqe->sq_cons_idx), &sq->hwq);
	if (cqe_sq_cons > sq->hwq.max_elements) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Process req reported ");
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: sq_cons_idx 0x%x which exceeded max 0x%x",
			cqe_sq_cons, sq->hwq.max_elements);
		return -EINVAL;
	}
#ifdef ENABLE_FP_SPINLOCK
	spin_lock_irqsave(&sq->hwq.lock, flags);
#endif

	/* Require to walk the sq's swq to fabricate CQEs for all previously
	 * signaled SWQEs due to CQE aggregation from the current sq cons
	 * to the cqe_sq_cons
	 */
	cqe = *pcqe;
	while (*budget) {
		sw_sq_cons = HWQ_CMP(sq->hwq.cons, &sq->hwq);
		if (sw_sq_cons == cqe_sq_cons)
			/* Done */
			break;

		swq = &sq->swq[sw_sq_cons];
		memset(cqe, 0, sizeof(*cqe));
		cqe->opcode = CQ_BASE_CQE_TYPE_REQ;
		cqe->qp_handle = (u64)qp;
		cqe->src_qp = qp->id;
		cqe->wr_id = swq->wr_id;
#ifndef WA9060_DELAY
		if (cqe->wr_id == BNXT_QPLIB_FENCE_WRID)
			goto skip;
#endif
		cqe->type = swq->type;

		/* For the last CQE, check for status.  For errors, regardless
		 * of the request being signaled or not, it must complete with
		 * the hwcqe error status
		 */
		if (HWQ_CMP((sw_sq_cons + 1), &sq->hwq) == cqe_sq_cons &&
		    hwcqe->status != CQ_REQ_STATUS_OK) {
			cqe->status = hwcqe->status;
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: CQ Processed Req ");
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: wr_id[%d] = 0x%llx with status 0x%x",
				sw_sq_cons, cqe->wr_id, cqe->status);
			cqe++;
			(*budget)--;
			/* Must block new posting of SQ and RQ */
			qp->state = CMDQ_MODIFY_QP_NEW_STATE_ERR;
			sq->condition = false;
			sq->single = false;
			/* Add qp to flush list of the CQ */
			bnxt_qplib_add_flush_qp(qp);
		} else {
			if (swq->flags & SQ_SEND_FLAGS_SIGNAL_COMP) {
				/* Before we complete, do WA 9060 */
				if (do_wa9060(qp, cq, cq_cons, sw_sq_cons,
					      cqe_sq_cons)) {
					*lib_qp = qp;
					goto out;
				}

				dev_dbg(&cq->hwq.pdev->dev,
					"QPLIB: FP: CQ Processed Req ");
				dev_dbg(&cq->hwq.pdev->dev,
					"QPLIB: wr_id[%d] = 0x%llx ",
					sw_sq_cons, cqe->wr_id);
				dev_dbg(&cq->hwq.pdev->dev,
					"QPLIB: with status 0x%x", cqe->status);
				cqe->status = CQ_REQ_STATUS_OK;
				cqe++;
				(*budget)--;
			}
		}
#ifndef WA9060_DELAY
skip:
#endif
		sq->hwq.cons++;
		if (sq->single == true)
			break;
	}
out:
	*pcqe = cqe;
	if (HWQ_CMP(sq->hwq.cons, &sq->hwq) != cqe_sq_cons) {
		/* Out of budget */
		rc = -EAGAIN;
		goto done;
	}
	/* Back to normal completion mode only after it has completed all of
	   the WC for this CQE */
	sq->single = false;
done:
#ifdef ENABLE_FP_SPINLOCK
	spin_unlock_irqrestore(&sq->hwq.lock, flags);
#endif
	return rc;
}

static int bnxt_qplib_cq_process_res_rc(struct bnxt_qplib_cq *cq,
					struct cq_res_rc *hwcqe,
					struct bnxt_qplib_cqe **pcqe,
					int *budget)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *rq;
	struct bnxt_qplib_srq *srq;
	struct bnxt_qplib_cqe *cqe;
	u64 wr_id_idx;
#ifdef ENABLE_FP_SPINLOCK
	unsigned long flags;
#endif
	int rc = 0;

	qp = (struct bnxt_qplib_qp *)le64_to_cpu(hwcqe->qp_handle);
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev, "QPLIB: process_cq RC qp is NULL");
		return -EINVAL;
	}
	cqe = *pcqe;
	cqe->opcode = hwcqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK;
	cqe->length = le32_to_cpu(hwcqe->length);
	cqe->immdata_or_invrkey = le32_to_cpu(hwcqe->imm_data_or_inv_r_key);
	cqe->mr_handle = le64_to_cpu(hwcqe->mr_handle);
	cqe->flags = le16_to_cpu(hwcqe->flags);
	cqe->status = hwcqe->status;
	cqe->qp_handle = (u64)qp;

	wr_id_idx = le64_to_cpu(hwcqe->srq_or_rq_wr_id &
				CQ_RES_RC_SRQ_OR_RQ_WR_ID_MASK);
	if (cqe->flags & CQ_RES_RC_FLAGS_SRQ_SRQ) {
		srq = qp->srq;
		if (!srq) {
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: SRQ used but not defined??");
			return -EINVAL;
		}
		if (wr_id_idx > srq->hwq.max_elements) {
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: CQ Process RC ");
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: wr_id idx 0x%llx exceeded SRQ max 0x%x",
				wr_id_idx, srq->hwq.max_elements);
			return -EINVAL;
		}
#ifdef ENABLE_FP_SPINLOCK
		spin_lock_irqsave(&srq->hwq.lock, flags);
#endif
		cqe->wr_id = srq->swq[wr_id_idx].wr_id;
		dev_dbg(&srq->hwq.pdev->dev,
			"QPLIB: FP: CQ Processed RC SRQ wr_id[%lld] = 0x%llx",
			wr_id_idx, cqe->wr_id);
		cqe++;
		(*budget)--;
		srq->hwq.cons++;
		*pcqe = cqe;
#ifdef ENABLE_FP_SPINLOCK
		spin_unlock_irqrestore(&srq->hwq.lock, flags);
#endif
	} else {
		rq = &qp->rq;
		if (wr_id_idx > rq->hwq.max_elements) {
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: CQ Process RC ");
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: wr_id idx 0x%llx exceeded RQ max 0x%x",
				wr_id_idx, rq->hwq.max_elements);
			return -EINVAL;
		}
#ifdef ENABLE_FP_SPINLOCK
		spin_lock_irqsave(&rq->hwq.lock, flags);
#endif

		cqe->wr_id = rq->swq[wr_id_idx].wr_id;
		dev_dbg(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Processed RC RQ wr_id[%lld] = 0x%llx",
			wr_id_idx, cqe->wr_id);
		cqe++;
		(*budget)--;
		rq->hwq.cons++;
		*pcqe = cqe;

		if (hwcqe->status != CQ_RES_RC_STATUS_OK)
			 /* Add qp to flush list of the CQ */
			bnxt_qplib_add_flush_qp(qp);

#ifdef ENABLE_FP_SPINLOCK
		spin_unlock_irqrestore(&rq->hwq.lock, flags);
#endif
	}
	return rc;
}

static int bnxt_qplib_cq_process_res_ud(struct bnxt_qplib_cq *cq,
					struct cq_res_ud *hwcqe,
					struct bnxt_qplib_cqe **pcqe,
					int *budget)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *rq;
	struct bnxt_qplib_srq *srq;
	struct bnxt_qplib_cqe *cqe;
	u64 wr_id_idx;
#ifdef ENABLE_FP_SPINLOCK
	unsigned long flags;
#endif
	int rc = 0;

	qp = (struct bnxt_qplib_qp *)le64_to_cpu(hwcqe->qp_handle);
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev, "QPLIB: process_cq UD qp is NULL");
		return -EINVAL;
	}
	cqe = *pcqe;
	cqe->opcode = hwcqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK;
	cqe->length = le32_to_cpu(hwcqe->length);
	cqe->immdata_or_invrkey = le32_to_cpu(hwcqe->imm_data);
	cqe->flags = le16_to_cpu(hwcqe->flags);
	cqe->status = hwcqe->status;
	cqe->qp_handle = (u64)qp;
	memcpy(cqe->smac, hwcqe->src_mac, 6);
	wr_id_idx = le64_to_cpu(hwcqe->src_qp_high_srq_or_rq_wr_id
				& CQ_RES_UD_SRQ_OR_RQ_WR_ID_MASK);
	cqe->src_qp = le16_to_cpu(hwcqe->src_qp_low) |
				(hwcqe->src_qp_high_srq_or_rq_wr_id &
				 CQ_RES_UD_SRC_QP_HIGH_MASK >> 8);

	if (cqe->flags & CQ_RES_RC_FLAGS_SRQ_SRQ) {
		srq = qp->srq;
		if (!srq) {
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: SRQ used but not defined??");
			return -EINVAL;
		}
		if (wr_id_idx > srq->hwq.max_elements) {
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: CQ Process UD ");
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: wr_id idx 0x%llx exceeded SRQ max 0x%x",
				wr_id_idx, srq->hwq.max_elements);
			return -EINVAL;
		}
#ifdef ENABLE_FP_SPINLOCK
		spin_lock_irqsave(&srq->hwq.lock, flags);
#endif
		cqe->wr_id = srq->swq[wr_id_idx].wr_id;
		dev_dbg(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Processed UD SRQ wr_id[%lld] = 0x%llx",
			wr_id_idx, cqe->wr_id);
		cqe++;
		(*budget)--;
		srq->hwq.cons++;
		*pcqe = cqe;
#ifdef ENABLE_FP_SPINLOCK
		spin_unlock_irqrestore(&srq->hwq.lock, flags);
#endif
	} else {
		rq = &qp->rq;
		if (wr_id_idx > rq->hwq.max_elements) {
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: CQ Process UD ");
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: wr_id idx 0x%llx exceeded RQ max 0x%x",
				wr_id_idx, rq->hwq.max_elements);
			return -EINVAL;
		}
#ifdef ENABLE_FP_SPINLOCK
		spin_lock_irqsave(&rq->hwq.lock, flags);
#endif

		cqe->wr_id = rq->swq[wr_id_idx].wr_id;
		dev_dbg(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Processed UD RQ wr_id[%lld] = 0x%llx",
			 wr_id_idx, cqe->wr_id);
		cqe++;
		(*budget)--;
		rq->hwq.cons++;
		*pcqe = cqe;

		if (hwcqe->status != CQ_RES_RC_STATUS_OK)
			  /* Add qp to flush list of the CQ */
			bnxt_qplib_add_flush_qp(qp);

#ifdef ENABLE_FP_SPINLOCK
		spin_unlock_irqrestore(&rq->hwq.lock, flags);
#endif
	}
	return rc;
}

static int bnxt_qplib_cq_process_res_raweth_qp1(struct bnxt_qplib_cq *cq,
						struct cq_res_raweth_qp1 *hwcqe,
						struct bnxt_qplib_cqe **pcqe,
						int *budget)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *rq;
	struct bnxt_qplib_srq *srq;
	struct bnxt_qplib_cqe *cqe;
	u64 wr_id_idx;
#ifdef ENABLE_FP_SPINLOCK
	unsigned long flags;
#endif
	int rc = 0;

	qp = (struct bnxt_qplib_qp *)le64_to_cpu(hwcqe->qp_handle);
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: process_cq Raw/QP1 qp is NULL");
		return -EINVAL;
	}
	cqe = *pcqe;
	cqe->opcode = hwcqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK;
	cqe->flags = le16_to_cpu(hwcqe->flags);
	cqe->qp_handle = (u64)qp;

	wr_id_idx = le64_to_cpu(hwcqe->raweth_qp1_payload_offset_srq_or_rq_wr_id
				& CQ_RES_RAWETH_QP1_SRQ_OR_RQ_WR_ID_MASK);
	cqe->src_qp = qp->id;
	if (qp->id == 1 && !cqe->length) {
		/* Add workaround for the length misdetection */
		cqe->length = 296;
	} else {
		cqe->length = le16_to_cpu(hwcqe->length);
	}
	cqe->pkey_index = qp->pkey_index;
	memcpy(cqe->smac, qp->smac, 6);

	cqe->raweth_qp1_flags = le16_to_cpu(hwcqe->raweth_qp1_flags);
	cqe->raweth_qp1_flags2 = le16_to_cpu(hwcqe->raweth_qp1_flags2);
	dev_dbg(&cq->hwq.pdev->dev,
		 "QPLIB: raweth_qp1_flags = 0x%x raweth_qp1_flags2 = 0x%x\n",
		 cqe->raweth_qp1_flags, cqe->raweth_qp1_flags2);

	if (cqe->flags & CQ_RES_RAWETH_QP1_FLAGS_SRQ_SRQ) {
		srq = qp->srq;
		if (!srq) {
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: SRQ used but not defined??");
			return -EINVAL;
		}
		if (wr_id_idx > srq->hwq.max_elements) {
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: CQ Process Raw/QP1 ");
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: wr_id idx 0x%llx exceeded SRQ max 0x%x",
				wr_id_idx, srq->hwq.max_elements);
			return -EINVAL;
		}
#ifdef ENABLE_FP_SPINLOCK
		spin_lock_irqsave(&srq->hwq.lock, flags);
#endif
		cqe->wr_id = srq->swq[wr_id_idx].wr_id;
		dev_dbg(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Processed Raw/QP1 SRQ ");
		dev_dbg(&cq->hwq.pdev->dev,
			"QPLIB: wr_id[%lld] = 0x%llx with status = 0x%x",
			wr_id_idx, cqe->wr_id, hwcqe->status);
		cqe++;
		(*budget)--;
		srq->hwq.cons++;
		*pcqe = cqe;
#ifdef ENABLE_FP_SPINLOCK
		spin_unlock_irqrestore(&srq->hwq.lock, flags);
#endif
	} else {
		rq = &qp->rq;
		if (wr_id_idx > rq->hwq.max_elements) {
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: FP: CQ Process Raw/QP1 RQ wr_id ");
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: ix 0x%llx exceeded RQ max 0x%x",
				wr_id_idx, rq->hwq.max_elements);
			return -EINVAL;
		}
#ifdef ENABLE_FP_SPINLOCK
		spin_lock_irqsave(&rq->hwq.lock, flags);
#endif

		cqe->wr_id = rq->swq[wr_id_idx].wr_id;
		dev_dbg(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Processed Raw/QP1 RQ ");
		dev_dbg(&cq->hwq.pdev->dev,
			"QPLIB: wr_id[%lld] = 0x%llx with status = 0x%x",
			wr_id_idx, cqe->wr_id, hwcqe->status);
		cqe++;
		(*budget)--;
		rq->hwq.cons++;
		*pcqe = cqe;

		if (hwcqe->status != CQ_RES_RC_STATUS_OK)
			  /* Add qp to flush list of the CQ */
			bnxt_qplib_add_flush_qp(qp);
#ifdef ENABLE_FP_SPINLOCK
		spin_unlock_irqrestore(&rq->hwq.lock, flags);
#endif
	}
	return rc;
}

static int bnxt_qplib_cq_process_terminal(struct bnxt_qplib_cq *cq,
					  struct cq_terminal *hwcqe,
					  struct bnxt_qplib_cqe **pcqe,
					  int *budget)
{
	struct bnxt_qplib_qp *qp;
	struct bnxt_qplib_q *sq, *rq;
	struct bnxt_qplib_cqe *cqe;
	u32 sw_cons = 0, cqe_cons;
#ifdef ENABLE_FP_SPINLOCK
	unsigned long flags;
#endif
	int rc = 0;
	u8 opcode = 0;

	/* Check the Status */
	if (hwcqe->status != CQ_TERMINAL_STATUS_OK)
		dev_warn(&cq->hwq.pdev->dev,
			 "QPLIB: FP: CQ Process Terminal Error status = 0x%x",
			 hwcqe->status);

	qp = (struct bnxt_qplib_qp *)le64_to_cpu(hwcqe->qp_handle);
	if (!qp) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Process terminal qp is NULL");
		return -EINVAL;
	}
	dev_dbg(&cq->hwq.pdev->dev,
		"QPLIB: FP: CQ Process terminal for qp (0x%x)", qp->id);
	/* Must block new posting of SQ and RQ */
	qp->state = CMDQ_MODIFY_QP_NEW_STATE_ERR;

	sq = &qp->sq;
	rq = &qp->rq;

	cqe_cons = le16_to_cpu(hwcqe->sq_cons_idx);
	if (cqe_cons == 0xFFFF)
		goto do_rq;

	if (cqe_cons > sq->hwq.max_elements) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Process terminal reported ");
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: sq_cons_idx 0x%x which exceeded max 0x%x",
			cqe_cons, sq->hwq.max_elements);
		goto do_rq;
	}
#ifdef ENABLE_FP_SPINLOCK
	spin_lock_irqsave(&sq->hwq.lock, flags);
#endif
	/* Terminal CQE can also include aggregated successful CQEs prior.
	   So we must complete all CQEs from the current sq's cons to the
	   cq_cons with status OK */
	cqe = *pcqe;
	while (*budget) {
		sw_cons = HWQ_CMP(sq->hwq.cons, &sq->hwq);
		if (sw_cons == cqe_cons)
			break;
		if (sq->swq[sw_cons].flags & SQ_SEND_FLAGS_SIGNAL_COMP) {
			memset(cqe, 0, sizeof(*cqe));
			cqe->status = CQ_REQ_STATUS_OK;
			cqe->opcode = CQ_BASE_CQE_TYPE_REQ;
			cqe->qp_handle = (u64)qp;
			cqe->src_qp = qp->id;
			cqe->wr_id = sq->swq[sw_cons].wr_id;
			cqe->type = sq->swq[sw_cons].type;
			dev_dbg(&cq->hwq.pdev->dev,
				"QPLIB: FP: CQ Processed terminal Req ");
			dev_dbg(&cq->hwq.pdev->dev,
				"QPLIB: wr_id[%d] = 0x%llx with status 0x%x",
				sw_cons, cqe->wr_id, cqe->status);
			cqe++;
			(*budget)--;
		}
		sq->hwq.cons++;
	}
	*pcqe = cqe;
	if (!budget && sw_cons != cqe_cons) {
		/* Out of budget */
		rc = -EAGAIN;
		goto sq_done;
	}
sq_done:
#ifdef ENABLE_FP_SPINLOCK
	spin_unlock_irqrestore(&sq->hwq.lock, flags);
#endif
	if (rc)
		return rc;
do_rq:
	cqe_cons = le16_to_cpu(hwcqe->rq_cons_idx);
	if (cqe_cons == 0xFFFF) {
		goto done;
	} else if (cqe_cons > rq->hwq.max_elements) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Processed terminal ");
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: reported rq_cons_idx 0x%x exceeds max 0x%x",
			cqe_cons, rq->hwq.max_elements);
		goto done;
	}
#ifdef ENABLE_FP_SPINLOCK
	spin_lock_irqsave(&rq->hwq.lock, flags);
#endif
	/* Terminal CQE requires all posted RQEs to complete with FLUSHED_ERR
	   from the current rq->cons to the rq->prod regardless what the
	   rq->cons the terminal CQE indicates */
	switch (qp->type) {
	case CMDQ_CREATE_QP1_TYPE_GSI:
		opcode = CQ_BASE_CQE_TYPE_RES_RAWETH_QP1;
		break;
	case CMDQ_CREATE_QP_TYPE_RC:
		opcode = CQ_BASE_CQE_TYPE_RES_RC;
		break;
	case CMDQ_CREATE_QP_TYPE_UD:
		opcode = CQ_BASE_CQE_TYPE_RES_UD;
		break;
	}

	/* Add qp to flush list of the CQ */
	bnxt_qplib_add_flush_qp(qp);
#ifdef ENABLE_FP_SPINLOCK
	spin_unlock_irqrestore(&rq->hwq.lock, flags);
#endif
done:
	return rc;
}

static int bnxt_qplib_cq_process_cutoff(struct bnxt_qplib_cq *cq,
					struct cq_cutoff *hwcqe)
{
	/* Check the Status */
	if (hwcqe->status != CQ_CUTOFF_STATUS_OK) {
		dev_err(&cq->hwq.pdev->dev,
			"QPLIB: FP: CQ Process Cutoff Error status = 0x%x",
			hwcqe->status);
		return -EINVAL;
	}
	clear_bit(CQ_FLAGS_RESIZE_IN_PROG, &cq->flags);
	wake_up_interruptible(&cq->waitq);

	dev_dbg(&cq->hwq.pdev->dev, "QPLIB: FP: CQ Processed Cutoff");
	return 0;
}

int bnxt_qplib_process_flush_list(struct bnxt_qplib_cq *cq,
				struct bnxt_qplib_cqe *cqe,
				int num_cqes)
{
	struct bnxt_qplib_qp *qp = NULL;
	u32 budget = num_cqes;

	spin_lock(&cq->flush_lock);
	list_for_each_entry(qp, &cq->sqf_head, sq_flush) {
		dev_dbg(&cq->hwq.pdev->dev,
			"QPLIB: FP: Flushing SQ QP= %p",
			qp);
		__flush_sq(&qp->sq, qp, &cqe, &budget);
	}

	list_for_each_entry(qp, &cq->rqf_head, rq_flush) {
		dev_dbg(&cq->hwq.pdev->dev,
			"QPLIB: FP: Flushing RQ QP= %p",
			qp);
		__flush_rq(&qp->rq, qp, &cqe, &budget);
	}
	spin_unlock(&cq->flush_lock);

	return num_cqes - budget;
}

int bnxt_qplib_poll_cq(struct bnxt_qplib_cq *cq, struct bnxt_qplib_cqe *cqe,
		       int num_cqes, struct bnxt_qplib_qp **lib_qp)
{
	struct cq_base *hw_cqe, **hw_cqe_ptr;
	u32 sw_cons, raw_cons;
	int budget, rc = 0;

#ifdef ENABLE_FP_SPINLOCK
	unsigned long flags;
	spin_lock_irqsave(&cq->hwq.lock, flags);
#endif
	raw_cons = cq->hwq.cons;
	budget = num_cqes;

	while (budget) {
		sw_cons = HWQ_CMP(raw_cons, &cq->hwq);
		hw_cqe_ptr = (struct cq_base **)cq->hwq.pbl_ptr;
		hw_cqe = &hw_cqe_ptr[CQE_PG(sw_cons)][CQE_IDX(sw_cons)];

		/* Check for Valid bit */
		if (!CQE_CMP_VALID(hw_cqe, raw_cons, cq->hwq.max_elements))
			break;

		/* From the device's respective CQE format to qplib_wc*/
		switch (hw_cqe->cqe_type_toggle & CQ_BASE_CQE_TYPE_MASK) {
		case CQ_BASE_CQE_TYPE_REQ:
			rc = bnxt_qplib_cq_process_req(cq,
					(struct cq_req *)hw_cqe, &cqe, &budget,
					sw_cons, lib_qp);
			break;
		case CQ_BASE_CQE_TYPE_RES_RC:
			rc = bnxt_qplib_cq_process_res_rc(cq,
						(struct cq_res_rc *)hw_cqe, &cqe,
						&budget);
			break;
		case CQ_BASE_CQE_TYPE_RES_UD:
			rc = bnxt_qplib_cq_process_res_ud(cq,
						(struct cq_res_ud *)hw_cqe, &cqe,
						&budget);
			break;
		case CQ_BASE_CQE_TYPE_RES_RAWETH_QP1:
			rc = bnxt_qplib_cq_process_res_raweth_qp1(cq,
						(struct cq_res_raweth_qp1 *)
						hw_cqe, &cqe, &budget);
			break;
		case CQ_BASE_CQE_TYPE_TERMINAL:
			rc = bnxt_qplib_cq_process_terminal(cq,
						(struct cq_terminal *)hw_cqe,
						&cqe, &budget);
			break;
		case CQ_BASE_CQE_TYPE_CUT_OFF:
			bnxt_qplib_cq_process_cutoff(cq,
						(struct cq_cutoff *)hw_cqe);
			/* Done processing this CQ */
			goto exit;
		default:
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: process_cq unknown type 0x%lx",
				hw_cqe->cqe_type_toggle &
				CQ_BASE_CQE_TYPE_MASK);
			rc = -EINVAL;
			break;
		}
		if (rc < 0) {
			dev_dbg(&cq->hwq.pdev->dev,
				"QPLIB: process_cqe rc = 0x%x", rc);
			if (rc == -EAGAIN)
				break;
			/* Error while processing the CQE, just skip to the
			   next one */
			dev_err(&cq->hwq.pdev->dev,
				"QPLIB: process_cqe error rc = 0x%x", rc);
		}
		raw_cons++;
	}
	if (cq->hwq.cons != raw_cons) {
		cq->hwq.cons = raw_cons;
		bnxt_qplib_arm_cq(cq, DBR_DBR_TYPE_CQ);
	}
exit:
#ifdef ENABLE_FP_SPINLOCK
	spin_unlock_irqrestore(&cq->hwq.lock, flags);
#endif
	return num_cqes - budget;
}

void bnxt_qplib_req_notify_cq(struct bnxt_qplib_cq *cq, u32 arm_type)
{
	unsigned long flags;

	spin_lock_irqsave(&cq->hwq.lock, flags);
	if (arm_type)
		bnxt_qplib_arm_cq(cq, arm_type);
	/* Using simple spin_lock since we have already disabled interrupt */
	spin_lock(&cq->compl_lock);
	cq->arm_state = true;
	spin_unlock(&cq->compl_lock);
	spin_unlock_irqrestore(&cq->hwq.lock, flags);
}

int bnxt_qplib_flush_cq(struct bnxt_qplib_cq *cq)
{
	unsigned long flags;

	spin_lock_irqsave(&cq->hwq.lock, flags);
	bnxt_qplib_arm_cq(cq, DBR_DBR_TYPE_CQ_CUTOFF_ACK);
	spin_unlock_irqrestore(&cq->hwq.lock, flags);
	return 0;
}
