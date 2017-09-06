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
 * Author: Devesh Sharma <devesh.sharma@broadcom.com>
 *
 * Description: Main component of the bnxt_re driver
 */

#if HAVE_CONFIG_H
#include <config.h>
#endif                          /* HAVE_CONFIG_H */

#include <assert.h>
#include <stdlib.h>
#include <stdio.h>
#include <string.h>
#include <unistd.h>
#include <signal.h>
#include <errno.h>
#include <pthread.h>
#include <malloc.h>
#include <sys/mman.h>
#include <netinet/in.h>
#include <unistd.h>

#include "bnxt_re_main.h"
#include "bnxt_re_verbs.h"

int bnxt_re_query_device(struct ibv_context *ibvctx,
			 struct ibv_device_attr *dev_attr)
{
	struct ibv_query_device cmd;
	uint64_t fw_ver;
	int status;

	memset(dev_attr, 0, sizeof(struct ibv_device_attr));
	status = ibv_cmd_query_device(ibvctx, dev_attr, &fw_ver,
				      &cmd, sizeof(cmd));
	return status;
}

int bnxt_re_query_port(struct ibv_context *ibvctx, uint8_t port,
		       struct ibv_port_attr *port_attr)
{
	struct ibv_query_port cmd;

	memset(port_attr, 0, sizeof(struct ibv_port_attr));
	return ibv_cmd_query_port(ibvctx, port, port_attr, &cmd, sizeof(cmd));
}

struct ibv_pd *bnxt_re_alloc_pd(struct ibv_context *ibvctx)
{
	struct ibv_alloc_pd cmd;
	struct bnxt_re_pd_resp resp;
	struct bnxt_re_context *ucntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);
	struct bnxt_re_pd *pd;

	pd = calloc(1, sizeof(*pd));
	if (!pd)
		return NULL;

	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_alloc_pd(ibvctx, &pd->ibvpd, &cmd, sizeof(cmd),
			     &resp.resp, sizeof(resp)))
		goto out;

	pd->pdid = resp.pdid;
	/* Map DB page now. */
	if (!ucntx->udpi.dbpage) {
		ucntx->udpi.dpindx = resp.dpi;
		ucntx->udpi.dbpage = mmap(NULL, dev->pg_size, PROT_WRITE,
					  MAP_SHARED, ibvctx->cmd_fd,
					  resp.dbr);
		if (ucntx->udpi.dbpage == MAP_FAILED) {
			(void)ibv_cmd_dealloc_pd(&pd->ibvpd);
			goto out;
		}
		pthread_spin_init(&ucntx->udpi.db_lock,
				  PTHREAD_PROCESS_PRIVATE);
	}

	return &pd->ibvpd;
out:
	free(pd);
	return NULL;
}

int bnxt_re_free_pd(struct ibv_pd *ibvpd)
{
	struct bnxt_re_pd *pd = to_bnxt_re_pd(ibvpd);
	int status;

	status = ibv_cmd_dealloc_pd(ibvpd);
	if (status)
		return status;
	/* DPI un-map will be during uninit_ucontext */
	free(pd);

	return 0;
}

struct ibv_mr *bnxt_re_reg_mr(struct ibv_pd *ibvpd, void *sva, size_t len,
			      int access)
{
	struct bnxt_re_mr *mr;
	struct ibv_reg_mr cmd;
	struct bnxt_re_mr_resp resp;

	mr = calloc(1, sizeof(*mr));
	if (!mr)
		return NULL;

	if (ibv_cmd_reg_mr(ibvpd, sva, len, (uint64_t)sva, access, &mr->ibvmr,
			   &cmd, sizeof(cmd), &resp.resp, sizeof(resp))) {
		free(mr);
		return NULL;
	}

	return &mr->ibvmr;
}

int bnxt_re_dereg_mr(struct ibv_mr *ibvmr)
{
	int status;
	struct bnxt_re_mr *mr = (struct bnxt_re_mr *)ibvmr;

	status = ibv_cmd_dereg_mr(ibvmr);
	if (status)
		return status;
	free(mr);

	return 0;
}

struct ibv_cq *bnxt_re_create_cq(struct ibv_context *ibvctx, int ncqe,
				 struct ibv_comp_channel *channel, int vec)
{
	struct bnxt_re_cq *cq;
	struct bnxt_re_cq_req cmd;
	struct bnxt_re_cq_resp resp;

	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvctx);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvctx->device);

	if (ncqe > dev->max_cq_depth)
		return NULL;

	cq = calloc(1, sizeof(*cq));
	if (!cq)
		return NULL;

	cq->cqq.depth = roundup_pow_of_two(ncqe + 1);
	if (cq->cqq.depth > dev->max_cq_depth + 1)
		cq->cqq.depth = dev->max_cq_depth + 1;
	cq->cqq.stride = dev->cqe_size;
	if (bnxt_re_alloc_aligned(&cq->cqq, dev->pg_size))
		goto fail;

	pthread_spin_init(&cq->cqq.qlock, PTHREAD_PROCESS_PRIVATE);

	cmd.cq_va = (uint64_t)cq->cqq.va;
	cmd.cq_handle = (uint64_t)cq;

	memset(&resp, 0, sizeof(resp));
	if (ibv_cmd_create_cq(ibvctx, ncqe, channel, vec,
			      &cq->ibvcq, &cmd.cmd, sizeof(cmd),
			      &resp.resp, sizeof(resp))) {
		/* TODO: Print something */
		goto cmdfail;
	}

	cq->cqid = resp.cqid;
	cq->phase = resp.phase;
	cq->cqq.tail = resp.tail;
	cq->udpi = &cntx->udpi;

	INIT_DBLY_LIST_HEAD(&cq->sfhead);
	INIT_DBLY_LIST_HEAD(&cq->rfhead);

	return &cq->ibvcq;
cmdfail:
	bnxt_re_free_aligned(&cq->cqq);
fail:
	free(cq);
	return NULL;
}

static int bnxt_re_poll_kernel_cq(struct bnxt_re_cq *cq)
{
	struct ibv_wc tmp_wc;
	int rc;

	rc = ibv_cmd_poll_cq(&cq->ibvcq, 1, &tmp_wc);
	if (rc)
		fprintf(stderr, "ibv_cmd_poll_cq failed: %d\n", rc);
	return rc;
}

/*
 * Function to complete the last steps in CQ resize. Invoke poll function
 * in the kernel driver; this serves as a signal to the driver to complete CQ
 * resize steps required. Free memory mapped for the original CQ and switch
 * over to the memory mapped for CQ with the new size. Finally Ack the Cutoff
 * CQE. This function must be called under cq->cqq.lock.
 */
void bnxt_re_resize_cq_complete(struct bnxt_re_cq *cq)
{
	bnxt_re_poll_kernel_cq(cq);
	bnxt_re_free_aligned(&cq->cqq);

	/*
	 * We don't want to memcpy() the entire cqq structure below; otherwise
	 * we'd end up overwriting cq->cqq.lock that is held by the caller.
	 * So we copy the members piecemeal. Reset cqq.head first before
	 * ringing the doorbell.
	 */
	cq->cqq.head = cq->resize_cqq.head;
	bnxt_re_ring_cq_arm_db(cq, BNXT_RE_QUE_TYPE_CQ_CUT_ACK);

	cq->cqq.va = cq->resize_cqq.va;
	cq->cqq.bytes = cq->resize_cqq.bytes;
	cq->cqq.depth = cq->resize_cqq.depth;
	cq->cqq.tail = cq->resize_cqq.tail;
	cq->cqq.stride = cq->resize_cqq.stride;
	cq->flags &= ~BNXT_RE_CQ_RESIZING;

	memset(&cq->resize_cqq, 0, sizeof(cq->cqq));
}

int bnxt_re_resize_cq(struct ibv_cq *ibvcq, int ncqe)
{
	struct bnxt_re_dev *dev = to_bnxt_re_dev(ibvcq->context->device);
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);
	struct bnxt_re_queue *resize_cqq = &cq->resize_cqq;
	struct bnxt_re_resize_cq_req cmd;
	struct ibv_resize_cq_resp resp;
	int status = 0;

	if (ncqe > dev->max_cq_depth)
		return -EINVAL;

	pthread_spin_lock(&cq->cqq.qlock);

	if (cq->flags & BNXT_RE_CQ_RESIZING) {
		fprintf(stderr, "%s: RESIZE_CQ already in progress\n",
			__func__);
		status = -EBUSY;
		goto done;
	}

	memset(resize_cqq, 0, sizeof(*resize_cqq));
	resize_cqq->depth = roundup_pow_of_two(ncqe + 1);
	if (resize_cqq->depth > dev->max_cq_depth + 1)
		resize_cqq->depth = dev->max_cq_depth + 1;
	if (resize_cqq->depth == cq->cqq.depth) {
		fprintf(stderr, "%s: cur-depth: %d new-depth: %d\n", __func__,
			cq->cqq.depth, resize_cqq->depth);
		goto done;
	}

	resize_cqq->stride = dev->cqe_size;
	status = bnxt_re_alloc_aligned(resize_cqq, dev->pg_size);
	if (status)
		goto done;

	cmd.cq_va = (uint64_t)resize_cqq->va;
	memset(&resp, 0, sizeof(resp));
	status = ibv_cmd_resize_cq(ibvcq, ncqe, &cmd.cmd, sizeof(cmd), &resp,
				   sizeof(resp));
	if (status) {
		bnxt_re_free_aligned(resize_cqq);
		goto done;
	}

	cq->flags |= BNXT_RE_CQ_RESIZING;

done:
	pthread_spin_unlock(&cq->cqq.qlock);
	return status;
}

int bnxt_re_destroy_cq(struct ibv_cq *ibvcq)
{
	int status;
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);

	status = ibv_cmd_destroy_cq(ibvcq);
	if (status)
		return status;

	bnxt_re_free_aligned(&cq->cqq);
	free(cq);

	return 0;
}

static uint8_t bnxt_re_poll_err_scqe(struct bnxt_re_qp *qp,
				     struct ibv_wc *ibvwc,
				     struct bnxt_re_bcqe *hdr,
				     struct bnxt_re_req_cqe *scqe, int *cnt)
{
	struct bnxt_re_queue *sq = qp->sqq;
	struct bnxt_re_context *cntx;
	struct bnxt_re_wrid *swrid;
	struct bnxt_re_psns *spsn;
	struct bnxt_re_cq *scq;
	uint32_t head = sq->head;
	uint8_t status;

	scq = to_bnxt_re_cq(qp->ibvqp.send_cq);
	cntx = to_bnxt_re_context(scq->ibvcq.context);
	swrid = &qp->swrid[head];
	spsn = swrid->psns;

	*cnt = 1;
	status = (hdr->flg_st_typ_ph >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	ibvwc->status = bnxt_re_to_ibv_wc_status(status, true);
	ibvwc->wc_flags = 0;
	ibvwc->wr_id = swrid->wrid;
	ibvwc->qp_num = qp->qpid;
	ibvwc->opcode = (le32toh(spsn->opc_spsn) >>
			BNXT_RE_PSNS_OPCD_SHIFT) &
			BNXT_RE_PSNS_OPCD_MASK;
	ibvwc->byte_len = 0;

	bnxt_re_incr_head(qp->sqq);

	if (qp->qpst != IBV_QPS_ERR)
		qp->qpst = IBV_QPS_ERR;
	pthread_spin_lock(&cntx->fqlock);
	bnxt_re_list_add_node(&qp->snode, &scq->sfhead);
	pthread_spin_unlock(&cntx->fqlock);

	return false;
}

static uint8_t bnxt_re_poll_success_scqe(struct bnxt_re_qp *qp,
				struct ibv_wc *ibvwc, struct bnxt_re_bcqe *hdr,
				struct bnxt_re_req_cqe *scqe, int *cnt)
{
	struct bnxt_re_queue *sq = qp->sqq;
	struct bnxt_re_wrid *swrid;
	struct bnxt_re_psns *spsn;
	uint8_t pcqe = false;
	uint32_t head = sq->head;
	uint32_t cindx;

	swrid = &qp->swrid[head];
	spsn = swrid->psns;
	cindx = scqe->con_indx;

	/* TODO: Signaling check still needs reveiw. */
	if (!(swrid->sig & IBV_SEND_SIGNALED)) {
		*cnt = 0;
	 } else {
		ibvwc->status = IBV_WC_SUCCESS;
		ibvwc->wc_flags = 0;
		ibvwc->qp_num = qp->qpid;
		ibvwc->wr_id = swrid->wrid;
		ibvwc->opcode = (le32toh(spsn->opc_spsn) >>
				BNXT_RE_PSNS_OPCD_SHIFT) &
				BNXT_RE_PSNS_OPCD_MASK;
		if (ibvwc->opcode == IBV_WC_RDMA_READ ||
		    ibvwc->opcode == IBV_WC_COMP_SWAP ||
		    ibvwc->opcode == IBV_WC_FETCH_ADD)
			ibvwc->byte_len = swrid->bytes;

		*cnt = 1;
	}

	bnxt_re_incr_head(sq);
	if (sq->head != cindx)
		pcqe = true;

	return pcqe;
}

static uint8_t bnxt_re_poll_scqe(struct bnxt_re_qp *qp, struct ibv_wc *ibvwc,
				 void *cqe, int *cnt)
{
	struct bnxt_re_bcqe *hdr;
	struct bnxt_re_req_cqe *scqe;
	uint8_t status, pcqe = false;

	scqe = cqe;
	hdr = cqe + sizeof(struct bnxt_re_req_cqe);

	status = (hdr->flg_st_typ_ph >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	if (status == BNXT_RE_REQ_ST_OK)
		pcqe = bnxt_re_poll_success_scqe(qp, ibvwc, hdr, scqe, cnt);
	else
		pcqe = bnxt_re_poll_err_scqe(qp, ibvwc, hdr, scqe, cnt);

	return pcqe;
}

static int bnxt_re_poll_err_rcqe(struct bnxt_re_qp *qp, struct ibv_wc *ibvwc,
				 struct bnxt_re_bcqe *hdr, void *cqe)
{
	struct bnxt_re_queue *rq;
	struct bnxt_re_wrid *rwrid;
	struct bnxt_re_cq *rcq;
	struct bnxt_re_context *cntx;
	uint8_t status;

	rcq = to_bnxt_re_cq(qp->ibvqp.recv_cq);
	cntx = to_bnxt_re_context(rcq->ibvcq.context);

	if (!qp->srq) {
		rq = qp->rqq;
		rwrid = &qp->rwrid[rq->head];
	} else {
		rq = qp->srq->srqq;
		rwrid = &qp->srq->srwrid[rq->head];
	}

	status = (hdr->flg_st_typ_ph >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	/* skip h/w flush errors */
	if (status == BNXT_RE_RSP_ST_HW_FLUSH)
		return 0;

	ibvwc->status = bnxt_re_to_ibv_wc_status(status, false);
	ibvwc->wr_id = rwrid->wrid;
	ibvwc->qp_num = qp->qpid;
	ibvwc->opcode = IBV_WC_RECV;
	ibvwc->byte_len = 0;
	ibvwc->wc_flags = 0;
	if (qp->qptyp == IBV_QPT_UD)
		ibvwc->src_qp = 0;
	bnxt_re_incr_head(rq);

	if (!qp->srq) {
		pthread_spin_lock(&cntx->fqlock);
		bnxt_re_list_add_node(&qp->rnode, &rcq->rfhead);
		pthread_spin_unlock(&cntx->fqlock);
	}

	return 1;
}

static void bnxt_re_fill_ud_cqe(struct ibv_wc *ibvwc,
				struct bnxt_re_bcqe *hdr, void *cqe)
{
	struct bnxt_re_ud_cqe *ucqe = cqe;
	uint32_t qpid;

	qpid = ((hdr->qphi_rwrid >> BNXT_RE_BCQE_SRCQP_SHIFT) &
		BNXT_RE_BCQE_SRCQP_SHIFT) << 0x10; /* higher 8 bits of 24 */
	qpid |= (ucqe->qplo_mac >> BNXT_RE_UD_CQE_SRCQPLO_SHIFT) &
		BNXT_RE_UD_CQE_SRCQPLO_MASK; /*lower 16 of 24 */
	ibvwc->src_qp = qpid;
	ibvwc->wc_flags |= IBV_WC_GRH;
	/*IB-stack ABI in user do not ask for MAC to be reported. */
}

static void bnxt_re_poll_success_rcqe(struct bnxt_re_qp *qp,
				      struct ibv_wc *ibvwc,
				      struct bnxt_re_bcqe *hdr, void *cqe)
{
	struct bnxt_re_queue *rq;
	struct bnxt_re_wrid *rwrid;
	struct bnxt_re_rc_cqe *rcqe;
	uint8_t flags, is_imm, is_rdma;

	rcqe = cqe;
	if (!qp->srq) {
		rq = qp->rqq;
		rwrid = &qp->rwrid[rq->head];
	} else {
		rq = qp->srq->srqq;
		rwrid = &qp->srq->srwrid[rq->head];
	}

	ibvwc->status = IBV_WC_SUCCESS;
	ibvwc->wr_id = rwrid->wrid;
	ibvwc->qp_num = qp->qpid;
	ibvwc->byte_len = rcqe->length;
	ibvwc->opcode = IBV_WC_RECV;

	flags = (hdr->flg_st_typ_ph >> BNXT_RE_BCQE_FLAGS_SHIFT) &
		 BNXT_RE_BCQE_FLAGS_MASK;
	is_imm = (flags & BNXT_RE_RC_FLAGS_IMM_MASK) >>
		     BNXT_RE_RC_FLAGS_IMM_SHIFT;
	is_rdma = (flags & BNXT_RE_RC_FLAGS_RDMA_MASK) >>
		   BNXT_RE_RC_FLAGS_RDMA_SHIFT;
	ibvwc->wc_flags = 0;
	if (is_imm) {
		ibvwc->wc_flags |= IBV_WC_WITH_IMM;
		/* The HW is returning imm_data in little-endian format,
		 * swap to Big Endian as expected by application
		 */
		ibvwc->imm_data = swab32(rcqe->imm_key);
		if (is_rdma)
			ibvwc->opcode = IBV_WC_RECV_RDMA_WITH_IMM;
	}

	if (qp->qptyp == IBV_QPT_UD) {
		bnxt_re_fill_ud_cqe(ibvwc, hdr, cqe);
	}
#if 0
	if (flags & BNXT_RE_RC_FLAGS_SRQ_RQ_MASK); /* Semicolon */
	       /* SRQ stuff here.*/
#endif
	bnxt_re_incr_head(rq);
}

static uint8_t bnxt_re_poll_rcqe(struct bnxt_re_qp *qp, struct ibv_wc *ibvwc,
				 void *cqe, int *cnt)
{
	struct bnxt_re_bcqe *hdr;
	uint8_t status, pcqe = false;

	hdr = cqe + sizeof(struct bnxt_re_rc_cqe);

	status = (hdr->flg_st_typ_ph >> BNXT_RE_BCQE_STATUS_SHIFT) &
		  BNXT_RE_BCQE_STATUS_MASK;
	*cnt = 1;
	if (status == BNXT_RE_RSP_ST_OK)
		bnxt_re_poll_success_rcqe(qp, ibvwc, hdr, cqe);
	else
		*cnt = bnxt_re_poll_err_rcqe(qp, ibvwc, hdr, cqe);

	return pcqe;
}

static uint8_t bnxt_re_poll_term_cqe(struct bnxt_re_qp *qp,
				     struct ibv_wc *ibvwc, void *cqe, int *cnt)
{
	struct bnxt_re_context *cntx;
	struct bnxt_re_cq *scq, *rcq;
	uint8_t pcqe = false;

	scq = to_bnxt_re_cq(qp->ibvqp.send_cq);
	rcq = to_bnxt_re_cq(qp->ibvqp.recv_cq);
	cntx = to_bnxt_re_context(scq->ibvcq.context);
	/* For now just add the QP to flush list without
	 * considering the index reported in the CQE.
	 * Continue reporting flush completions until the
	 * SQ and RQ are empty.
	 */
	*cnt = 0;
	if (qp->qpst != IBV_QPS_ERR)
		qp->qpst = IBV_QPS_ERR;
	pthread_spin_lock(&cntx->fqlock);
	bnxt_re_list_add_node(&qp->rnode, &rcq->rfhead);
	bnxt_re_list_add_node(&qp->snode, &scq->sfhead);
	pthread_spin_unlock(&cntx->fqlock);

	return pcqe;
}

static int bnxt_re_poll_one(struct bnxt_re_cq *cq, int nwc, struct ibv_wc *wc)
{
	struct bnxt_re_queue *cqq = &cq->cqq;
	struct bnxt_re_qp *qp;
	struct bnxt_re_bcqe *hdr;
	struct bnxt_re_req_cqe *scqe;
	struct bnxt_re_ud_cqe *rcqe;
	void *cqe;
	uint64_t *qp_handle = NULL;
	int type, cnt = 0, dqed = 0, hw_polled = 0;
	uint8_t pcqe = false;

	while (nwc) {
		cqe = cqq->va + cqq->head * bnxt_re_get_cqe_sz();
		bnxt_re_le64_to_host((uint64_t *)cqe, cqq->stride);
		hdr = cqe + sizeof(struct bnxt_re_req_cqe);
		if (!bnxt_re_is_cqe_valid(cq, hdr))
			break;
		type = (hdr->flg_st_typ_ph >> BNXT_RE_BCQE_TYPE_SHIFT) &
			BNXT_RE_BCQE_TYPE_MASK;
		switch (type) {
		case BNXT_RE_WC_TYPE_SEND:
			scqe = cqe;
			qp_handle = (uint64_t *)&scqe->qp_handle;
			qp = (struct bnxt_re_qp *)scqe->qp_handle;
			if (!qp)
				break; /*stale cqe. should be rung.*/
			pcqe = bnxt_re_poll_scqe(qp, wc, cqe, &cnt);
			break;
		case BNXT_RE_WC_TYPE_RECV_RC:
		case BNXT_RE_WC_TYPE_RECV_UD:
			rcqe = cqe;
			qp_handle = (uint64_t *)&rcqe->qp_handle;
			qp = (struct bnxt_re_qp *)rcqe->qp_handle;
			if (!qp)
				break; /*stale cqe. should be rung.*/
			pcqe = bnxt_re_poll_rcqe(qp, wc, cqe, &cnt);
			break;
		case BNXT_RE_WC_TYPE_RECV_RAW:
			break;
		case BNXT_RE_WC_TYPE_TERM:
			scqe = cqe;
			qp_handle = (uint64_t *)&scqe->qp_handle;
			qp = (struct bnxt_re_qp *)scqe->qp_handle;
			if (!qp)
				break;
			pcqe = bnxt_re_poll_term_cqe(qp, wc, cqe, &cnt);
			break;
		case BNXT_RE_WC_TYPE_COFF:
			/* Stop further processing and return */
			bnxt_re_resize_cq_complete(cq);
			return dqed;
		default:
			break;
		};

		if (pcqe)
			goto skipp_real;

		hw_polled++;
		if (qp_handle) {
			*qp_handle = 0x0ULL; /* mark cqe as read */
			qp_handle = NULL;
		}
		bnxt_re_incr_head(&cq->cqq);
		bnxt_re_change_cq_phase(cq);
skipp_real:
		if (cnt) {
			cnt = 0;
			dqed++;
			nwc--;
			wc++;
		}
	}

	if (hw_polled)
		bnxt_re_ring_cq_db(cq);

	return dqed;
}

static int bnxt_re_poll_flush_wcs(struct bnxt_re_queue *que,
				  struct bnxt_re_wrid *wridp,
				  struct ibv_wc *ibvwc, uint32_t qpid,
				  int nwc)
{
	struct bnxt_re_wrid *wrid;
	struct bnxt_re_psns *psns;
	uint32_t cnt = 0, head;
	uint8_t opcode = IBV_WC_RECV;

	while(nwc) {
		if (bnxt_re_is_que_empty(que))
			break;
		head = que->head;
		wrid = &wridp[head];
		if (wrid->psns) {
			psns = wrid->psns;
			opcode = (psns->opc_spsn >> BNXT_RE_PSNS_OPCD_SHIFT) &
				  BNXT_RE_PSNS_OPCD_MASK;
		}

		ibvwc->status = IBV_WC_WR_FLUSH_ERR;
		ibvwc->opcode = opcode;
		ibvwc->wr_id = wrid->wrid;
		ibvwc->qp_num = qpid;
		ibvwc->byte_len = 0;
		ibvwc->wc_flags = 0;

		bnxt_re_incr_head(que);
		nwc--;
		cnt++;
		ibvwc++;
	}

	return cnt;
}

static int bnxt_re_poll_flush_lists(struct bnxt_re_cq *cq, uint32_t nwc,
				    struct ibv_wc *ibvwc)
{
	struct bnxt_re_list_node *cur, *tmp;
	struct bnxt_re_qp *qp;
	struct bnxt_re_queue *que;
	int dqed = 0, left;

	/* Check if flush Qs are empty */
	if (list_empty(&cq->sfhead) && list_empty(&cq->rfhead))
		return 0;

	if (!list_empty(&cq->sfhead)) {
		list_for_each_node_safe(cur, tmp, &cq->sfhead ) {
			qp = list_node(cur, struct bnxt_re_qp, snode);
			que = qp->sqq;
			if (bnxt_re_is_que_empty(que))
				continue;
			dqed = bnxt_re_poll_flush_wcs(que, qp->swrid, ibvwc,
						      qp->qpid, nwc);
		}
	}

	left = nwc - dqed;
	if (!left)
		return dqed;

	if (!list_empty(&cq->rfhead)) {
		list_for_each_node_safe(cur, tmp, &cq->rfhead) {
			qp = list_node(cur, struct bnxt_re_qp, rnode);
			que = qp->rqq;
			if (!que || bnxt_re_is_que_empty(que))
				continue;
			dqed += bnxt_re_poll_flush_wcs(que, qp->rwrid,
						       ibvwc + dqed, qp->qpid,
						       left);
		}
	}

	return dqed;
}

int bnxt_re_poll_cq(struct ibv_cq *ibvcq, int nwc, struct ibv_wc *wc)
{
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvcq->context);
	int dqed, left = 0;

	pthread_spin_lock(&cq->cqq.qlock);
	dqed = bnxt_re_poll_one(cq, nwc, wc);
	pthread_spin_unlock(&cq->cqq.qlock);

	/* Check if anything is there to flush. */
	pthread_spin_lock(&cntx->fqlock);
	left = nwc - dqed;
	if (left)
		dqed += bnxt_re_poll_flush_lists(cq, left, (wc + dqed));
	pthread_spin_unlock(&cntx->fqlock);

	return dqed;
}

void bnxt_re_cleanup_cq(struct bnxt_re_qp *qp, struct bnxt_re_cq *cq)
{
	struct bnxt_re_context *cntx;
	struct bnxt_re_queue *que = &cq->cqq;
	struct bnxt_re_bcqe *hdr;
	struct bnxt_re_req_cqe *scqe;
	struct bnxt_re_rc_cqe *rcqe;
	void *cqe;
	int indx, type;

	cntx = to_bnxt_re_context(cq->ibvcq.context);

	pthread_spin_lock(&que->qlock);
	for(indx = 0; indx < que->depth; indx++) {
		cqe = que->va + indx * bnxt_re_get_cqe_sz();
		hdr = cqe + sizeof(struct bnxt_re_req_cqe);
		type = (hdr->flg_st_typ_ph >> BNXT_RE_BCQE_TYPE_SHIFT) &
			BNXT_RE_BCQE_TYPE_MASK;

		if (type == BNXT_RE_WC_TYPE_COFF)
			continue;
		if (type == BNXT_RE_WC_TYPE_SEND ||
		    type == BNXT_RE_WC_TYPE_TERM) {
			scqe = cqe;
			if (scqe->qp_handle == (uint64_t)qp)
				scqe->qp_handle = 0ULL;
		} else {
			rcqe = cqe;
			if (rcqe->qp_handle == (uint64_t)qp)
				rcqe->qp_handle = 0ULL;
		}

	}
	pthread_spin_unlock(&que->qlock);

	pthread_spin_lock(&cntx->fqlock);
	bnxt_re_list_del_node(&qp->snode, &cq->sfhead);
	bnxt_re_list_del_node(&qp->rnode, &cq->rfhead);
	pthread_spin_unlock(&cntx->fqlock);
}

void bnxt_re_cq_event(struct ibv_cq *ibvcq)
{

}

int bnxt_re_arm_cq(struct ibv_cq *ibvcq, int flags)
{
	struct bnxt_re_cq *cq = to_bnxt_re_cq(ibvcq);

	pthread_spin_lock(&cq->cqq.qlock);
	flags = !flags ? BNXT_RE_QUE_TYPE_CQ_ARMALL :
			 BNXT_RE_QUE_TYPE_CQ_ARMSE;
	bnxt_re_ring_cq_arm_db(cq, flags);
	pthread_spin_unlock(&cq->cqq.qlock);

	return 0;
}

static int bnxt_re_check_qp_limits(struct bnxt_re_context *cntx,
				   struct ibv_qp_init_attr *attr)
{
	struct ibv_device_attr devattr;
	int ret;

	ret = bnxt_re_query_device(&cntx->ibvctx, &devattr);
	if (ret)
		return ret;
	if (attr->cap.max_send_sge > devattr.max_sge)
		return EINVAL;
	if (attr->cap.max_recv_sge > devattr.max_sge)
		return EINVAL;
	if (attr->cap.max_inline_data > BNXT_RE_MAX_INLINE_SIZE)
		return EINVAL;
	if (attr->cap.max_send_wr > devattr.max_qp_wr)
		attr->cap.max_send_wr = devattr.max_qp_wr;
	if (attr->cap.max_recv_wr > devattr.max_qp_wr)
		attr->cap.max_recv_wr = devattr.max_qp_wr;

	return 0;
}

static void bnxt_re_free_queue_ptr(struct bnxt_re_qp *qp)
{
	if (qp->rqq)
		free(qp->rqq);
	if (qp->sqq)
		free(qp->sqq);
}

static int bnxt_re_alloc_queue_ptr(struct bnxt_re_qp *qp,
				   struct ibv_qp_init_attr *attr)
{
	qp->sqq = calloc(1, sizeof(struct bnxt_re_queue));
	if (!qp->sqq)
		return -ENOMEM;
	if (!attr->srq) {
		qp->rqq = calloc(1, sizeof(struct bnxt_re_queue));
		if (!qp->rqq) {
			free(qp->sqq);
			return -ENOMEM;
		}
	}

	return 0;
}

static void bnxt_re_free_queues(struct bnxt_re_qp *qp)
{
	if (qp->rqq) {
		if (qp->rwrid)
			free(qp->rwrid);
		pthread_spin_destroy(&qp->rqq->qlock);
		bnxt_re_free_aligned(qp->rqq);
	}

	if (qp->swrid)
		free(qp->swrid);
	pthread_spin_destroy(&qp->sqq->qlock);
	bnxt_re_free_aligned(qp->sqq);
}

static int bnxt_re_alloc_queues(struct bnxt_re_qp *qp,
				struct ibv_qp_init_attr *attr,
				uint32_t pg_size) {
	struct bnxt_re_queue *que;
	struct bnxt_re_psns *psns;
	uint32_t psn_depth;
	int ret, indx;

	que = qp->sqq;
	que->stride = bnxt_re_get_sqe_sz();
	/* 8916 adjustment */
	que->depth = roundup_pow_of_two(attr->cap.max_send_wr + 1 +
					BNXT_RE_FULL_FLAG_DELTA);

	que->diff = que->depth - attr->cap.max_send_wr;
	/* psn_depth extra entries of size que->stride.*/
	psn_depth = (que->depth * sizeof(struct bnxt_re_psns))/
		     que->stride;
	if ((que->depth * sizeof(struct bnxt_re_psns)) % que->stride)
		psn_depth++;
	que->depth += psn_depth;
	/* PSN-search memory is allocated without checking for
	 * QP-Type. Kenrel driver do not map this memory if it
	 * is UD-qp. UD-qp use this memory to maintain WC-opcode.
	 * See definition of bnxt_re_fill_psns() for the use case.
	 */
	ret = bnxt_re_alloc_aligned(qp->sqq, pg_size);
	if (ret)
		return ret;
	/* exclude psns depth*/
	que->depth -= psn_depth;
	/* start of spsn space sizeof(struct bnxt_re_psns) each. */
	psns = (que->va + que->stride * que->depth);
	pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);
	qp->swrid = calloc(que->depth, sizeof(struct bnxt_re_wrid));
	if (!qp->swrid) {
		ret = -ENOMEM;
		goto fail;
	}

	for (indx = 0 ; indx < que->depth; indx++, psns++)
		qp->swrid[indx].psns = psns;
	qp->cap.max_swr = que->depth;

	if (qp->rqq) {
		que = qp->rqq;
		que->stride = bnxt_re_get_rqe_sz();
		que->depth = roundup_pow_of_two(attr->cap.max_recv_wr + 1);
		 que->diff = que->depth - attr->cap.max_recv_wr;
		ret = bnxt_re_alloc_aligned(qp->rqq, pg_size);
		if (ret)
			goto fail;
		pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);
		/* For RQ only bnxt_re_wri.wrid is used. */
		qp->rwrid = calloc(que->depth, sizeof(struct bnxt_re_wrid));
		if (!qp->rwrid) {
			ret = -ENOMEM;
			goto fail;
		}
		qp->cap.max_rwr = que->depth;
	}

	return 0;

fail:
	bnxt_re_free_queues(qp);
	return ret;
}

struct ibv_qp *bnxt_re_create_qp(struct ibv_pd *ibvpd,
				 struct ibv_qp_init_attr *attr)
{
	struct bnxt_re_qp *qp;
	struct bnxt_re_qp_req req;
	struct bnxt_re_qp_resp resp;
	struct bnxt_re_qpcap *cap;

	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvpd->context);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(cntx->ibvctx.device);

	if (bnxt_re_check_qp_limits(cntx, attr))
		return NULL;

	qp = calloc(1, sizeof(*qp));
	if (!qp)
		return NULL;
	/* alloc queue pointers */
	if (bnxt_re_alloc_queue_ptr(qp, attr))
		goto fail;
	/* alloc queues */
	if (bnxt_re_alloc_queues(qp, attr, dev->pg_size))
		goto failq;
	/* Fill ibv_cmd */
	cap = &qp->cap;
	req.qpsva = (uint64_t)qp->sqq->va;
	req.qprva = qp->rqq ? (uint64_t)qp->rqq->va : 0;
	req.qp_handle = (uint64_t)qp;

	if (ibv_cmd_create_qp(ibvpd, &qp->ibvqp, attr, &req.cmd, sizeof(req),
			      &resp.resp, sizeof(resp))) {
		goto failcmd;
	}

	qp->qpid = resp.qpid;
	qp->qptyp = attr->qp_type;
	qp->qpst = IBV_QPS_RESET;
	qp->scq = to_bnxt_re_cq(attr->send_cq);
	qp->rcq = to_bnxt_re_cq(attr->recv_cq);
	if (attr->srq)
		qp->srq = to_bnxt_re_srq(attr->srq);
	qp->udpi = &cntx->udpi;

	cap->max_ssge = attr->cap.max_send_sge;
	cap->max_rsge = attr->cap.max_recv_sge;
	cap->max_inline = attr->cap.max_inline_data;
	cap->sqsig = attr->sq_sig_all;
	INIT_DBLY_LIST_NODE(&qp->snode);
	INIT_DBLY_LIST_NODE(&qp->rnode);

	return &qp->ibvqp;
failcmd:
	bnxt_re_free_queues(qp);
failq:
	bnxt_re_free_queue_ptr(qp);
fail:
	free(qp);

	return NULL;
}

int bnxt_re_modify_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		      int attr_mask)
{
	struct ibv_modify_qp cmd;
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	int rc;

	rc = ibv_cmd_modify_qp(ibvqp, attr, attr_mask, &cmd, sizeof(cmd));
	if (!rc) {
		if (attr_mask & IBV_QP_STATE)
			qp->qpst = attr->qp_state;
		if (attr_mask & IBV_QP_SQ_PSN)
			qp->sq_psn = attr->sq_psn;
		if (attr_mask & IBV_QP_PATH_MTU)
			qp->mtu = (0x80 << attr->path_mtu);
	}

	return rc;
}

int bnxt_re_query_qp(struct ibv_qp *ibvqp, struct ibv_qp_attr *attr,
		     int attr_mask, struct ibv_qp_init_attr *init_attr)
{
	struct ibv_query_qp cmd;
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	int rc;

	rc = ibv_cmd_query_qp(ibvqp, attr, attr_mask, init_attr,
			      &cmd, sizeof(cmd));
	if (!rc)
		qp->qpst = ibvqp->state;

	return rc;
}

int bnxt_re_destroy_qp(struct ibv_qp *ibvqp)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	int status;

	status = ibv_cmd_destroy_qp(ibvqp);
	if (status)
		return status;
	bnxt_re_cleanup_cq(qp, qp->rcq);
	bnxt_re_cleanup_cq(qp, qp->scq);
	bnxt_re_free_queues(qp);
	bnxt_re_free_queue_ptr(qp);
	free(qp);

	return 0;
}

static inline uint8_t bnxt_re_set_hdr_flags(struct bnxt_re_bsqe *hdr,
					    uint32_t send_flags, uint8_t sqsig)
{
	uint8_t is_inline = false;

	if (send_flags & IBV_SEND_SIGNALED || sqsig)
		hdr->rsv_ws_fl_wt |= ((BNXT_RE_WR_FLAGS_SIGNALED &
				       BNXT_RE_HDR_FLAGS_MASK) <<
				       BNXT_RE_HDR_FLAGS_SHIFT);

	if (send_flags & IBV_SEND_FENCE)
		/*TODO: See when RD fence can be used. */
		hdr->rsv_ws_fl_wt |= ((BNXT_RE_WR_FLAGS_UC_FENCE &
				       BNXT_RE_HDR_FLAGS_MASK) <<
				       BNXT_RE_HDR_FLAGS_SHIFT);

	if (send_flags & IBV_SEND_SOLICITED)
		hdr->rsv_ws_fl_wt |= ((BNXT_RE_WR_FLAGS_SE &
				       BNXT_RE_HDR_FLAGS_MASK) <<
				       BNXT_RE_HDR_FLAGS_SHIFT);
	if (send_flags & IBV_SEND_INLINE) {
		hdr->rsv_ws_fl_wt |= ((BNXT_RE_WR_FLAGS_INLINE &
				       BNXT_RE_HDR_FLAGS_MASK) <<
				       BNXT_RE_HDR_FLAGS_SHIFT);
		is_inline = true;
	}

	return is_inline;
}

static int bnxt_re_build_sge(struct bnxt_re_sge *sge, struct ibv_sge *sg_list,
			     uint32_t num_sge, uint8_t is_inline) {
	int indx, length = 0;
	void *dst;

	if (!num_sge) {
		memset(sge, 0, sizeof(*sge));
		return 0;
	}

	if (is_inline) {
		dst = sge;
		for (indx = 0; indx < num_sge; indx++) {
			length += sg_list[indx].length;
			if (length > BNXT_RE_MAX_INLINE_SIZE)
				return -ENOMEM;
			memcpy(dst, (void *)sg_list[indx].addr,
			       sg_list[indx].length);
			dst = dst + sg_list[indx].length;
		}
	} else {
		for (indx = 0; indx < num_sge; indx++) {
			sge[indx].pa_lo = sg_list[indx].addr & 0xFFFFFFFFUL;
			sge[indx].pa_hi = sg_list[indx].addr >> 32;
			sge[indx].lkey = sg_list[indx].lkey;
			sge[indx].length = sg_list[indx].length;
			length += sg_list[indx].length;
		}
	}

	return length;
}

static void bnxt_re_fill_psns(struct bnxt_re_qp *qp, struct bnxt_re_psns *psns,
			      uint8_t opcode, uint32_t len)
{
	uint32_t pkt_cnt = 0, nxt_psn;

	memset(psns, 0, sizeof(*psns));
	if (qp->qptyp == IBV_QPT_RC) {
		psns->opc_spsn = qp->sq_psn & BNXT_RE_PSNS_SPSN_MASK;
		pkt_cnt = (len / qp->mtu);
		if (len % qp->mtu)
			pkt_cnt++;
		nxt_psn = ((qp->sq_psn + pkt_cnt) & BNXT_RE_PSNS_NPSN_MASK);
		psns->flg_npsn = nxt_psn;
		qp->sq_psn = nxt_psn;
	}
	opcode = bnxt_re_ibv_wr_to_wc_opcd(opcode);
	psns->opc_spsn |= ((opcode & BNXT_RE_PSNS_OPCD_MASK) <<
			    BNXT_RE_PSNS_OPCD_SHIFT);
	*(uint64_t *)psns = htole64(*(uint64_t *)psns);
}

static void bnxt_re_fill_wrid(struct bnxt_re_wrid *wrid, struct ibv_send_wr *wr,
			      uint32_t len, uint8_t sqsig )
{
	wrid->wrid = wr->wr_id;
	wrid->bytes = len;
	wrid->sig = 0;
	if (wr->send_flags & IBV_SEND_SIGNALED || sqsig)
		wrid->sig = IBV_SEND_SIGNALED;
}

static int bnxt_re_build_send_sqe(struct bnxt_re_qp *qp, void *wqe,
				  struct ibv_send_wr *wr, uint8_t is_inline)
{
	struct bnxt_re_bsqe *hdr = wqe;
	struct bnxt_re_send *sqe = ((void *)wqe + sizeof(struct bnxt_re_bsqe));
	struct bnxt_re_sge *sge = ((void *)wqe + bnxt_re_get_sqe_hdr_sz());
	uint32_t wrlen;
	int len;
	uint8_t opcode, wqesize;

	len = bnxt_re_build_sge(sge, wr->sg_list, wr->num_sge, is_inline);
	if (len < 0)
		return len;
	sqe->length = len;

	/* Fill Header */
	opcode = bnxt_re_ibv_to_bnxt_wr_opcd(wr->opcode);
	if (opcode == BNXT_RE_WR_OPCD_INVAL)
		return -EINVAL;
	hdr->rsv_ws_fl_wt |= (opcode & BNXT_RE_HDR_WT_MASK);

	if (is_inline) {
		wrlen = get_aligned(len, 16);
		wqesize = wrlen >> 4;
	} else {
		wqesize = wr->num_sge;
	}
	wqesize += (bnxt_re_get_sqe_hdr_sz() >> 4);
	/* HW requires wqe size has room for atleast one SGE even if none
	 * was supplied by application
	 */
	if (!wr->num_sge)
		wqesize++;
	hdr->rsv_ws_fl_wt |= (wqesize & BNXT_RE_HDR_WS_MASK) <<
			      BNXT_RE_HDR_WS_SHIFT;
	return len;
}

static int bnxt_re_build_ud_sqe(struct bnxt_re_qp *qp, void *wqe,
				struct ibv_send_wr *wr, uint8_t is_inline)
{
	struct bnxt_re_send *sqe = ((void *)wqe + sizeof(struct bnxt_re_bsqe));
	struct bnxt_re_ah *ah;
	uint32_t len;

	len = bnxt_re_build_send_sqe(qp, wqe, wr, is_inline);
	sqe->qkey = wr->wr.ud.remote_qkey;
	sqe->dst_qp = wr->wr.ud.remote_qpn;
	if (!wr->wr.ud.ah) {
		len = -EINVAL;
		goto bail;
	}
	ah = to_bnxt_re_ah(wr->wr.ud.ah);
	sqe->avid = ah->avid & 0xFFFFF;
bail:
	return len;
}

static int bnxt_re_build_rdma_sqe(struct bnxt_re_qp *qp, void *wqe,
				  struct ibv_send_wr *wr, uint8_t is_inline)
{
	struct bnxt_re_rdma *sqe = ((void *)wqe + sizeof(struct bnxt_re_bsqe));
	uint32_t len;

	len = bnxt_re_build_send_sqe(qp, wqe, wr, is_inline);
	sqe->rva_lo = wr->wr.rdma.remote_addr & 0xFFFFFFFFUL;
	sqe->rva_hi = (wr->wr.rdma.remote_addr >> 32);
	sqe->rkey = wr->wr.rdma.rkey;

	return len;
}

static int bnxt_re_build_cns_sqe(struct bnxt_re_qp *qp, void *wqe,
				 struct ibv_send_wr *wr)
{
	struct bnxt_re_bsqe *hdr = wqe;
	struct bnxt_re_atomic *sqe = ((void *)wqe +
				      sizeof(struct bnxt_re_bsqe));
	uint32_t len;

	len = bnxt_re_build_send_sqe(qp, wqe, wr, false);
	hdr->key_immd = wr->wr.atomic.rkey;
	sqe->rva_lo = lower_32_bits(wr->wr.atomic.remote_addr);
	sqe->rva_hi = upper_32_bits(wr->wr.atomic.remote_addr);
	sqe->cmp_dt_lo = lower_32_bits(wr->wr.atomic.compare_add);
	sqe->cmp_dt_hi = upper_32_bits(wr->wr.atomic.compare_add);
	sqe->swp_dt_lo = lower_32_bits(wr->wr.atomic.swap);
	sqe->swp_dt_hi = upper_32_bits(wr->wr.atomic.swap);

	return len;
}

static int bnxt_re_build_fna_sqe(struct bnxt_re_qp *qp, void *wqe,
				 struct ibv_send_wr *wr)
{
	struct bnxt_re_bsqe *hdr = wqe;
	struct bnxt_re_atomic *sqe = ((void *)wqe +
				      sizeof(struct bnxt_re_bsqe));
	uint32_t len;

	len = bnxt_re_build_send_sqe(qp, wqe, wr, false);
	hdr->key_immd = wr->wr.atomic.rkey;
	sqe->rva_lo = lower_32_bits(wr->wr.atomic.remote_addr);
	sqe->rva_hi = upper_32_bits(wr->wr.atomic.remote_addr);
	sqe->cmp_dt_lo = lower_32_bits(wr->wr.atomic.compare_add);
	sqe->cmp_dt_hi = upper_32_bits(wr->wr.atomic.compare_add);

	return len;
}

#ifdef HAVE_WR_BIND_MW
static int bnxt_re_build_bind_sqe(struct bnxt_re_qp *qp, void *wqe,
				  struct ibv_send_wr *wr)
{
	struct bnxt_re_bsqe *hdr = wqe;
	struct bnxt_re_bind *sqe = ((void *)wqe +
				    sizeof(struct bnxt_re_bsqe));
	struct ibv_mw *mw = wr->bind_mw.mw;
	uint32_t acc, opcode;
	uint32_t hdr_acc = 0, hdr_typezb = 0;

	/* Build wqe header */
	opcode = bnxt_re_ibv_to_bnxt_wr_opcd(wr->opcode);
	if (opcode == BNXT_RE_WR_OPCD_INVAL)
		return -EINVAL;

	acc = wr->bind_mw.bind_info.mw_access_flags;
	if (mw->type == IBV_MW_TYPE_1 && (acc & IBV_ACCESS_ZERO_BASED))
		return -EINVAL;

	if (acc & IBV_ACCESS_REMOTE_READ)
		hdr_acc |= BNXT_RE_WR_BIND_ACC_RRD;
	if (acc & IBV_ACCESS_REMOTE_WRITE)
		hdr_acc |= BNXT_RE_WR_BIND_ACC_RWR;
	if (acc & IBV_ACCESS_REMOTE_ATOMIC)
		hdr_acc |= BNXT_RE_WR_BIND_ACC_RAT;
	hdr->rsv_ws_fl_wt |= (hdr_acc << BNXT_RE_WR_BIND_ACC_SHIFT);
	hdr->rsv_ws_fl_wt |= (opcode & BNXT_RE_HDR_WT_MASK);

	if (mw->type == IBV_MW_TYPE_2) {
		hdr_typezb |= BNXT_RE_MEMW_TYPE_2;
		if (acc & IBV_ACCESS_ZERO_BASED)
			hdr_typezb |= BNXT_RE_WR_BIND_ACC_ZBVA;
	}
	hdr->key_immd = hdr_typezb;

	/* Fill rest of the WQE */
	sqe->plkey = wr->bind_mw.bind_info.mr->lkey;
	sqe->lkey = wr->bind_mw.rkey;
	sqe->va_hi = upper_32_bits((uint64_t)wr->bind_mw.bind_info.addr);
	sqe->va_lo = lower_32_bits((uint64_t)wr->bind_mw.bind_info.addr);
	sqe->len_hi = 0;
	sqe->len_lo = wr->bind_mw.bind_info.length;

	return 0;
}

static int bnxt_re_build_inval_sqe(struct bnxt_re_qp *qp, void *wqe,
				   struct ibv_send_wr *wr)
{
	struct bnxt_re_bsqe *hdr = wqe;
	uint32_t len;

	len = bnxt_re_build_send_sqe(qp, wqe, wr, false);
	hdr->key_immd = swab32(wr->imm_data);
	/* rest of sqe is unused. */
	return len;
}
#endif

int bnxt_re_post_send(struct ibv_qp *ibvqp, struct ibv_send_wr *wr,
		      struct ibv_send_wr **bad)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct bnxt_re_queue *sq = qp->sqq;
	struct bnxt_re_bsqe *hdr;
	struct bnxt_re_wrid *wrid;
	struct bnxt_re_psns *psns;
	void *sqe;
	int ret = 0, bytes = 0;
	uint8_t is_inline = false;

	pthread_spin_lock(&sq->qlock);
	while (wr) {
		if ((qp->qpst != IBV_QPS_RTS) && (qp->qpst != IBV_QPS_SQD)) {
			*bad = wr;
			pthread_spin_unlock(&sq->qlock);
			return EINVAL;
		}

		if ((qp->qptyp == IBV_QPT_UD) && (wr->opcode != IBV_WR_SEND &&
		    wr->opcode != IBV_WR_SEND_WITH_IMM)) {
			*bad = wr;
			pthread_spin_unlock(&sq->qlock);
			return EINVAL;
		}

		if (bnxt_re_is_que_full(sq) ||
		    wr->num_sge > qp->cap.max_ssge) {
			*bad = wr;
			pthread_spin_unlock(&sq->qlock);
			return ENOMEM;
		}

		sqe = (void *) (sq->va + (sq->tail * sq->stride));
		wrid = &qp->swrid[sq->tail];
		psns = wrid->psns;

		memset(sqe, 0, bnxt_re_get_sqe_sz());
		hdr = sqe;
		is_inline = bnxt_re_set_hdr_flags(hdr, wr->send_flags,
						  qp->cap.sqsig);
		switch (wr->opcode) {
		case IBV_WR_SEND_WITH_IMM:
			/* HW is swapping the immediate data before sending it
			 * out on the wire. To workaround this, swap the
			 * imm_data value as sent by the application so that the
			 *  value going out on the wire is in big-endian format.
			 */
			hdr->key_immd = swab32(wr->imm_data);
		case IBV_WR_SEND:
			if (qp->qptyp == IBV_QPT_UD)
				bytes = bnxt_re_build_ud_sqe(qp, sqe, wr,
							     is_inline);
			else
				bytes = bnxt_re_build_send_sqe(qp, sqe, wr,
							       is_inline);
			break;
		case IBV_WR_RDMA_WRITE_WITH_IMM:
			hdr->key_immd = swab32(wr->imm_data);
		case IBV_WR_RDMA_WRITE:
			bytes = bnxt_re_build_rdma_sqe(qp, sqe, wr, is_inline);
			break;
		case IBV_WR_RDMA_READ:
			bytes = bnxt_re_build_rdma_sqe(qp, sqe, wr, false);
			break;
		case IBV_WR_ATOMIC_CMP_AND_SWP:
			bytes = bnxt_re_build_cns_sqe(qp, sqe, wr);
			break;
		case IBV_WR_ATOMIC_FETCH_AND_ADD:
			bytes = bnxt_re_build_fna_sqe(qp, sqe, wr);
			break;
#ifdef HAVE_WR_BIND_MW
		case IBV_WR_BIND_MW:
			bytes = bnxt_re_build_bind_sqe(qp, sqe, wr);
			break;
		case IBV_WR_LOCAL_INV:
			bytes = bnxt_re_build_inval_sqe(qp, sqe, wr);
			break;
#endif
		default :
			bytes = -EINVAL;
			break;
		}

		if (bytes < 0) {
			ret = (bytes == -EINVAL) ? EINVAL : ENOMEM;
			*bad = wr;
			break;
		}

		bnxt_re_fill_wrid(wrid, wr, bytes, qp->cap.sqsig);
		bnxt_re_fill_psns(qp, psns, wr->opcode, bytes);
		bnxt_re_host_to_le64((uint64_t*)sqe, sq->stride);
		bnxt_re_incr_tail(sq);
		qp->wqe_cnt++;
		wr = wr->next;
		udma_to_device_barrier();

		bnxt_re_ring_sq_db(qp);

		/* WA for HW Bug 9208 */
		if (qp->wqe_cnt == BNXT_RE_UD_QP_HW_STALL && qp->qptyp ==
		    IBV_QPT_UD) {
			struct ibv_qp_attr attr;
			int attr_mask;

			attr_mask = IBV_QP_STATE;
			attr.qp_state = IBV_QPS_RTS;
			bnxt_re_modify_qp(&qp->ibvqp, &attr, attr_mask);
			qp->wqe_cnt = 0;
		}
	}

	pthread_spin_unlock(&sq->qlock);
	return ret;
}

static int bnxt_re_build_rqe(struct bnxt_re_qp *qp, struct ibv_recv_wr *wr,
			     void *rqe) {
	struct bnxt_re_brqe *hdr = rqe;
	struct bnxt_re_rqe *rwr;
	struct bnxt_re_sge *sge;
	struct bnxt_re_wrid *wrid;
	int wqe_sz, len;

	rwr = (rqe + sizeof(struct bnxt_re_brqe));
	sge = (rqe + bnxt_re_get_rqe_hdr_sz());
	wrid = &qp->rwrid[qp->rqq->tail];

	len = bnxt_re_build_sge(sge, wr->sg_list, wr->num_sge, false);
	hdr->rsv_ws_fl_wt = BNXT_RE_WR_OPCD_RECV;
	wqe_sz = wr->num_sge + (bnxt_re_get_rqe_hdr_sz() >> 4); /* 16B chunk */
	/* HW requires wqe size has room for atleast one SGE even if none
	 * was supplied by application
	 */
	if (!wr->num_sge)
		wqe_sz++;
	hdr->rsv_ws_fl_wt |= ((wqe_sz & BNXT_RE_HDR_WS_MASK) <<
			       BNXT_RE_HDR_WS_SHIFT);
	rwr->wrid = qp->rqq->tail;

	/* Fill wrid */
	wrid->wrid = wr->wr_id;
	wrid->bytes = len; /* N.A. for RQE */
	wrid->sig = 0; /* N.A. for RQE */

	return len;
}

int bnxt_re_post_recv(struct ibv_qp *ibvqp, struct ibv_recv_wr *wr,
		      struct ibv_recv_wr **bad)
{
	struct bnxt_re_qp *qp = to_bnxt_re_qp(ibvqp);
	struct bnxt_re_queue *rq = qp->rqq;
	void *rqe;
	int ret;

	pthread_spin_lock(&rq->qlock);
	while (wr) {
		/* check QP state, abort if it is ERR or RST */
		if (qp->qpst == IBV_QPS_RESET || qp->qpst == IBV_QPS_ERR) {
			*bad = wr;
			pthread_spin_unlock(&rq->qlock);
			return EINVAL;
		}

		if (bnxt_re_is_que_full(rq) ||
		    wr->num_sge > qp->cap.max_rsge) {
			pthread_spin_unlock(&rq->qlock);
			*bad = wr;
			return ENOMEM;
		}

		rqe = (void *) (rq->va + (rq->tail * rq->stride));
		memset(rqe, 0, bnxt_re_get_rqe_sz());
		ret = bnxt_re_build_rqe(qp, wr, rqe);
		if (ret < 0) {
			pthread_spin_unlock(&rq->qlock);
			*bad = wr;
			return ENOMEM;
		}

		bnxt_re_host_to_le64((uint64_t*)rqe, rq->stride);
		bnxt_re_incr_tail(rq);
		wr = wr->next;

		udma_to_device_barrier();
		bnxt_re_ring_rq_db(qp);
	}
	pthread_spin_unlock(&rq->qlock);

	return 0;
}

static void bnxt_re_srq_free_queue_ptr(struct bnxt_re_srq *srq)
{
	if (srq && srq->srqq)
		free(srq->srqq);
	if (srq)
		free(srq);
}

static struct bnxt_re_srq *bnxt_re_srq_alloc_queue_ptr(void)
{
	struct bnxt_re_srq *srq;

	srq = calloc(1, sizeof(struct bnxt_re_srq));
	if (!srq)
		return NULL;

	srq->srqq = calloc(1, sizeof(struct bnxt_re_queue));
	if (!srq->srqq) {
		free(srq);
		return NULL;
	}

	return srq;
}

static void bnxt_re_srq_free_queue(struct bnxt_re_srq *srq)
{
	if (srq->srwrid)
		free(srq->srwrid);
	pthread_spin_destroy(&srq->srqq->qlock);
	bnxt_re_free_aligned(srq->srqq);
}

static int bnxt_re_srq_alloc_queue(struct bnxt_re_srq *srq,
				   struct ibv_srq_init_attr *attr,
				   uint32_t pg_size)
{
	struct bnxt_re_queue *que;
	int ret;

	que = srq->srqq;
	que->depth = roundup_pow_of_two(attr->attr.max_wr + 1);
	que->diff = que->depth - attr->attr.max_wr;
	que->stride = bnxt_re_get_srqe_sz();
	ret = bnxt_re_alloc_aligned(que, pg_size);
	if (ret)
		goto bail;
	pthread_spin_init(&que->qlock, PTHREAD_PROCESS_PRIVATE);
	/* For SRQ only bnxt_re_wrid.wrid is used. */
	srq->srwrid = calloc(que->depth, sizeof(struct bnxt_re_wrid));
	if (!srq->srwrid) {
		ret = -ENOMEM;
		goto bail;
	}
	/*TODO: update actual max depth. */
	return 0;
bail:
	bnxt_re_srq_free_queue(srq);
	return ret;
}

struct ibv_srq *bnxt_re_create_srq(struct ibv_pd *ibvpd,
				   struct ibv_srq_init_attr *attr)
{
	struct bnxt_re_srq *srq;
	struct bnxt_re_srq_req cmd;
	struct bnxt_re_srq_resp resp;
	struct bnxt_re_context *cntx = to_bnxt_re_context(ibvpd->context);
	struct bnxt_re_dev *dev = to_bnxt_re_dev(cntx->ibvctx.device);
	int ret;

	/*TODO: Check max limit on queue depth and sge.*/
	srq = bnxt_re_srq_alloc_queue_ptr();
	if (!srq)
		goto fail;

	if(bnxt_re_srq_alloc_queue(srq, attr, dev->pg_size))
		goto fail;

	cmd.srqva = (uint64_t)srq->srqq->va;
	cmd.srq_handle = (uint64_t)srq;
	ret = ibv_cmd_create_srq(ibvpd, &srq->ibvsrq, attr,
				 &cmd.cmd, sizeof(cmd),
				 &resp.resp, sizeof(resp));
	if (ret)
		goto fail;

	srq->srqid = resp.srqid;
	srq->udpi = &cntx->udpi;
	srq->cap.max_wr = srq->srqq->depth;
	srq->cap.max_sge = attr->attr.max_sge;
	srq->cap.srq_limit = attr->attr.srq_limit;
	srq->pre_count = 0;

	return &srq->ibvsrq;
fail:
	bnxt_re_srq_free_queue_ptr(srq);
	return NULL;
}

int bnxt_re_modify_srq(struct ibv_srq *ibvsrq, struct ibv_srq_attr *attr,
		       int attr_mask)
{
	struct bnxt_re_srq *srq = to_bnxt_re_srq(ibvsrq);
	struct ibv_modify_srq cmd;
	int status = 0;

	status =  ibv_cmd_modify_srq(ibvsrq, attr, attr_mask,
				     &cmd, sizeof(cmd));
	if (!status && ((attr_mask & IBV_SRQ_LIMIT) &&
			(srq->cap.srq_limit != attr->srq_limit))) {
		srq->cap.srq_limit = attr->srq_limit;
	}

	return status;
}

int bnxt_re_destroy_srq(struct ibv_srq *ibvsrq)
{
	struct bnxt_re_srq *srq = to_bnxt_re_srq(ibvsrq);
	int ret;

	ret = ibv_cmd_destroy_srq(ibvsrq);
	if (ret)
		return ret;
	bnxt_re_srq_free_queue(srq);
	bnxt_re_srq_free_queue_ptr(srq);

	return 0;
}

int bnxt_re_query_srq(struct ibv_srq *ibvsrq, struct ibv_srq_attr *attr)
{
	struct ibv_query_srq cmd;

	return ibv_cmd_query_srq(ibvsrq, attr, &cmd, sizeof cmd);
}

static int bnxt_re_build_srqe(struct bnxt_re_srq *srq,
			      struct ibv_recv_wr *wr, void *srqe)
{
	struct bnxt_re_brqe *hdr = srqe;
	struct bnxt_re_rqe *rwr;
	struct bnxt_re_sge *sge;
	struct bnxt_re_wrid *wrid;
	int wqe_sz, len;

	rwr = (srqe + sizeof(struct bnxt_re_brqe));
	sge = (srqe + bnxt_re_get_srqe_hdr_sz());
	wrid = &srq->srwrid[srq->srqq->tail];

	len = bnxt_re_build_sge(sge, wr->sg_list, wr->num_sge, false);
	hdr->rsv_ws_fl_wt = BNXT_RE_WR_OPCD_RECV;
	wqe_sz = wr->num_sge + (bnxt_re_get_srqe_hdr_sz() >> 4); /* 16B align */
	hdr->rsv_ws_fl_wt |= ((wqe_sz & BNXT_RE_HDR_WS_MASK) <<
			       BNXT_RE_HDR_WS_SHIFT);
	rwr->wrid = srq->srqq->tail;

	/* Fill wrid */
	wrid->wrid = wr->wr_id;
	wrid->bytes = len; /* N.A. for RQE */
	wrid->sig = 0; /* N.A. for RQE */

	return len;
}

int bnxt_re_post_srq_recv(struct ibv_srq *ibvsrq, struct ibv_recv_wr *wr,
			  struct ibv_recv_wr **bad)
{
	struct bnxt_re_srq *srq = to_bnxt_re_srq(ibvsrq);
	struct bnxt_re_queue *rq = srq->srqq;
	void *srqe;
	int ret;

	pthread_spin_lock(&rq->qlock);
	while (wr) {
		if (bnxt_re_is_que_full(rq) ||
		    wr->num_sge > srq->cap.max_sge) {
			*bad = wr;
			pthread_spin_unlock(&rq->qlock);
			return ENOMEM;
		}

		srqe = (void *) (rq->va + (rq->tail * rq->stride));
		memset(srqe, 0, bnxt_re_get_srqe_sz());
		ret = bnxt_re_build_srqe(srq, wr, srqe);
		if (ret < 0) {
			pthread_spin_unlock(&rq->qlock);
			*bad = wr;
			return ENOMEM;
		}

		bnxt_re_host_to_le64((uint64_t*)srqe, rq->stride);
		bnxt_re_incr_tail(rq);
		wr = wr->next;

		udma_to_device_barrier();
		bnxt_re_ring_srq_db(srq);
		if ((srq->pre_count < srq->srqq->depth) &&
		    (++srq->pre_count > srq->cap.srq_limit)) {
			srq->pre_count = srq->srqq->depth;
			bnxt_re_ring_srq_arm(srq);
		}
	}
	pthread_spin_unlock(&rq->qlock);

	return 0;
}

struct ibv_ah *bnxt_re_create_ah(struct ibv_pd *ibvpd, struct ibv_ah_attr *attr)
{
	struct bnxt_re_pd *pd;
	struct bnxt_re_context *uctx;
	struct bnxt_re_ah *ah;
	struct ibv_create_ah_resp resp;
	int status;

	pd = to_bnxt_re_pd(ibvpd);
	uctx = to_bnxt_re_context(ibvpd->context);

	ah = calloc(1, sizeof(struct bnxt_re_ah));
	if (!ah) {
		goto failed;
	}

	ah->pd = pd;
	pthread_mutex_lock(&uctx->shlock);
	status = ibv_cmd_create_ah(ibvpd, &ah->ibvah, attr,
				   &resp, sizeof(resp));
	if (status)
	{
		pthread_mutex_unlock(&uctx->shlock);
		free(ah);
		goto failed;
	}
	/* read AV ID now. */
	ah->avid = *(uint32_t *)(uctx->shpg + BNXT_RE_SHPG_AVID_OFFT);
	pthread_mutex_unlock(&uctx->shlock);

	return &ah->ibvah;
failed:
	return NULL;
}

int bnxt_re_destroy_ah(struct ibv_ah *ibvah)
{
	struct bnxt_re_ah *ah;
	int status;

	ah = to_bnxt_re_ah(ibvah);
	status = ibv_cmd_destroy_ah(ibvah);
	if (status)
		return status;
	free(ah);

	return 0;
}

#ifdef HAVE_WR_BIND_MW
struct ibv_mw *bnxt_re_alloc_mw(struct ibv_pd *ibvpd, enum ibv_mw_type type)
{
	struct ibv_mw *ibvmw;
	struct ibv_alloc_mw cmd;
	struct ibv_alloc_mw_resp resp;
	int status;

	ibvmw = calloc(1, sizeof(*ibvmw));
	if (!ibvmw)
		return NULL;

	status = ibv_cmd_alloc_mw(ibvpd, type, ibvmw, &cmd,
				  sizeof(cmd), &resp, sizeof(resp));
	if (status) {
		free(ibvmw);
		return NULL;
	}

	return ibvmw;
}

int bnxt_re_dealloc_mw(struct ibv_mw *ibvmw)
{
	struct ibv_dealloc_mw cmd;
	int status;

	status = ibv_cmd_dealloc_mw(ibvmw, &cmd, sizeof(cmd));
	if (status)
		return status;

	free(ibvmw);

	return 0;
}

int bnxt_re_bind_mw(struct ibv_qp *ibvqp, struct ibv_mw *ibvmw,
		    struct ibv_mw_bind *bind)
{
	int status;
	struct ibv_send_wr *bad_wr = NULL;
	struct ibv_send_wr wr;

	memset(&wr, 0, sizeof(wr));

	wr.opcode = IBV_WR_BIND_MW;
	wr.next = NULL;

	wr.wr_id = bind->wr_id;
	wr.send_flags = bind->send_flags;

	wr.bind_mw.mw = ibvmw;
	wr.bind_mw.rkey = ibv_inc_rkey(ibvmw->rkey);
	wr.bind_mw.bind_info = bind->bind_info;

	status = bnxt_re_post_send(ibvqp, &wr, &bad_wr);
	if (status)
		return status;
	/* Update the rkey */
	ibvmw->rkey = wr.bind_mw.rkey;

	return 0;
}
#endif
