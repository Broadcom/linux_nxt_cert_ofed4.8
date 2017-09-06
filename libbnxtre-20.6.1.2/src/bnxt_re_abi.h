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

#ifndef __BNXT_RE_ABI_H__
#define __BNXT_RE_ABI_H__

#include <infiniband/kern-abi.h>

#define true			1
#define false			0
#define BNXT_RE_ABI_VERSION	3
/*  Cu+ max inline data */
#define BNXT_RE_MAX_INLINE_SIZE	0x60

#ifdef HAVE_J8916_ENABLED
#define BNXT_RE_FULL_FLAG_DELTA	0x80
#else
#define BNXT_RE_FULL_FLAG_DELTA	0x00
#endif

enum bnxt_re_wr_opcode {
	BNXT_RE_WR_OPCD_SEND		= 0x00,
	BNXT_RE_WR_OPCD_SEND_IMM	= 0x01,
	BNXT_RE_WR_OPCD_SEND_INVAL	= 0x02,
	BNXT_RE_WR_OPCD_RDMA_WRITE	= 0x04,
	BNXT_RE_WR_OPCD_RDMA_WRITE_IMM	= 0x05,
	BNXT_RE_WR_OPCD_RDMA_READ	= 0x06,
	BNXT_RE_WR_OPCD_ATOMIC_CS	= 0x08,
	BNXT_RE_WR_OPCD_ATOMIC_FA	= 0x0B,
	BNXT_RE_WR_OPCD_LOC_INVAL	= 0x0C,
	BNXT_RE_WR_OPCD_BIND		= 0x0E,
	BNXT_RE_WR_OPCD_RECV		= 0x80,
	BNXT_RE_WR_OPCD_INVAL		= 0xFF
};

enum bnxt_re_wr_flags {
	BNXT_RE_WR_FLAGS_INLINE		= 0x10,
	BNXT_RE_WR_FLAGS_SE		= 0x08,
	BNXT_RE_WR_FLAGS_UC_FENCE	= 0x04,
	BNXT_RE_WR_FLAGS_RD_FENCE	= 0x02,
	BNXT_RE_WR_FLAGS_SIGNALED	= 0x01
};

#define BNXT_RE_MEMW_TYPE_2		0x02
#define BNXT_RE_MEMW_TYPE_1		0x00
enum bnxt_re_wr_bind_acc {
	BNXT_RE_WR_BIND_ACC_LWR		= 0x01,
	BNXT_RE_WR_BIND_ACC_RRD		= 0x02,
	BNXT_RE_WR_BIND_ACC_RWR		= 0x04,
	BNXT_RE_WR_BIND_ACC_RAT		= 0x08,
	BNXT_RE_WR_BIND_ACC_MWB		= 0x10,
	BNXT_RE_WR_BIND_ACC_ZBVA	= 0x01,
	BNXT_RE_WR_BIND_ACC_SHIFT	= 0x10
};

enum bnxt_re_wc_type {
	BNXT_RE_WC_TYPE_SEND		= 0x00,
	BNXT_RE_WC_TYPE_RECV_RC		= 0x01,
	BNXT_RE_WC_TYPE_RECV_UD		= 0x02,
	BNXT_RE_WC_TYPE_RECV_RAW	= 0x03,
	BNXT_RE_WC_TYPE_TERM		= 0x0E,
	BNXT_RE_WC_TYPE_COFF		= 0x0F
};

enum bnxt_re_req_wc_status {
	BNXT_RE_REQ_ST_OK		= 0x00,
	BNXT_RE_REQ_ST_BAD_RESP		= 0x01,
	BNXT_RE_REQ_ST_LOC_LEN		= 0x02,
	BNXT_RE_REQ_ST_LOC_QP_OP	= 0x03,
	BNXT_RE_REQ_ST_PROT		= 0x04,
	BNXT_RE_REQ_ST_MEM_OP		= 0x05,
	BNXT_RE_REQ_ST_REM_INVAL	= 0x06,
	BNXT_RE_REQ_ST_REM_ACC		= 0x07,
	BNXT_RE_REQ_ST_REM_OP		= 0x08,
	BNXT_RE_REQ_ST_RNR_NAK_XCED	= 0x09,
	BNXT_RE_REQ_ST_TRNSP_XCED	= 0x0A,
	BNXT_RE_REQ_ST_WR_FLUSH		= 0x0B
};

enum bnxt_re_rsp_wc_status {
	BNXT_RE_RSP_ST_OK		= 0x00,
	BNXT_RE_RSP_ST_LOC_ACC		= 0x01,
	BNXT_RE_RSP_ST_LOC_LEN		= 0x02,
	BNXT_RE_RSP_ST_LOC_PROT		= 0x03,
	BNXT_RE_RSP_ST_LOC_QP_OP	= 0x04,
	BNXT_RE_RSP_ST_MEM_OP		= 0x05,
	BNXT_RE_RSP_ST_REM_INVAL	= 0x06,
	BNXT_RE_RSP_ST_WR_FLUSH		= 0x07,
	BNXT_RE_RSP_ST_HW_FLUSH		= 0x08
};

enum bnxt_re_hdr_offset {
	BNXT_RE_HDR_WT_MASK		= 0xFF,
	BNXT_RE_HDR_FLAGS_MASK		= 0xFF,
	BNXT_RE_HDR_FLAGS_SHIFT		= 0x08,
	BNXT_RE_HDR_WS_MASK		= 0xFF,
	BNXT_RE_HDR_WS_SHIFT		= 0x10
};

enum bnxt_re_db_que_type {
	BNXT_RE_QUE_TYPE_SQ		= 0x00,
	BNXT_RE_QUE_TYPE_RQ		= 0x01,
	BNXT_RE_QUE_TYPE_SRQ		= 0x02,
	BNXT_RE_QUE_TYPE_SRQ_ARM	= 0x03,
	BNXT_RE_QUE_TYPE_CQ		= 0x04,
	BNXT_RE_QUE_TYPE_CQ_ARMSE	= 0x05,
	BNXT_RE_QUE_TYPE_CQ_ARMALL	= 0x06,
	BNXT_RE_QUE_TYPE_CQ_ARMENA	= 0x07,
	BNXT_RE_QUE_TYPE_SRQ_ARMENA	= 0x08,
	BNXT_RE_QUE_TYPE_CQ_CUT_ACK	= 0x09,
	BNXT_RE_QUE_TYPE_NULL		= 0x0F
};

enum bnxt_re_db_mask {
	BNXT_RE_DB_INDX_MASK		= 0xFFFFFUL,
	BNXT_RE_DB_QID_MASK		= 0xFFFFFUL,
	BNXT_RE_DB_TYP_MASK		= 0x0FUL,
	BNXT_RE_DB_TYP_SHIFT		= 0x1C
};

enum bnxt_re_psns_mask {
	BNXT_RE_PSNS_SPSN_MASK		= 0xFFFFFF,
	BNXT_RE_PSNS_OPCD_MASK		= 0xFF,
	BNXT_RE_PSNS_OPCD_SHIFT		= 0x18,
	BNXT_RE_PSNS_NPSN_MASK		= 0xFFFFFF,
	BNXT_RE_PSNS_FLAGS_MASK		= 0xFF,
	BNXT_RE_PSNS_FLAGS_SHIFT	= 0x18
};

enum bnxt_re_bcqe_mask {
	BNXT_RE_BCQE_PH_MASK		= 0x01,
	BNXT_RE_BCQE_TYPE_MASK		= 0x0F,
	BNXT_RE_BCQE_TYPE_SHIFT		= 0x01,
	BNXT_RE_BCQE_STATUS_MASK	= 0xFF,
	BNXT_RE_BCQE_STATUS_SHIFT	= 0x08,
	BNXT_RE_BCQE_FLAGS_MASK		= 0xFFFFU,
	BNXT_RE_BCQE_FLAGS_SHIFT	= 0x10,
	BNXT_RE_BCQE_RWRID_MASK		= 0xFFFFFU,
	BNXT_RE_BCQE_SRCQP_MASK		= 0xFF,
	BNXT_RE_BCQE_SRCQP_SHIFT	= 0x18
};

enum bnxt_re_rc_flags_mask {
	BNXT_RE_RC_FLAGS_SRQ_RQ_MASK	= 0x01,
	BNXT_RE_RC_FLAGS_IMM_MASK	= 0x02,
	BNXT_RE_RC_FLAGS_IMM_SHIFT	= 0x01,
	BNXT_RE_RC_FLAGS_INV_MASK	= 0x04,
	BNXT_RE_RC_FLAGS_INV_SHIFT	= 0x02,
	BNXT_RE_RC_FLAGS_RDMA_MASK	= 0x08,
	BNXT_RE_RC_FLAGS_RDMA_SHIFT	= 0x03
};

enum bnxt_re_ud_flags_mask {
	BNXT_RE_UD_FLAGS_SRQ_RQ_MASK	= 0x01,
	BNXT_RE_UD_FLAGS_IMM_MASK	= 0x02,
	BNXT_RE_UD_FLAGS_HDR_TYP_MASK	= 0x0C,

	BNXT_RE_UD_FLAGS_SRQ		= 0x01,
	BNXT_RE_UD_FLAGS_RQ		= 0x00,
	BNXT_RE_UD_FLAGS_ROCE		= 0x00,
	BNXT_RE_UD_FLAGS_ROCE_IPV4	= 0x02,
	BNXT_RE_UD_FLAGS_ROCE_IPV6	= 0x03
};

enum bnxt_re_ud_cqe_mask {
	BNXT_RE_UD_CQE_MAC_MASK		= 0xFFFFFFFFFFFFULL,
	BNXT_RE_UD_CQE_SRCQPLO_MASK	= 0xFFFF,
	BNXT_RE_UD_CQE_SRCQPLO_SHIFT	= 0x30
};

enum bnxt_re_shpg_offt {
	BNXT_RE_SHPG_BEG_RESV_OFFT	= 0x00,
	BNXT_RE_SHPG_AVID_OFFT		= 0x10,
	BNXT_RE_SHPG_AVID_SIZE		= 0x04,
	BNXT_RE_SHPG_END_RESV_OFFT	= 0xFF0
};

struct bnxt_re_db_hdr {
	__u32 indx;
	__u32 typ_qid; /* typ: 4, qid:20*/
};

struct bnxt_re_cntx_resp {
	struct ibv_get_context_resp resp;
	__u32 dev_id;
	__u32 max_qp; /* To allocate qp-table */
	__u32 pg_size;
	__u32 cqe_sz;
	__u32 max_cqd;
} __attribute__((packed));

struct bnxt_re_pd_resp {
	struct ibv_alloc_pd_resp resp;
	__u32 pdid;
	__u32 dpi;
	__u64 dbr;
} __attribute__((packed));

struct bnxt_re_mr_resp {
	struct ibv_reg_mr_resp resp;
} __attribute__((packed));

/* CQ */
struct bnxt_re_cq_req {
	struct ibv_create_cq cmd;
	__u64 cq_va;
	__u64 cq_handle;
} __attribute__((packed));

struct bnxt_re_cq_resp {
	struct ibv_create_cq_resp resp;
	__u32 cqid;
	__u32 tail;
	__u32 phase;
} __attribute__((packed));

struct bnxt_re_resize_cq_req {
	struct ibv_resize_cq cmd;
	__u64   cq_va;
} __attribute__((packed));

struct bnxt_re_bcqe {
	__u32 flg_st_typ_ph;
	__u32 qphi_rwrid;
} __attribute__((packed));

struct bnxt_re_req_cqe {
	__u64 qp_handle;
	__u32 con_indx; /* 16 bits valid. */
	__u32 rsvd1;
	__u64 rsvd2;
} __attribute__((packed));

struct bnxt_re_rc_cqe {
	__u32 length;
	__u32 imm_key;
	__u64 qp_handle;
	__u64 mr_handle;
} __attribute__((packed));

struct bnxt_re_ud_cqe {
	__u32 length; /* 14 bits */
	__u32 immd;
	__u64 qp_handle;
	__u64 qplo_mac; /* 16:48*/
} __attribute__((packed));

struct bnxt_re_term_cqe {
	__u64 qp_handle;
	__u32 rq_sq_cidx;
	__u32 rsvd;
	__u64 rsvd1;
} __attribute__((packed));

struct bnxt_re_cutoff_cqe {
	__u64 rsvd1;
	__u64 rsvd2;
	__u64 rsvd3;
	__u8 cqe_type_toggle;
	__u8 status;
	__u16 rsvd4;
	__u32 rsvd5;
} __attribute__((packed));

/* QP */
struct bnxt_re_qp_req {
	struct ibv_create_qp cmd;
	__u64 qpsva;
	__u64 qprva;
	__u64 qp_handle;
} __attribute__((packed));

struct bnxt_re_qp_resp {
	struct ibv_create_qp_resp resp;
	__u32 qpid;
} __attribute__((packed));

struct bnxt_re_bsqe {
	__u32 rsv_ws_fl_wt;
	__u32 key_immd;
} __attribute__((packed));

struct bnxt_re_psns {
	__u32 opc_spsn;
	__u32 flg_npsn;
} __attribute__((packed));

struct bnxt_re_sge {
	__u32 pa_lo;
	__u32 pa_hi;
	__u32 lkey;
	__u32 length;
} __attribute__((packed));

struct bnxt_re_send {
	__u32 length;
	__u32 qkey;
	__u32 dst_qp;
	__u32 avid;
	__u64 rsvd;
} __attribute__((packed));

struct bnxt_re_raw {
	__u32 length;
	__u32 rsvd1;
	__u32 cfa_meta;
	__u32 rsvd2;
	__u64 rsvd3;
} __attribute__((packed));

struct bnxt_re_rdma {
	__u32 length;
	__u32 rsvd1;
	__u32 rva_lo;
	__u32 rva_hi;
	__u32 rkey;
	__u32 rsvd2;
} __attribute__((packed));

struct bnxt_re_atomic {
	__u32 rva_lo;
	__u32 rva_hi;
	__u32 swp_dt_lo;
	__u32 swp_dt_hi;
	__u32 cmp_dt_lo;
	__u32 cmp_dt_hi;
} __attribute__((packed));

struct bnxt_re_inval {
	__u64 rsvd[3];
} __attribute__((packed));

struct bnxt_re_bind {
	__u32 plkey;
	__u32 lkey;
	__u32 va_lo;
	__u32 va_hi;
	__u32 len_lo;
	__u32 len_hi; /* only 40 bits are valid */
} __attribute__((packed));

struct bnxt_re_brqe {
	__u32 rsv_ws_fl_wt;
	__u32 rsvd;
} __attribute__((packed));

struct bnxt_re_rqe {
	__u32 wrid;
	__u32 rsvd1;
	__u64 rsvd[2];
} __attribute__((packed));

/* SRQ */
struct bnxt_re_srq_req {
	struct ibv_create_srq cmd;
	__u64 srqva;
	__u64 srq_handle;
} __attribute__((packed));

struct bnxt_re_srq_resp {
	struct ibv_create_srq_resp resp;
	__u32 srqid;
} __attribute__((packed));

struct bnxt_re_srqe {
	__u32 srq_tag; /* 20 bits are valid */
	__u32 rsvd1;
	__u64 rsvd[2];
} __attribute__((packed));

static inline uint32_t bnxt_re_get_sqe_sz(void)
{
	return sizeof(struct bnxt_re_bsqe) +
	       sizeof(struct bnxt_re_send) +
	       BNXT_RE_MAX_INLINE_SIZE;
}

static inline uint32_t bnxt_re_get_sqe_hdr_sz(void)
{
	return sizeof(struct bnxt_re_bsqe) + sizeof(struct bnxt_re_send);
}

static inline uint32_t bnxt_re_get_rqe_sz(void)
{
	return sizeof(struct bnxt_re_brqe) +
	       sizeof(struct bnxt_re_rqe) +
	       BNXT_RE_MAX_INLINE_SIZE;
}

static inline uint32_t bnxt_re_get_rqe_hdr_sz(void)
{
	return sizeof(struct bnxt_re_brqe) + sizeof(struct bnxt_re_rqe);
}

static inline uint32_t bnxt_re_get_srqe_hdr_sz(void)
{
	return sizeof(struct bnxt_re_brqe) + sizeof(struct bnxt_re_srqe);
}

static inline uint32_t bnxt_re_get_srqe_sz(void)
{
	return sizeof(struct bnxt_re_brqe) +
	       sizeof(struct bnxt_re_srqe) +
	       BNXT_RE_MAX_INLINE_SIZE;
}

static inline uint32_t bnxt_re_get_cqe_sz(void)
{
	return sizeof(struct bnxt_re_req_cqe) + sizeof(struct bnxt_re_bcqe);
}
#endif
