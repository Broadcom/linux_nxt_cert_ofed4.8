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
 * Description: IB Verbs interpreter (header)
 */

#ifndef __BNXT_RE_IB_VERBS_H__
#define __BNXT_RE_IB_VERBS_H__

struct bnxt_re_gid_ctx {
	u32			idx;
	u32			refcnt;
};

#ifdef BIND_MW_FENCE_WQE
struct bnxt_re_fence_data {
	u32 size;
	void *va;
	dma_addr_t dma_addr;
	struct bnxt_re_mr *mr;
	struct ib_mw *mw;
	struct bnxt_qplib_swqe bind_wqe;
	u32 bind_rkey;
};
#endif

struct bnxt_re_pd {
	struct bnxt_re_dev	*rdev;
	struct ib_pd		ib_pd;
	struct bnxt_qplib_pd	qplib_pd;
#ifdef BIND_MW_FENCE_WQE
	struct bnxt_re_fence_data fence;
#endif
};

struct bnxt_re_ah {
	struct bnxt_re_dev	*rdev;
	struct ib_ah		ib_ah;
	struct bnxt_qplib_ah	qplib_ah;
};

struct bnxt_re_srq {
	struct bnxt_re_dev	*rdev;
	u32			srq_limit;
	struct ib_srq		ib_srq;
	struct bnxt_qplib_srq	qplib_srq;
	struct ib_umem		*umem;
};

struct bnxt_re_qp {
	struct list_head	list;
	struct bnxt_re_dev	*rdev;
	struct ib_qp		ib_qp;
	spinlock_t		sq_lock;
	spinlock_t		rq_lock;
	struct bnxt_qplib_qp	qplib_qp;
	struct ib_umem		*sumem;
	struct ib_umem		*rumem;
	/* QP1 */
	u32			send_psn;
	struct ib_ud_header	qp1_hdr;
};

struct bnxt_re_cq {
	struct bnxt_re_dev	*rdev;
	spinlock_t              cq_lock;
	u16			cq_count;
	u16			cq_period;
	struct ib_cq		ib_cq;
	struct bnxt_qplib_cq	qplib_cq;
	struct bnxt_qplib_cqe	*cql;
#define MAX_CQL_PER_POLL	1024
	u32			max_cql;
	struct ib_umem		*umem;
	struct ib_umem		*resize_umem;
	int			resize_cqe;
};

struct bnxt_re_mr {
	struct bnxt_re_dev	*rdev;
	struct ib_mr		ib_mr;
	struct ib_umem		*ib_umem;
	struct bnxt_qplib_mrw	qplib_mr;
#ifdef HAVE_IB_ALLOC_MR
	u32			npages;
	u64			*pages;
	struct bnxt_qplib_frpl	qplib_frpl;
#endif
};

struct bnxt_re_frpl {
	struct bnxt_re_dev		*rdev;
#ifdef HAVE_IB_FAST_REG_MR
	struct ib_fast_reg_page_list	ib_frpl;
#endif
	struct bnxt_qplib_frpl		qplib_frpl;
	u64				*page_list;
};

struct bnxt_re_fmr {
	struct bnxt_re_dev	*rdev;
	struct ib_fmr		ib_fmr;
	struct bnxt_qplib_mrw	qplib_fmr;
};

struct bnxt_re_mw {
	struct bnxt_re_dev	*rdev;
	struct ib_mw		ib_mw;
	struct bnxt_qplib_mrw	qplib_mw;
};

struct bnxt_re_ucontext {
	struct bnxt_re_dev	*rdev;
	struct ib_ucontext	ib_uctx;
	struct bnxt_qplib_dpi	dpi;
	void			*shpg;
	spinlock_t		sh_lock;
};

struct net_device *bnxt_re_get_netdev(struct ib_device *ibdev, u8 port_num);

#ifdef HAVE_IB_QUERY_DEVICE_UDATA
int bnxt_re_query_device(struct ib_device *ibdev,
			 struct ib_device_attr *ib_attr,
			 struct ib_udata *udata);
#else
int bnxt_re_query_device(struct ib_device *ibdev,
			 struct ib_device_attr *device_attr);
#endif
int bnxt_re_modify_device(struct ib_device *ibdev,
			  int device_modify_mask,
			  struct ib_device_modify *device_modify);
int bnxt_re_query_port(struct ib_device *ibdev, u8 port_num,
		       struct ib_port_attr *port_attr);
int bnxt_re_modify_port(struct ib_device *ibdev, u8 port_num,
			int port_modify_mask,
			struct ib_port_modify *port_modify);
#ifdef HAVE_IB_GET_PORT_IMMUTABLE
int bnxt_re_get_port_immutable(struct ib_device *ibdev, u8 port_num,
			       struct ib_port_immutable *immutable);
#endif
int bnxt_re_query_pkey(struct ib_device *ibdev, u8 port_num,
		       u16 index, u16 *pkey);
#ifdef HAVE_IB_ADD_DEL_GID
int bnxt_re_del_gid(struct ib_device *ibdev, u8 port_num,
		    unsigned int index, void **context);
int bnxt_re_add_gid(struct ib_device *ibdev, u8 port_num,
		    unsigned int index, const union ib_gid *gid,
		    const struct ib_gid_attr *attr, void **context);
#endif
#ifdef HAVE_IB_MODIFY_GID
int bnxt_re_modify_gid(struct ib_device *ibdev, u8 port_num,
		    unsigned int index, const union ib_gid *gid,
		    const struct ib_gid_attr *attr, void **context);
#endif
int bnxt_re_query_gid(struct ib_device *ibdev, u8 port_num,
		       int index, union ib_gid *gid);
enum rdma_link_layer bnxt_re_get_link_layer(struct ib_device *ibdev,
					    u8 port_num);
struct ib_pd *bnxt_re_alloc_pd(struct ib_device *ibdev,
			       struct ib_ucontext *context,
			       struct ib_udata *udata);
int bnxt_re_dealloc_pd(struct ib_pd *pd);
struct ib_ah *bnxt_re_create_ah(struct ib_pd *pd,
				struct ib_ah_attr *ah_attr);
int bnxt_re_modify_ah(struct ib_ah *ah, struct ib_ah_attr *ah_attr);
int bnxt_re_query_ah(struct ib_ah *ah, struct ib_ah_attr *ah_attr);
int bnxt_re_destroy_ah(struct ib_ah *ah);
struct ib_srq *bnxt_re_create_srq(struct ib_pd *pd,
				  struct ib_srq_init_attr *srq_init_attr,
				  struct ib_udata *udata);
int bnxt_re_modify_srq(struct ib_srq *srq, struct ib_srq_attr *srq_attr,
		       enum ib_srq_attr_mask srq_attr_mask,
		       struct ib_udata *udata);
int bnxt_re_query_srq(struct ib_srq *srq, struct ib_srq_attr *srq_attr);
int bnxt_re_destroy_srq(struct ib_srq *srq);
int bnxt_re_post_srq_recv(struct ib_srq *srq, struct ib_recv_wr *recv_wr,
			  struct ib_recv_wr **bad_recv_wr);
struct ib_qp *bnxt_re_create_qp(struct ib_pd *pd,
				struct ib_qp_init_attr *qp_init_attr,
				struct ib_udata *udata);
int bnxt_re_modify_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
		      int qp_attr_mask, struct ib_udata *udata);
int bnxt_re_query_qp(struct ib_qp *qp, struct ib_qp_attr *qp_attr,
		     int qp_attr_mask, struct ib_qp_init_attr *qp_init_attr);
int bnxt_re_destroy_qp(struct ib_qp *qp);
int bnxt_re_post_send(struct ib_qp *qp, struct ib_send_wr *send_wr,
		      struct ib_send_wr **bad_send_wr);
int bnxt_re_post_recv(struct ib_qp *qp, struct ib_recv_wr *recv_wr,
		      struct ib_recv_wr **bad_recv_wr);
#ifdef HAVE_IB_CQ_INIT_ATTR
struct ib_cq *bnxt_re_create_cq(struct ib_device *ibdev,
				const struct ib_cq_init_attr *attr,
				struct ib_ucontext *context,
				struct ib_udata *udata);
#else
struct ib_cq *bnxt_re_create_cq(struct ib_device *ibdev, int cqe,
				int comp_vector, struct ib_ucontext *context,
				struct ib_udata *udata);
#endif
int bnxt_re_modify_cq(struct ib_cq *cq, u16 cq_count, u16 cq_period);
int bnxt_re_destroy_cq(struct ib_cq *cq);
int bnxt_re_destroy_cq(struct ib_cq *cq);
int bnxt_re_resize_cq(struct ib_cq *cq, int cqe, struct ib_udata *udata);
int bnxt_re_poll_cq(struct ib_cq *cq, int num_entries, struct ib_wc *wc);
int bnxt_re_req_notify_cq(struct ib_cq *cq, enum ib_cq_notify_flags flags);
struct ib_mr *bnxt_re_get_dma_mr(struct ib_pd *pd, int mr_access_flags);
#ifdef HAVE_IB_MAP_MR_SG
int bnxt_re_map_mr_sg(struct ib_mr *ib_mr, struct scatterlist *sg, int sg_nents
#ifdef HAVE_IB_MAP_MR_SG_PAGE_SIZE
		      , unsigned int *sg_offset
#else
#ifdef HAVE_IB_MAP_MR_SG_OFFSET
		      , unsigned int sg_offset
#endif
#endif
		      );
#endif
#ifdef HAVE_IB_ALLOC_MR
struct ib_mr *bnxt_re_alloc_mr(struct ib_pd *ib_pd, enum ib_mr_type mr_type,
			       u32 max_num_sg);
#endif
#ifdef HAVE_IB_REG_PHYS_MR
struct ib_mr *bnxt_re_reg_phys_mr(struct ib_pd *pd,
				  struct ib_phys_buf *phys_buf_array,
				  int num_phys_buf, int mr_access_flags,
				  u64 *iova_start);
int bnxt_re_rereg_phys_mr(struct ib_mr *ib_mr, int mr_rereg_mask,
			  struct ib_pd *ib_pd,
			  struct ib_phys_buf *phys_buf_array,
			  int num_phys_buf, int mr_access_flags,
			  u64 *iova_start);
#endif
#ifdef HAVE_IB_QUERY_MR
int bnxt_re_query_mr(struct ib_mr *mr, struct ib_mr_attr *mr_attr);
#endif
int bnxt_re_dereg_mr(struct ib_mr *mr);
#ifdef HAVE_IB_SIGNATURE_HANDOVER
int bnxt_re_destroy_mr(struct ib_mr *mr);
struct ib_mr *bnxt_re_create_mr(struct ib_pd *pd,
				struct ib_mr_init_attr *mr_init_attr);
#endif
#ifdef HAVE_IB_FAST_REG_MR
struct ib_mr *bnxt_re_alloc_fast_reg_mr(struct ib_pd *pd,
					int max_page_list_len);
struct ib_fast_reg_page_list *bnxt_re_alloc_fast_reg_page_list(
						struct ib_device *ibdev,
						int page_list_len);
void bnxt_re_free_fast_reg_page_list(struct ib_fast_reg_page_list *page_list);
#endif
#ifdef HAVE_IB_MW_TYPE
struct ib_mw *bnxt_re_alloc_mw(struct ib_pd *ib_pd, enum ib_mw_type type
#ifdef HAVE_ALLOW_MW_WITH_UDATA
			       , struct ib_udata *udata
#endif
			       );
#else
struct ib_mw *bnxt_re_alloc_mw(struct ib_pd *ib_pd);
#endif
#ifdef HAVE_IB_BIND_MW
int bnxt_re_bind_mw(struct ib_qp *qp, struct ib_mw *mw,
		    struct ib_mw_bind *mw_bind);
#endif
int bnxt_re_dealloc_mw(struct ib_mw *mw);
struct ib_fmr *bnxt_re_alloc_fmr(struct ib_pd *pd, int mr_access_flags,
				 struct ib_fmr_attr *fmr_attr);
int bnxt_re_map_phys_fmr(struct ib_fmr *fmr, u64 *page_list, int list_len,
			 u64 iova);
int bnxt_re_unmap_fmr(struct list_head *fmr_list);
int bnxt_re_dealloc_fmr(struct ib_fmr *fmr);
#ifdef HAVE_IB_FLOW
struct ib_flow *bnxt_re_create_flow(struct ib_qp *qp,
				    struct ib_flow_attr *flow_attr,
				    int domain);
int bnxt_re_destroy_flow(struct ib_flow *flow_id);
#endif
struct ib_mr *bnxt_re_reg_user_mr(struct ib_pd *pd, u64 start, u64 length,
				  u64 virt_addr, int mr_access_flags,
				  struct ib_udata *udata);
int bnxt_re_rereg_user_mr(struct ib_mr *mr, int flags, u64 start, u64 length,
			  u64 virt_addr, int mr_access_flags, struct ib_pd *pd,
			  struct ib_udata *udata);
struct ib_ucontext *bnxt_re_alloc_ucontext(struct ib_device *ibdev,
					   struct ib_udata *udata);
int bnxt_re_dealloc_ucontext(struct ib_ucontext *context);
int bnxt_re_mmap(struct ib_ucontext *context, struct vm_area_struct *vma);
#ifdef HAVE_IB_MAD_HDR
int bnxt_re_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
			const struct ib_wc *wc, const struct ib_grh *grh,
			const struct ib_mad_hdr *in_mad, size_t in_mad_size,
			struct ib_mad_hdr *out_mad, size_t *out_mad_size,
			u16 *out_mad_pkey_index);
#else
int bnxt_re_process_mad(struct ib_device *ibdev, int mad_flags, u8 port_num,
			struct ib_wc *wc, struct ib_grh *grh,
			struct ib_mad *in_mad, struct ib_mad *out_mad);
#endif

#ifdef HAVE_IB_DRAIN
void bnxt_re_drain_rq(struct ib_qp *ib_qp);
void bnxt_re_drain_sq(struct ib_qp *ib_qp);
#endif
#endif
