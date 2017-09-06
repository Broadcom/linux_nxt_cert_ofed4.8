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
 *
 * Description: Compat file for supporting multiple distros
 */

#include <linux/types.h>
#include <linux/version.h>
#include <linux/netdevice.h>
#include <rdma/ib_verbs.h>
#include <rdma/ib_umem.h>
#include "bnxt_ulp.h"
#include "bnxt_re_compat.h"

#ifndef RHEL_RELEASE_CODE
#define RHEL_RELEASE_CODE 0
#endif

#ifndef RHEL_RELEASE_VERSION
#define RHEL_RELEASE_VERSION(a, b)       (((a) << 8) + (b))
#endif

int bnxt_re_register_netdevice_notifier(struct notifier_block *nb)
{
	int rc;
#ifdef HAVE_REGISTER_NETDEVICE_NOTIFIER_RH
	rc = register_netdevice_notifier_rh(nb);
#else
	rc = register_netdevice_notifier(nb);
#endif
	return rc;
}

int bnxt_re_unregister_netdevice_notifier(struct notifier_block *nb)
{
	int rc;
#ifdef HAVE_REGISTER_NETDEVICE_NOTIFIER_RH
	rc = unregister_netdevice_notifier_rh(nb);
#else
	rc = unregister_netdevice_notifier(nb);
#endif
	return rc;
}

#ifdef HAVE_IB_WR_BIND_MW
struct ib_mw_bind_info *get_bind_info(struct ib_send_wr *wr)
{
#ifdef HAVE_IB_BIND_MW_WR
	struct ib_bind_mw_wr *bind_mw = bind_mw_wr(wr);

	return &bind_mw->bind_info;
#else
	return &wr->wr.bind_mw.bind_info;
#endif
}

struct ib_mw *get_ib_mw(struct ib_send_wr *wr)
{
#ifdef HAVE_IB_BIND_MW_WR
	struct ib_bind_mw_wr *bind_mw = bind_mw_wr(wr);

	return bind_mw->mw;
#else
	return wr->wr.bind_mw.mw;
#endif
}
#endif

struct scatterlist *get_ib_umem_sgl(struct ib_umem *umem, u32 *nmap)
{
#ifndef HAVE_IB_UMEM_SG_TABLE
	struct ib_umem_chunk *chunk;
	struct scatterlist **sg = NULL;
	u32 sg_nmap = 0;
	int i = 0, j;
	size_t n = 0;
#endif

#ifdef HAVE_IB_UMEM_SG_TABLE
	*nmap = umem->nmap;
	return umem->sg_head.sgl;
#else
	list_for_each_entry(chunk, &umem->chunk_list, list)
		n += chunk->nmap;

	*sg = kcalloc(n, sizeof(*sg), GFP_KERNEL);
	if (!(*sg)) {
		*nmap = 0;
		return NULL;
	}
	list_for_each_entry(chunk, &umem->chunk_list, list) {
		for (j = 0; j < chunk->nmap; ++j)
			sg[i++] = &chunk->page_list[j];
		sg_nmap += chunk->nmap;
	}
	*nmap = sg_nmap;
	return *sg;
#endif
}

void bnxt_re_set_fence_flag(struct ib_send_wr *wr,
			    struct bnxt_qplib_swqe *wqe)
{
#if RHEL_RELEASE_CODE == RHEL_RELEASE_VERSION(6, 7)
	/* The nfs-rdma stack in RHEL6.7 does not request FENCE while
	 * invalidating a MR. This causes local errors if the MR is still
	 * in use (e.g, a RDMA_READ pending on the MR). Always set the
	 * FENCE bit in the wqe to avoid this.
	 */
	wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
#else
	if (wr->send_flags & IB_SEND_FENCE)
		wqe->flags |= BNXT_QPLIB_SWQE_FLAGS_UC_FENCE;
#endif
}
