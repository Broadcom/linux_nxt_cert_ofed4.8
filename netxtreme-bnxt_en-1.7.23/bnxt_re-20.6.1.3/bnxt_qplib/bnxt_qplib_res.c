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
 * Description: QPLib resource manager
 */

#include <linux/spinlock.h>
#include <linux/pci.h>
#include <linux/interrupt.h>
#include <linux/inetdevice.h>
#include <linux/dma-mapping.h>
#include <linux/if_vlan.h>

#include <net/ipv6.h>
#include <net/addrconf.h>

#include <rdma/ib_verbs.h>

#include "roce_hsi.h"

#include "bnxt_qplib_res.h"
#include "bnxt_qplib_sp.h"
#include "bnxt_qplib_rcfw.h"

static void bnxt_qplib_free_stats_ctx(struct pci_dev *pdev,
				      struct bnxt_qplib_stats *stats);
static int bnxt_qplib_alloc_stats_ctx(struct pci_dev *pdev,
				      struct bnxt_qplib_stats *stats);


/* PBL */
static void __free_pbl(struct pci_dev *pdev, struct bnxt_qplib_pbl *pbl,
		       bool is_umem)
{
	int i;

	if (is_umem == false) {
		for (i = 0; i < pbl->pg_count; i++) {
			if (pbl->pg_arr[i])
				dma_free_coherent(&pdev->dev, pbl->pg_size,
					(void *)((u64)pbl->pg_arr[i] &
						 PAGE_MASK),
					pbl->pg_map_arr[i]);
			else
				dev_warn(&pdev->dev,
					 "QPLIB: PBL free pg_arr[%d] empty?!",
					 i);
			pbl->pg_arr[i] = NULL;
		}
	}
	if (pbl->pg_arr)
		kfree(pbl->pg_arr);
	if (pbl->pg_map_arr)
		kfree(pbl->pg_map_arr);
	pbl->pg_arr = NULL;
	pbl->pg_map_arr = NULL;
	pbl->pg_count = 0;
	pbl->pg_size = 0;
}

static int __alloc_pbl(struct pci_dev *pdev, struct bnxt_qplib_pbl *pbl,
		       struct scatterlist *sghead, u32 pages, u32 pg_size)
{
	int i;
	bool is_umem = false;
	struct scatterlist *sg;

	/* page ptr arrays */
	pbl->pg_arr = kcalloc(pages, sizeof(void *), GFP_KERNEL);
	if (!pbl->pg_arr)
		return -ENOMEM;

	pbl->pg_map_arr = kcalloc(pages, sizeof(dma_addr_t), GFP_KERNEL);
	if (!pbl->pg_map_arr) {
		kfree(pbl->pg_arr);
		return -ENOMEM;
	}
	pbl->pg_count = 0;
	pbl->pg_size = pg_size;

	if (!sghead) {
		for (i = 0; i < pages; i++) {
			pbl->pg_arr[i] = dma_alloc_coherent(&pdev->dev,
							    pbl->pg_size,
							    &pbl->pg_map_arr[i],
							    GFP_KERNEL);
			if (!pbl->pg_arr[i])
				goto fail;
			memset(pbl->pg_arr[i], 0, pbl->pg_size);
			pbl->pg_count++;
		}
	} else {
		i = 0;
		is_umem = true;
		for_each_sg(sghead, sg, pages, i) {
			pbl->pg_map_arr[i] = sg_dma_address(sg);
			pbl->pg_arr[i] = sg_virt(sg);
			if (!pbl->pg_arr[i])
				goto fail;

			pbl->pg_count++;
		}
	}

	return 0;

fail:
	__free_pbl(pdev, pbl, is_umem);
	return -ENOMEM;
}

/* HWQ */
void bnxt_qplib_free_hwq(struct pci_dev *pdev, struct bnxt_qplib_hwq *hwq)
{
	int i;

	if (!hwq->max_elements)
		return;
	if (hwq->level >= PBL_LVL_MAX)
		return;

	for (i = 0; i < hwq->level + 1; i++) {
		if (i == hwq->level)
			__free_pbl(pdev, &hwq->pbl[i], hwq->is_user);
		else
			__free_pbl(pdev, &hwq->pbl[i], false);
	}

	hwq->level = PBL_LVL_MAX;
	hwq->max_elements = 0;
	hwq->element_size = 0;
	hwq->prod = hwq->cons = 0;
	hwq->cp_bit = 0;
}

/* All HWQs are power of 2 in size */
int bnxt_qplib_alloc_init_hwq(struct pci_dev *pdev, struct bnxt_qplib_hwq *hwq,
			      struct scatterlist *sghead, int nmap,
			      u32 *elements, u32 element_size, u32 aux,
			      u32 pg_size, enum bnxt_qplib_hwq_type hwq_type)
{
	dma_addr_t *src_phys_ptr, **dst_virt_ptr;
	u32 pages, slots, size, aux_pages = 0, aux_size = 0;
	int i, rc;

	hwq->level = PBL_LVL_MAX;

	if (*elements < 0)
		return -EINVAL;

	slots = roundup_pow_of_two(*elements);
	if (aux) {
		aux_size = roundup_pow_of_two(aux);
		aux_pages = (slots * aux_size) / pg_size;
		if ((slots * aux_size) % pg_size)
			aux_pages++;
	}
	size = roundup_pow_of_two(element_size);

	if (!sghead) {
		hwq->is_user = false;
		pages = (slots * size) / pg_size + aux_pages;
		if ((slots * size) % pg_size)
			pages++;
		if (!pages)
			return -EINVAL;
	} else {
		hwq->is_user = true;
		pages = nmap;
	}
#ifdef ENABLE_DEBUG_SGE
	dev_dbg(&pdev->dev, "QPLIB: Alloc HWQ slots 0x%x size 0x%x pages 0x%x",
		slots, size, pages);
#endif
	/* Alloc the 1st memory block; can be a PDL/PTL/PBL */
	if (sghead && (pages == MAX_PBL_LVL_0_PGS))
		rc = __alloc_pbl(pdev, &hwq->pbl[PBL_LVL_0], sghead,
				 pages, pg_size);
	else
		rc = __alloc_pbl(pdev, &hwq->pbl[PBL_LVL_0], NULL, 1, pg_size);
	if (rc)
		goto fail;

	hwq->level = PBL_LVL_0;
#ifdef ENABLE_DEBUG_SGE
	dev_dbg(&pdev->dev, "QPLIB: PBL_LVL_0 DMA=0x%llx",
		hwq->pbl[PBL_LVL_0].pg_map_arr[0]);
#endif
	if (pages > MAX_PBL_LVL_0_PGS) {
		if (pages > MAX_PBL_LVL_1_PGS) {
			/* 2 levels of indirection */
			rc = __alloc_pbl(pdev, &hwq->pbl[PBL_LVL_1], NULL,
					 MAX_PBL_LVL_1_PGS_FOR_LVL_2, pg_size);
			if (rc)
				goto fail;
			/* Fill in lvl0 PBL */
			dst_virt_ptr =
				(dma_addr_t **)hwq->pbl[PBL_LVL_0].pg_arr;
			src_phys_ptr = hwq->pbl[PBL_LVL_1].pg_map_arr;
			for (i = 0; i < hwq->pbl[PBL_LVL_1].pg_count; i++)
				dst_virt_ptr[PTR_PG(i)][PTR_IDX(i)] =
					src_phys_ptr[i] | PTU_PDE_VALID;
			hwq->level = PBL_LVL_1;

			rc = __alloc_pbl(pdev, &hwq->pbl[PBL_LVL_2], sghead,
					 pages, pg_size);
			if (rc)
				goto fail;
#ifdef ENABLE_DEBUG_SGE
			dev_dbg(&pdev->dev, "QPLIB: PBL_LVL_1 alloc ");
			dev_dbg(&pdev->dev,
				"QPLIB: aux pg_count=0x%x aux_pages=0x%x",
				hwq->pbl[PBL_LVL_1].pg_count, aux_pages);
#endif
			/* Fill in lvl1 PBL */
			dst_virt_ptr =
				(dma_addr_t **)hwq->pbl[PBL_LVL_1].pg_arr;
			src_phys_ptr = hwq->pbl[PBL_LVL_2].pg_map_arr;
			for (i = 0; i < hwq->pbl[PBL_LVL_2].pg_count; i++) {
				dst_virt_ptr[PTR_PG(i)][PTR_IDX(i)] =
					src_phys_ptr[i] | PTU_PTE_VALID;
#ifdef ENABLE_DEBUG_SGE
				dev_dbg(&pdev->dev,
					"QPLIB: dst_virt_ptr[%d] = 0x%llx", i,
					dst_virt_ptr[PTR_PG(i)][PTR_IDX(i)]);
#endif
			}
			if (hwq_type == HWQ_TYPE_QUEUE) {
				/* Find the last pg of the size */
				i = hwq->pbl[PBL_LVL_2].pg_count;
				dst_virt_ptr[PTR_PG(i - 1)][PTR_IDX(i - 1)] |=
								  PTU_PTE_LAST;
				if (i > 1)
					dst_virt_ptr[PTR_PG(i - 2)]
						    [PTR_IDX(i - 2)] |=
						    PTU_PTE_NEXT_TO_LAST;
			}
#ifdef ENABLE_DEBUG_SGE
			dev_dbg(&pdev->dev, "QPLIB: PBL_LVL_2 alloc ");
			dev_dbg(&pdev->dev,
				"QPLIB: aux pg_count=0x%x aux_pages=0x%x",
				hwq->pbl[PBL_LVL_2].pg_count, aux_pages);
			for (i = 0; i < hwq->pbl[PBL_LVL_2].pg_count; i++)
				dev_dbg(&pdev->dev,
					"QPLIB: dst_virt_ptr[%d] = 0x%llx", i,
					dst_virt_ptr[PTR_PG(i)][PTR_IDX(i)]);
#endif
			hwq->level = PBL_LVL_2;
		} else {
			u32 flag = hwq_type == HWQ_TYPE_L2_CMPL ? 0 : PTU_PTE_VALID;

			/* 1 level of indirection */
			rc = __alloc_pbl(pdev, &hwq->pbl[PBL_LVL_1], sghead,
					 pages, pg_size);
			if (rc)
				goto fail;
#ifdef ENABLE_DEBUG_SGE
			dev_dbg(&pdev->dev, "QPLIB: PBL_LVL_1 alloc ");
			dev_dbg(&pdev->dev,
				"QPLIB: aux pg_count=0x%x aux_pages=0x%x",
				hwq->pbl[PBL_LVL_1].pg_count, aux_pages);
#endif
			/* Fill in lvl0 PBL */
			dst_virt_ptr =
				(dma_addr_t **)hwq->pbl[PBL_LVL_0].pg_arr;
			src_phys_ptr = hwq->pbl[PBL_LVL_1].pg_map_arr;
			for (i = 0; i < hwq->pbl[PBL_LVL_1].pg_count; i++) {
				dst_virt_ptr[PTR_PG(i)][PTR_IDX(i)] =
					src_phys_ptr[i] | flag;
			}
			if (hwq_type == HWQ_TYPE_QUEUE) {
				/* Find the last pg of the size */
				i = hwq->pbl[PBL_LVL_1].pg_count;
				dst_virt_ptr[PTR_PG(i - 1)][PTR_IDX(i - 1)] |=
								  PTU_PTE_LAST;
				if (i > 1)
					dst_virt_ptr[PTR_PG(i - 2)]
						    [PTR_IDX(i - 2)] |=
						    PTU_PTE_NEXT_TO_LAST;
			}
#ifdef ENABLE_DEBUG_SGE
			for (i = 0; i < hwq->pbl[PBL_LVL_1].pg_count; i++)
				dev_dbg(&pdev->dev,
					"QPLIB: dst_virt_ptr[%d] = 0x%llx",
					i, dst_virt_ptr[PTR_PG(i)][PTR_IDX(i)]);
#endif
			hwq->level = PBL_LVL_1;
		}
	}
	hwq->pdev = pdev;
	spin_lock_init(&hwq->lock);
	hwq->prod = 0;
	hwq->cons = 0;
	*elements = hwq->max_elements = slots;
	hwq->element_size = size;

	/* For direct access to the elements */
	hwq->pbl_ptr = hwq->pbl[hwq->level].pg_arr;
	hwq->pbl_dma_ptr = hwq->pbl[hwq->level].pg_map_arr;

	return 0;

fail:
	bnxt_qplib_free_hwq(pdev, hwq);
	return -ENOMEM;
}

/* Context Tables */
void bnxt_qplib_free_ctx(struct pci_dev *pdev,
			 struct bnxt_qplib_ctx *ctx)
{
	int i;

	bnxt_qplib_free_hwq(pdev, &ctx->qpc_tbl);
	bnxt_qplib_free_hwq(pdev, &ctx->mrw_tbl);
	bnxt_qplib_free_hwq(pdev, &ctx->srqc_tbl);
	bnxt_qplib_free_hwq(pdev, &ctx->cq_tbl);
	bnxt_qplib_free_hwq(pdev, &ctx->tim_tbl);
	for (i = 0; i < MAX_TQM_ALLOC_REQ; i++)
		bnxt_qplib_free_hwq(pdev, &ctx->tqm_tbl[i]);
	bnxt_qplib_free_hwq(pdev, &ctx->tqm_pde);
	bnxt_qplib_free_stats_ctx(pdev, &ctx->stats);
}

/*
 * Routine: bnxt_qplib_alloc_ctx
 * Description:
 *     Context tables are memories which are used by the chip fw.
 *     The 6 tables defined are:
 *             QPC ctx - holds QP states
 *             MRW ctx - holds memory region and window
 *             SRQ ctx - holds shared RQ states
 *             CQ ctx - holds completion queue states
 *             TQM ctx - holds Tx Queue Manager context
 *             TIM ctx - holds timer context
 *     Depending on the size of the tbl requested, either a 1 Page Buffer List
 *     or a 1-to-2-stage indirection Page Directory List + 1 PBL is used
 *     instead.
 *     Table might be employed as follows:
 *             For 0      < ctx size <= 1 PAGE, 0 level of ind is used
 *             For 1 PAGE < ctx size <= 512 entries size, 1 level of ind is used
 *             For 512    < ctx size <= MAX, 2 levels of ind is used
 * Returns:
 *     0 if success, else -ERRORS
 */
int bnxt_qplib_alloc_ctx(struct pci_dev *pdev,
			 struct bnxt_qplib_ctx *ctx,
			 bool virt_fn)
{
	u64 **pbl_ptr;
	int i, j, k, rc = 0;
	int fnz_idx = -1;

	if (virt_fn)
		goto stats_alloc;

	/* QPC Tables */
	ctx->qpc_tbl.max_elements = ctx->qpc_count;
	rc = bnxt_qplib_alloc_init_hwq(pdev, &ctx->qpc_tbl, NULL, 0,
				       &ctx->qpc_tbl.max_elements,
				       BNXT_QPLIB_MAX_QP_CTX_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_CTX);
	if (rc)
		goto fail;

	/* MRW Tables */
	ctx->mrw_tbl.max_elements = ctx->mrw_count;
	rc = bnxt_qplib_alloc_init_hwq(pdev, &ctx->mrw_tbl, NULL, 0,
				       &ctx->mrw_tbl.max_elements,
				       BNXT_QPLIB_MAX_MRW_CTX_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_CTX);
	if (rc)
		goto fail;

	/* SRQ Tables */
	ctx->srqc_tbl.max_elements = ctx->srqc_count;
	rc = bnxt_qplib_alloc_init_hwq(pdev, &ctx->srqc_tbl, NULL, 0,
				       &ctx->srqc_tbl.max_elements,
				       BNXT_QPLIB_MAX_SRQ_CTX_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_CTX);
	if (rc)
		goto fail;

	/* CQ Tables */
	ctx->cq_tbl.max_elements = ctx->cq_count;
	rc = bnxt_qplib_alloc_init_hwq(pdev, &ctx->cq_tbl, NULL, 0,
				       &ctx->cq_tbl.max_elements,
				       BNXT_QPLIB_MAX_CQ_CTX_ENTRY_SIZE, 0,
				       PAGE_SIZE, HWQ_TYPE_CTX);
	if (rc)
		goto fail;

	/* TQM Buffer */
	ctx->tqm_pde.max_elements = 512;
	rc = bnxt_qplib_alloc_init_hwq(pdev, &ctx->tqm_pde, NULL, 0,
				       &ctx->tqm_pde.max_elements, sizeof(u64),
				       0, PAGE_SIZE, HWQ_TYPE_CTX);
	if (rc)
		goto fail;

	for (i = 0; i < MAX_TQM_ALLOC_REQ; i++) {
		if (!ctx->tqm_count[i])
			continue;
		ctx->tqm_tbl[i].max_elements = ctx->qpc_count *
					       ctx->tqm_count[i];
		rc = bnxt_qplib_alloc_init_hwq(pdev, &ctx->tqm_tbl[i], NULL, 0,
					       &ctx->tqm_tbl[i].max_elements, 1,
					       0, PAGE_SIZE, HWQ_TYPE_CTX);
		if (rc)
			goto fail;

	}
	pbl_ptr = (u64 **)ctx->tqm_pde.pbl_ptr;
	for (i = 0, j = 0; i < MAX_TQM_ALLOC_REQ;
	     i++, j += MAX_TQM_ALLOC_BLK_SIZE) {
		if (!ctx->tqm_tbl[i].max_elements)
			continue;
		if (fnz_idx == -1)
			fnz_idx = i;
		switch (ctx->tqm_tbl[i].level) {
		case PBL_LVL_2:
			for (k = 0; k < ctx->tqm_tbl[i].pbl[PBL_LVL_1].pg_count;
			     k++)
				pbl_ptr[PTR_PG(j + k)][PTR_IDX(j + k)] =
				  cpu_to_le64(
				    ctx->tqm_tbl[i].pbl[PBL_LVL_1].pg_map_arr[k]
				    | PTU_PTE_VALID);
			break;
		case PBL_LVL_1:
		case PBL_LVL_0:
		default:
			pbl_ptr[PTR_PG(j)][PTR_IDX(j)] = cpu_to_le64(
				ctx->tqm_tbl[i].pbl[PBL_LVL_0].pg_map_arr[0] |
				PTU_PTE_VALID);
			break;
		}
	}
	if (fnz_idx == -1)
		fnz_idx = 0;
	ctx->tqm_pde_level = ctx->tqm_tbl[fnz_idx].level == PBL_LVL_2 ?
			     PBL_LVL_2 : ctx->tqm_tbl[fnz_idx].level + 1;

	/* TIM Buffer */
	ctx->tim_tbl.max_elements = ctx->qpc_count * 16;
	rc = bnxt_qplib_alloc_init_hwq(pdev, &ctx->tim_tbl, NULL, 0,
				       &ctx->tim_tbl.max_elements, 1,
				       0, PAGE_SIZE, HWQ_TYPE_CTX);
	if (rc)
		goto fail;

stats_alloc:
	/* Stats */
	rc = bnxt_qplib_alloc_stats_ctx(pdev, &ctx->stats);
	if (rc)
		goto fail;

	return 0;

fail:
	bnxt_qplib_free_ctx(pdev, ctx);
	return rc;
}

/* GUID */
void bnxt_qplib_get_guid(u8 *dev_addr, u8 *guid)
{
	u8 mac[ETH_ALEN];

	/* MAC-48 to EUI-64 mapping */
	memcpy(mac, dev_addr, ETH_ALEN);
	guid[0] = mac[0] ^ 2;
	guid[1] = mac[1];
	guid[2] = mac[2];
	guid[3] = 0xff;
	guid[4] = 0xfe;
	guid[5] = mac[3];
	guid[6] = mac[4];
	guid[7] = mac[5];
}

static void bnxt_qplib_free_sgid_tbl(struct bnxt_qplib_res *res,
				     struct bnxt_qplib_sgid_tbl *sgid_tbl)
{
	if (sgid_tbl->tbl) {
		kfree(sgid_tbl->tbl);
		kfree(sgid_tbl->hw_id);
		kfree(sgid_tbl->ctx);
	} else {
		dev_dbg(&res->pdev->dev, "QPLIB: SGID tbl not present");
	}
	sgid_tbl->tbl = NULL;
	sgid_tbl->hw_id = NULL;
	sgid_tbl->ctx = NULL;
	sgid_tbl->max = 0;
	sgid_tbl->active = 0;
}

#ifndef STACK_MANAGES_GID
int bnxt_qplib_netdev_del_gid(struct bnxt_qplib_sgid_tbl *sgid_tbl,
			      struct net_device *netdev)
{
	struct in_device *in_dev;
	struct bnxt_qplib_gid sgid;
	u16 vlan_id = 0xFFFF;
#if IS_ENABLED(CONFIG_IPV6)
	struct inet6_dev *in6_dev;
	struct inet6_ifaddr *ifp;
	struct bnxt_qplib_gid *pgid;
#endif
	int rc = 0;

	if (netdev->priv_flags & IFF_802_1Q_VLAN)
		vlan_id = vlan_dev_vlan_id(netdev);

	/* IPv4 */
	in_dev = in_dev_get(netdev);
	if (in_dev) {
		for_ifa(in_dev) {
			ipv6_addr_set_v4mapped(ifa->ifa_address,
					       (struct in6_addr *)&sgid);
			rc = bnxt_qplib_del_sgid(sgid_tbl, &sgid, true);
			if (rc)
				break;
		}
		endfor_ifa(in_dev);
		in_dev_put(in_dev);
	}
#if IS_ENABLED(CONFIG_IPV6)
	/* IPv6 */
	in6_dev = in6_dev_get(netdev);
	if (in6_dev) {
		read_lock_bh(&in6_dev->lock);
#ifdef HAVE_INET6_IF_LIST
		list_for_each_entry(ifp, &in6_dev->addr_list, if_list) {
#else
		for (ifp = in6_dev->addr_list; ifp; ifp = ifp->if_next) {
#endif
			pgid = (struct bnxt_qplib_gid *)&ifp->addr;
			read_unlock_bh(&in6_dev->lock);
			rc = bnxt_qplib_del_sgid(sgid_tbl, pgid, true);
			read_lock_bh(&in6_dev->lock);
			if (rc)
				break;
		}
		read_unlock_bh(&in6_dev->lock);
		in6_dev_put(in6_dev);
	}
#endif
	return rc;
}

int bnxt_qplib_netdev_add_gid(struct bnxt_qplib_sgid_tbl *sgid_tbl,
			      struct net_device *netdev)
{
	struct in_device *in_dev;
	struct bnxt_qplib_gid sgid;
	u16 vlan_id = 0xFFFF;
	u32 idx;
#if IS_ENABLED(CONFIG_IPV6)
	struct inet6_dev *in6_dev;
	struct inet6_ifaddr *ifp;
	struct bnxt_qplib_gid *pgid;
#endif
	int rc = 0;

	if (netdev->priv_flags & IFF_802_1Q_VLAN)
		vlan_id = vlan_dev_vlan_id(netdev);

	/* IPv4 */
	in_dev = in_dev_get(netdev);
	if (in_dev) {
		for_ifa(in_dev) {
			ipv6_addr_set_v4mapped(ifa->ifa_address,
					       (struct in6_addr *)&sgid);
			rc = bnxt_qplib_add_sgid(sgid_tbl, &sgid,
						 netdev->dev_addr,
						 vlan_id, true, &idx);
			if (rc)
				break;
		}
		endfor_ifa(in_dev);
		in_dev_put(in_dev);
	}
#if IS_ENABLED(CONFIG_IPV6)
	/* IPv6 */
	in6_dev = in6_dev_get(netdev);
	if (in6_dev) {
		read_lock_bh(&in6_dev->lock);
#ifdef HAVE_INET6_IF_LIST
		list_for_each_entry(ifp, &in6_dev->addr_list, if_list) {
#else
		for (ifp = in6_dev->addr_list; ifp; ifp = ifp->if_next) {
#endif
			pgid = (struct bnxt_qplib_gid *)&ifp->addr;
			read_unlock_bh(&in6_dev->lock);
			rc = bnxt_qplib_add_sgid(sgid_tbl, pgid,
						 netdev->dev_addr,
						 vlan_id, true, &idx);
			read_lock_bh(&in6_dev->lock);
			if (rc)
				break;
		}
		read_unlock_bh(&in6_dev->lock);
		in6_dev_put(in6_dev);
	}
#endif
	return rc;
}
#endif

static int bnxt_qplib_alloc_sgid_tbl(struct bnxt_qplib_res *res,
				     struct bnxt_qplib_sgid_tbl *sgid_tbl,
				     u16 max)
{
	sgid_tbl->tbl = kcalloc(max, sizeof(struct bnxt_qplib_gid), GFP_KERNEL);
	if (!sgid_tbl->tbl) {
		return -ENOMEM;
	}
	sgid_tbl->hw_id = kcalloc(max, sizeof(u32), GFP_KERNEL);
	if (!sgid_tbl->hw_id) {
		kfree(sgid_tbl->hw_id);
		return -ENOMEM;
	}
	sgid_tbl->ctx = kcalloc(max, sizeof(void *), GFP_KERNEL);
	if (!sgid_tbl->ctx) {
		kfree(sgid_tbl->ctx);
		return -ENOMEM;
	}
	sgid_tbl->max = max;
	return 0;
};

static void bnxt_qplib_cleanup_sgid_tbl(struct bnxt_qplib_res *res,
					struct bnxt_qplib_sgid_tbl *sgid_tbl)
{
	int i;

	for (i = 0; i < sgid_tbl->max; i++) {
		if (memcmp(&sgid_tbl->tbl[i], &bnxt_qplib_gid_zero,
			   sizeof(bnxt_qplib_gid_zero)))
			bnxt_qplib_del_sgid(sgid_tbl, &sgid_tbl->tbl[i], true);
	}
	memset(sgid_tbl->tbl, 0, sizeof(struct bnxt_qplib_gid) * sgid_tbl->max);
	memset(sgid_tbl->hw_id, -1, sizeof(u16) * sgid_tbl->max);
	sgid_tbl->active = 0;
}

static void bnxt_qplib_init_sgid_tbl(struct bnxt_qplib_sgid_tbl *sgid_tbl,
				     struct net_device *netdev)
{
#ifndef STACK_MANAGES_GID
	struct bnxt_qplib_gid sgid;
	__be64 prefix;
	u32 idx;
#endif
	memset(sgid_tbl->tbl, 0, sizeof(struct bnxt_qplib_gid) * sgid_tbl->max);
	memset(sgid_tbl->hw_id, -1, sizeof(u16) * sgid_tbl->max);

#ifndef STACK_MANAGES_GID
	if (!netdev)
		return;

	/* GID Index 0 - Unicast GID based on the endpoint's invariant
			 manufacturer-assigned EUI-64 */
	prefix = cpu_to_be64(0xfe80000000000000LL);
	memcpy(&sgid.data[0], &prefix, sizeof(prefix));
	bnxt_qplib_get_guid(netdev->dev_addr, &sgid.data[8]);
	bnxt_qplib_add_sgid(sgid_tbl, &sgid, netdev->dev_addr, 0xFFFF, true,
			    &idx);
	bnxt_qplib_netdev_add_gid(sgid_tbl, netdev);
#endif
}

static void bnxt_qplib_free_pkey_tbl(struct bnxt_qplib_res *res,
				     struct bnxt_qplib_pkey_tbl *pkey_tbl)
{
	if (!pkey_tbl->tbl)
		dev_dbg(&res->pdev->dev, "QPLIB: PKEY tbl not present");
	else
		kfree(pkey_tbl->tbl);

	pkey_tbl->tbl = NULL;
	pkey_tbl->max = 0;
	pkey_tbl->active = 0;
}

static int bnxt_qplib_alloc_pkey_tbl(struct bnxt_qplib_res *res,
				     struct bnxt_qplib_pkey_tbl *pkey_tbl,
				     u16 max)
{
	pkey_tbl->tbl = kcalloc(max, sizeof(u16), GFP_KERNEL);
	if (!pkey_tbl->tbl) {
		return -ENOMEM;
	}
	pkey_tbl->max = max;
	return 0;
};

/* PDs */
int bnxt_qplib_alloc_pd(struct bnxt_qplib_pd_tbl *pdt, struct bnxt_qplib_pd *pd)
{
	u32 bit_num;

	bit_num = find_first_bit(pdt->tbl, pdt->max);
	if (bit_num == pdt->max)
		return -ENOMEM;

	/* Found unused PD */
	clear_bit(bit_num, pdt->tbl);
	pd->id = bit_num;
	return 0;
}

int bnxt_qplib_dealloc_pd(struct bnxt_qplib_res *res,
			  struct bnxt_qplib_pd_tbl *pdt,
			  struct bnxt_qplib_pd *pd)
{
	if (test_and_set_bit(pd->id, pdt->tbl)) {
		dev_warn(&res->pdev->dev, "Freeing an unused PD? pdn = %d",
			 pd->id);
		return -EINVAL;
	}
	pd->id = 0;
	return 0;
}

static void bnxt_qplib_free_pd_tbl(struct bnxt_qplib_pd_tbl *pdt)
{
	if (pdt->tbl)
		kfree(pdt->tbl);
	pdt->max = 0;
}

static int bnxt_qplib_alloc_pd_tbl(struct bnxt_qplib_res *res,
				   struct bnxt_qplib_pd_tbl *pdt,
				   u32 max)
{
	u32 bytes;

	bytes = max >> 3;
	if (!bytes)
		bytes = 1;
	pdt->tbl = kmalloc(bytes, GFP_KERNEL);
	if (!pdt->tbl) {
		dev_err(&res->pdev->dev,
			"QPLIB: PD tbl allocation failed for size = %d", bytes);
		return -ENOMEM;
	}
	pdt->max = max;
	memset((u8 *)pdt->tbl, 0xFF, bytes);

	return 0;
}

/* DPIs */
int bnxt_qplib_alloc_dpi(struct bnxt_qplib_dpi_tbl *dpit,
			 struct bnxt_qplib_dpi     *dpi,
			 void                      *app)
{
	u32 bit_num;

	/*
	 * TODO: Will need a better algorithm here for PF/VF
	 * partitioning and checking if the 'app' already has
	 * a dpi.
	 */

	bit_num = find_first_bit(dpit->tbl, dpit->max);
	if (bit_num == dpit->max)
		return -ENOMEM;

	/* Found unused DPI */
	clear_bit(bit_num, dpit->tbl);
	dpit->app_tbl[bit_num] = app;

	dpi->dpi = bit_num;
	dpi->dbr = dpit->dbr_bar_reg_iomem + (bit_num * PAGE_SIZE);
	dpi->umdbr = dpit->unmapped_dbr + (bit_num * PAGE_SIZE);

	return 0;
}

int bnxt_qplib_dealloc_dpi(struct bnxt_qplib_res *res,
			   struct bnxt_qplib_dpi_tbl *dpit,
			   struct bnxt_qplib_dpi     *dpi)
{
	if (dpi->dpi >= dpit->max) {
		dev_warn(&res->pdev->dev, "Invalid DPI? dpi = %d", dpi->dpi);
		return -EINVAL;
	}
	if (test_and_set_bit(dpi->dpi, dpit->tbl)) {
		dev_warn(&res->pdev->dev, "Freeing an unused DPI? dpi = %d",
			 dpi->dpi);
		return -EINVAL;
	}
	if (dpit->app_tbl)
		dpit->app_tbl[dpi->dpi] = NULL;
	memset(dpi, 0, sizeof(*dpi));

	return 0;
}

static void bnxt_qplib_free_dpi_tbl(struct bnxt_qplib_res     *res,
				    struct bnxt_qplib_dpi_tbl *dpit)
{
	if (dpit->tbl)
		kfree(dpit->tbl);
	if (dpit->app_tbl)
		kfree(dpit->app_tbl);
	if (dpit->dbr_bar_reg_iomem)
		pci_iounmap(res->pdev, dpit->dbr_bar_reg_iomem);
	memset(dpit, 0, sizeof(*dpit));
}

static int bnxt_qplib_alloc_dpi_tbl(struct bnxt_qplib_res     *res,
				    struct bnxt_qplib_dpi_tbl *dpit,
				    u32                       dbr_offset)
{
	resource_size_t bar_reg_base;
	u32 dbr_bar_reg = RCFW_DBR_PCI_BAR_REGION;
	u32 dbr_len, bytes;

	if (dpit->dbr_bar_reg_iomem) {
		dev_err(&res->pdev->dev,
			"QPLIB: DBR BAR region %d already mapped", dbr_bar_reg);
		return -EALREADY;
	}

	bar_reg_base = pci_resource_start(res->pdev, dbr_bar_reg);
	if (!bar_reg_base) {
		dev_err(&res->pdev->dev,
			"QPLIB: BAR region %d resc start failed", dbr_bar_reg);
		return -ENOMEM;
	}

	dbr_len = pci_resource_len(res->pdev, dbr_bar_reg) - dbr_offset;
	if (!dbr_len || ((dbr_len & (PAGE_SIZE - 1)) != 0)) {
		dev_err(&res->pdev->dev, "QPLIB: Invalid DBR length %d",
			dbr_len);
		return -ENOMEM;
	}

	dpit->dbr_bar_reg_iomem = ioremap_nocache(bar_reg_base + dbr_offset,
						  dbr_len);
	if (!dpit->dbr_bar_reg_iomem) {
		dev_err(&res->pdev->dev,
			"QPLIB: FP: DBR BAR region %d mapping failed",
			dbr_bar_reg);
		return -ENOMEM;
	}

	dpit->unmapped_dbr = bar_reg_base + dbr_offset;
	dpit->max = dbr_len / PAGE_SIZE;

	dpit->app_tbl = kzalloc(dpit->max * sizeof(void*), GFP_KERNEL);
	if (!dpit->app_tbl) {
		pci_iounmap(res->pdev, dpit->dbr_bar_reg_iomem);
		dev_err(&res->pdev->dev,
			"QPLIB: DPI app tbl allocation failed");
		return -ENOMEM;
	}

	bytes = dpit->max >> 3;
	if (!bytes)
		bytes = 1;

	dpit->tbl = kmalloc(bytes, GFP_KERNEL);
	if (!dpit->tbl) {
		pci_iounmap(res->pdev, dpit->dbr_bar_reg_iomem);
		kfree(dpit->app_tbl);
		dev_err(&res->pdev->dev,
			"QPLIB: DPI tbl allocation failed for size = %d",
			bytes);
		return -ENOMEM;
	}

	memset((u8 *)dpit->tbl, 0xFF, bytes);

	return 0;
}

/* PKEYs */
void bnxt_qplib_cleanup_pkey_tbl(struct bnxt_qplib_pkey_tbl *pkey_tbl)
{
	/* TODO: Send cmd to Bono to remove all pkeys in the pkey_tbl */

	memset(pkey_tbl->tbl, 0, sizeof(u16) * pkey_tbl->max);
	pkey_tbl->active = 0;
}

static void bnxt_qplib_init_pkey_tbl(struct bnxt_qplib_res *res,
				     struct bnxt_qplib_pkey_tbl *pkey_tbl)
{
	u16 pkey = 0xFFFF;

	memset(pkey_tbl->tbl, 0, sizeof(u16) * pkey_tbl->max);

	/* pkey default = 0xFFFF */
	bnxt_qplib_add_pkey(res, pkey_tbl, &pkey, false);

	/* TODO: Send cmd to Bono to inform about the def pkey? */
}

/* Stats */
static void bnxt_qplib_free_stats_ctx(struct pci_dev *pdev,
				      struct bnxt_qplib_stats *stats)
{
	if (stats->dma) {
		dma_free_coherent(&pdev->dev, stats->size,
				  stats->dma, stats->dma_map);
	}
	memset(stats, 0, sizeof(*stats));
	stats->fw_id = -1;
}

static int bnxt_qplib_alloc_stats_ctx(struct pci_dev *pdev,
				      struct bnxt_qplib_stats *stats)
{
	memset(stats, 0, sizeof(*stats));
	stats->fw_id = -1;
	stats->size = sizeof(struct ctx_hw_stats);
	stats->dma = dma_alloc_coherent(&pdev->dev, stats->size,
					&stats->dma_map, GFP_KERNEL);
	if (!stats->dma) {
		dev_err(&pdev->dev, "QPLIB: Stats DMA allocation failed");
		return -ENOMEM;
	}
	return 0;
}

/* Resource */
int bnxt_qplib_stop_res(struct bnxt_qplib_res *res)
{
	struct bnxt_qplib_rcfw *rcfw = res->rcfw;
	struct cmdq_stop_func req;
	struct creq_stop_func_resp resp;
	u16 cmd_flags = 0;
	int rc;

	RCFW_CMD_PREP(req, STOP_FUNC, cmd_flags);

	rc = bnxt_qplib_rcfw_send_message(rcfw, (void *)&req, (void *)&resp,
					  NULL, 0);
	return rc;
}

void bnxt_qplib_cleanup_res(struct bnxt_qplib_res *res)
{
	bnxt_qplib_cleanup_pkey_tbl(&res->pkey_tbl);
	bnxt_qplib_cleanup_sgid_tbl(res, &res->sgid_tbl);
}

int bnxt_qplib_init_res(struct bnxt_qplib_res *res)
{
	bnxt_qplib_init_sgid_tbl(&res->sgid_tbl, res->netdev);
	bnxt_qplib_init_pkey_tbl(res, &res->pkey_tbl);

	return 0;
}

void bnxt_qplib_free_res(struct bnxt_qplib_res *res)
{
	bnxt_qplib_free_pkey_tbl(res, &res->pkey_tbl);
	bnxt_qplib_free_sgid_tbl(res, &res->sgid_tbl);
	bnxt_qplib_free_pd_tbl(&res->pd_tbl);
	bnxt_qplib_free_dpi_tbl(res, &res->dpi_tbl);

	res->netdev = NULL;
	res->pdev = NULL;
}

int bnxt_qplib_alloc_res(struct bnxt_qplib_res *res, struct pci_dev *pdev,
			 struct net_device *netdev,
			 struct bnxt_qplib_dev_attr *dev_attr)
{
	int rc = 0;

	res->pdev = pdev;
	res->netdev = netdev;

	rc = bnxt_qplib_alloc_sgid_tbl(res, &res->sgid_tbl, dev_attr->max_sgid);
	if (rc)
		goto fail;

	rc = bnxt_qplib_alloc_pkey_tbl(res, &res->pkey_tbl, dev_attr->max_pkey);
	if (rc)
		goto fail;

	rc = bnxt_qplib_alloc_pd_tbl(res, &res->pd_tbl, dev_attr->max_pd);
	if (rc)
		goto fail;

	rc = bnxt_qplib_alloc_dpi_tbl(res, &res->dpi_tbl, dev_attr->l2_db_size);
	if (rc)
		goto fail;

	return 0;
fail:
	bnxt_qplib_free_res(res);
	return rc;
}
