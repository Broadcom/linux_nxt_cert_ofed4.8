#!/usr/bin/make
# Makefile for building Linux Broadcom Gigabit ethernet RDMA driver as a module.
# $id$
KVER=
ifeq ($(KVER),)
  KVER=$(shell uname -r)
endif

__ARCH=$(shell uname -m)

ifeq ($(BNXT_EN_INC),)
  BNXT_EN_INC=$(shell pwd)/../bnxt_en
  export BNXT_EN_INC
endif

ifeq ($(BNXT_QPLIB_INC),)
  BNXT_QPLIB_INC=$(shell pwd)/bnxt_qplib
  export BNXT_QPLIB_INC
endif

# PREFIX may be set by the RPM build to set the effective root.
PREFIX=
ifeq ($(shell ls /lib/modules/$(KVER)/build > /dev/null 2>&1 && echo build),)
# SuSE source RPMs
  _KVER=$(shell echo $(KVER) | cut -d "-" -f1,2)
  _KFLA=$(shell echo $(KVER) | cut -d "-" -f3)
  _ARCH=$(shell file -b /lib/modules/$(shell uname -r)/build | cut -d "/" -f5)
  ifeq ($(_ARCH),)
    _ARCH=$(__ARCH)
  endif
  ifeq ($(shell ls /usr/src/linux-$(_KVER)-obj > /dev/null 2>&1 && echo linux),)
    ifeq ($(shell ls /usr/src/kernels/$(KVER)-$(__ARCH) > /dev/null 2>&1 && echo linux),)
      LINUX=
    else
      LINUX=/usr/src/kernels/$(KVER)-$(__ARCH)
      LINUXSRC=$(LINUX)
    endif
  else
    LINUX=/usr/src/linux-$(_KVER)-obj/$(_ARCH)/$(_KFLA)
    LINUXSRC=/usr/src/linux-$(_KVER)
  endif
else
  LINUX=/lib/modules/$(KVER)/build
  ifeq ($(shell ls /lib/modules/$(KVER)/source > /dev/null 2>&1 && echo source),)
    LINUXSRC=$(LINUX)
  else
    LINUXSRC=/lib/modules/$(KVER)/source
  endif
endif

ifeq ($(shell ls $(LINUXSRC)/include/uapi > /dev/null 2>&1 && echo uapi),)
  UAPI=
else
  UAPI=uapi
endif

ifeq ($(BCMMODDIR),)
  ifeq ($(shell ls /lib/modules/$(KVER)/updates > /dev/null 2>&1 && echo 1),1)
    BCMMODDIR=/lib/modules/$(KVER)/updates/drivers/infiniband/hw/bnxt_re
  else
    ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.conf > /dev/null 2>&1 && echo 1),1)
      BCMMODDIR=/lib/modules/$(KVER)/updates/drivers/infiniband/hw/bnxt_re
    else
      ifeq ($(shell grep -q "search.*[[:space:]]updates" /etc/depmod.d/* > /dev/null 2>&1 && echo 1),1)
        BCMMODDIR=/lib/modules/$(KVER)/updates/drivers/infiniband/hw/bnxt_re
      else
        BCMMODDIR=/lib/modules/$(KVER)/kernel/drivers/infiniband/hw/bnxt_re
      endif
    endif
  endif
endif

ifeq ($(OFED_VERSION), )
     $(warning Using native IB stack)
     $(warning Please check OS support matrix. Run export OFED_VERSION=OFED-3.18-2 if OFED is installed)
     OFED_VERSION=OFED-NATIVE
endif

#find OFED version and compat-includes
ofed_major=$(filter OFED-3.% OFED-4.%, $(OFED_VERSION))
ifneq ($(ofed_major), )
exists=$(shell if [ -e /usr/src/compat-rdma$(OFED_VERSION) ];\
                then echo y; fi)
ifeq ($(exists), )
$(shell ln -s /usr/src/compat-rdma\
         /usr/src/compat-rdma$(OFED_VERSION))
endif
OFA_BUILD_PATH=/usr/src/compat-rdma$(OFED_VERSION)
OFA_KERNEL_PATH=/usr/src/compat-rdma$(OFED_VERSION)
EXTRA_CFLAGS += -DOFED_3_x
EXTRA_CFLAGS += -include $(OFA_KERNEL_PATH)/include/linux/compat-2.6.h

AUTOCONF_H = -include $(shell /bin/ls -1 $(LINUX)/include/*/autoconf.h 2> /dev/null | head -1)
endif #end non 3.x OFED

ifeq (OFED-NATIVE, $(findstring OFED-NATIVE, $(OFED_VERSION)))
ifeq ($(KERNELRELEASE),)
OFA_BUILD_PATH =/lib/modules/`uname -r`/build/
OFA_KERNEL_PATH=/lib/modules/`uname -r`/source/
else
OFA_BUILD_PATH =/lib/modules/$(KERNELRELEASE)/build/
OFA_KERNEL_PATH=/lib/modules/$(KERNELRELEASE)/source/
endif
endif

ifeq ($(shell ls /lib/modules/$(KVER)/source > /dev/null 2>&1 && echo source),)
OFA_KERNEL_PATH=$(OFA_BUILD_PATH)
endif

EXTRA_CFLAGS += -I$(BNXT_EN_INC)
KBUILD_EXTRA_SYMBOLS := $(OFA_BUILD_PATH)/Module.symvers

# Distro specific compilation flags
DISTRO_CFLAG = -D__LINUX

ifneq ($(shell grep "netdev_notifier_info_to_dev" $(LINUXSRC)/include/linux/netdevice.h > /dev/null 2>&1 && echo netdev_not),)
  DISTRO_CFLAG += -DHAVE_NETDEV_NOTIFIER_INFO_TO_DEV
endif

ifneq ($(shell grep "register_netdevice_notifier_rh" $(LINUXSRC)/include/linux/netdevice.h > /dev/null 2>&1 && echo register_net),)
  DISTRO_CFLAG += -DHAVE_REGISTER_NETDEVICE_NOTIFIER_RH
endif

ifneq ($(shell grep -so "ib_mw_type" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo ib_mw_type),)
  DISTRO_CFLAG += -DHAVE_IB_MW_TYPE
endif

ifneq ($(shell grep -A 3 "alloc_mw" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h |grep "struct ib_udata" > /dev/null 2>&1 && echo ib_udata),)
  DISTRO_CFLAG += -DHAVE_ALLOW_MW_WITH_UDATA
endif

ifneq ($(shell grep -so "ib_bind_mw" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo ib_bind_mw),)
  DISTRO_CFLAG += -DHAVE_IB_BIND_MW
endif

ifneq ($(shell grep "ib_create_mr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo ib_create_mr),)
  DISTRO_CFLAG += -DHAVE_IB_CREATE_MR
endif

ifneq ($(shell grep "ib_flow" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo ib_flow),)
  DISTRO_CFLAG += -DHAVE_IB_FLOW
endif

ifneq ($(shell grep "rereg_user_mr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo rereg_user_mr),)
  DISTRO_CFLAG += -DHAVE_IB_REREG_USER_MR
endif

ifneq ($(shell grep "MEM_WINDOW_TYPE" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo mem_window_type),)
  DISTRO_CFLAG += -DHAVE_IB_MEM_WINDOW_TYPE
endif

ifneq ($(shell grep "odp_caps" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo odp_caps),)
  DISTRO_CFLAG += -DHAVE_IB_ODP_CAPS
endif

ifneq ($(shell grep "IP_BASED_GIDS" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo ip_based_gids),)
  DISTRO_CFLAG += -DHAVE_IB_BASED_GIDS
endif

ifneq ($(shell grep "dmac" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo dmac),)
  DISTRO_CFLAG += -DHAVE_IB_AH_DMAC
endif

ifneq ($(shell grep "IB_ZERO_BASED" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo zero),)
  DISTRO_CFLAG += -DHAVE_IB_ZERO_BASED
endif

ifneq ($(shell grep "IB_ACCESS_ON_DEMAND" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo demand),)
  DISTRO_CFLAG += -DHAVE_IB_ACCESS_ON_DEMAND
endif

ifneq ($(shell grep "sg_table" $(OFA_KERNEL_PATH)/include/rdma/ib_umem.h > /dev/null 2>&1 && echo sg_table),)
  DISTRO_CFLAG += -DHAVE_IB_UMEM_SG_TABLE
endif

ifneq ($(shell grep "ib_mr_init_attr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo mr_init_attr),)
  DISTRO_CFLAG += -DHAVE_IB_MR_INIT_ATTR
endif

# add_gid/del_gid replaced the modify_gid
ifneq ($(shell grep "add_gid" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo add_gid),)
  DISTRO_CFLAG += -DHAVE_IB_ADD_DEL_GID
endif

ifneq ($(shell grep "modify_gid" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo modify_gid),)
  DISTRO_CFLAG += -DHAVE_IB_MODIFY_GID
endif

ifneq ($(shell grep -A 3 "struct ib_gid_attr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo struct ib_gid_attr),)
  DISTRO_CFLAG += -DHAVE_IB_GID_ATTR
endif

ifneq ($(shell grep -A 3 "struct ib_bind_mw_wr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo struct ib_bind_mw_wr),)
  DISTRO_CFLAG += -DHAVE_IB_BIND_MW_WR
endif

ifneq ($(shell grep "alloc_mr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo alloc_mr),)
  DISTRO_CFLAG += -DHAVE_IB_ALLOC_MR
endif

ifneq ($(shell grep "query_mr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo query_mr),)
  DISTRO_CFLAG += -DHAVE_IB_QUERY_MR
endif

ifneq ($(shell grep "alloc_fast_reg_mr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo fast_reg_mr),)
  DISTRO_CFLAG += -DHAVE_IB_FAST_REG_MR
endif

ifneq ($(shell grep "map_mr_sg" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo map_mr_sg),)
  DISTRO_CFLAG += -DHAVE_IB_MAP_MR_SG
endif

ifneq ($(shell grep -A 2 "int ib_map_mr_sg" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h | grep sg_offset > /dev/null 2>&1 && echo sg_offset),)
  DISTRO_CFLAG += -DHAVE_IB_MAP_MR_SG_OFFSET
endif

ifneq ($(shell grep -A 2 "int ib_map_mr_sg" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h | grep page_size > /dev/null 2>&1 && echo page_size),)
  DISTRO_CFLAG += -DHAVE_IB_MAP_MR_SG_PAGE_SIZE
endif

ifneq ($(shell grep "IB_WR_FAST_REG_MR" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo fast_reg_mr),)
  DISTRO_CFLAG += -DHAVE_IB_FAST_REG_MR_WR
endif

ifneq ($(shell grep "IB_WR_REG_MR" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo wr_reg_mr),)
  DISTRO_CFLAG += -DHAVE_IB_REG_MR_WR
endif

ifneq ($(shell grep "IB_WR_BIND_MW" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo bind_mw),)
  DISTRO_CFLAG += -DHAVE_IB_WR_BIND_MW
endif

ifneq ($(shell grep "rdma_wr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo rdma_wr),)
  DISTRO_CFLAG += -DHAVE_IB_RDMA_WR
endif

ifneq ($(shell grep "reg_phys_mr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo reg_phys_mr),)
  DISTRO_CFLAG += -DHAVE_IB_REG_PHYS_MR
endif

ifneq ($(shell grep "ud_wr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo ud_wr),)
  DISTRO_CFLAG += -DHAVE_IB_UD_WR
endif

ifneq ($(shell grep "get_netdev" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo get_netdev),)
  DISTRO_CFLAG += -DHAVE_IB_GET_NETDEV
endif

ifneq ($(shell grep "get_port_immutable" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo port_immutable),)
  DISTRO_CFLAG += -DHAVE_IB_GET_PORT_IMMUTABLE
endif

ifneq ($(shell grep "ib_mad_hdr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo ib_mad_hdr),)
  DISTRO_CFLAG += -DHAVE_IB_MAD_HDR
endif

ifneq ($(shell grep "query_device" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h -A2 | grep udata > /dev/null 2>&1 && echo query_device),)
  DISTRO_CFLAG += -DHAVE_IB_QUERY_DEVICE_UDATA
endif

ifneq ($(shell grep "cq_init_attr" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo cq_init_attr),)
  DISTRO_CFLAG += -DHAVE_IB_CQ_INIT_ATTR
endif

ifneq ($(shell grep "drain_rq" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo drain_rq),)
  DISTRO_CFLAG += -DHAVE_IB_DRAIN
endif

ifneq ($(shell grep "roce_gid_cache" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo roce_gid_cache),)
  DISTRO_CFLAG += -DUSE_ROCE_GID_CACHE -DSTACK_MANAGES_GID
endif

ifneq ($(shell grep "roce_gid_table" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo roce_gid_table),)
  DISTRO_CFLAG += -DUSE_ROCE_GID_TABLE -DSTACK_MANAGES_GID
endif

ifneq ($(shell grep "RDMA_CORE_CAP_PROT_ROCE_UDP_ENCAP" $(OFA_KERNEL_PATH)/include/rdma/ib_verbs.h > /dev/null 2>&1 && echo roce_v2_enable),)
  DISTRO_CFLAG +=  -DENABLE_SHADOW_QP -DENABLE_ROCEV2_QP1
endif

ifneq (,$(shell grep -so "ETHTOOL_LINK_MODE_25000baseCR_Full_BIT" $(LINUXSRC)/include/$(UAPI)/linux/ethtool.h $(LINUXSRC)/include/linux/ethtool.h))
  DISTRO_CFLAG += -DHAVE_ETHTOOL_GLINKSETTINGS_25G
endif

ifneq ($(shell grep -o "rdma_addr_find_l2_eth_by_grh" $(OFA_KERNEL_PATH)/include/rdma/ib_addr.h),)
  DISTRO_CFLAG += -DHAVE_RDMA_ADDR_FIND_L2_ETH_BY_GRH
endif

ifneq ($(shell grep -A 2 "rdma_addr_find_dmac_by_grh" $(OFA_KERNEL_PATH)/include/rdma/ib_addr.h | grep if_index),)
  DISTRO_CFLAG += -DHAVE_RDMA_ADDR_FIND_DMAC_BY_GRH_V2
endif

ifneq (,$(shell grep -o "if_list" $(LINUXSRC)/include/net/if_inet6.h))
  DISTRO_CFLAG += -DHAVE_INET6_IF_LIST
endif

ifneq ($(shell grep -o "PKT_HASH_TYPE" $(LINUXSRC)/include/linux/skbuff.h),)
  DISTRO_CFLAG += -DHAVE_SKB_HASH_TYPE
endif
EXTRA_CFLAGS += ${DISTRO_CFLAG} -DFPGA -g -DCONFIG_BNXT_SRIOV -DCONFIG_BNXT_DCB -DHAVE_NET_VERSION -DENABLE_DEBUGFS -DCONFIG_BNXT_RE -DENABLE_SHADOW_QP -DENABLE_ROCE_TOS -DBIND_MW_FENCE_WQE
EXTRA_CFLAGS += -I$(BNXT_QPLIB_INC) -I$(BNXT_EN_INC)

BCM_DRV = bnxt_re.ko

KSRC=$(LINUXSRC)

ifneq (OFED-NATIVE, $(findstring OFED-NATIVE, $(OFED_VERSION)))
OFED_INCLUDES := LINUXINCLUDE=' \
                $(AUTOCONF_H) \
                -I$(OFA_KERNEL_PATH)/include \
                -I$(OFA_KERNEL_PATH)/include/uapi \
		 $$(if $$(CONFIG_XEN),-D__XEN_INTERFACE_VERSION__=$$(CONFIG_XEN_INTERFACE_VERSION)) \
		 $$(if $$(CONFIG_XEN),-I$$(KSRC)/arch/x86/include/mach-xen) \
                -I$(OFA_KERNEL_PATH)/arch/$$(SRCARCH)/include/generated/uapi \
                -I$(OFA_KERNEL_PATH)/arch/$$(SRCARCH)/include/generated \
                -Iinclude \
                -I$(KSRC)/include \
                -I$(KSRC)/arch/$$(SRCARCH)/include \
                -I$(KSRC)/include/generated/uapi \
                -I$(KSRC)/include/uapi \
                -I$(KSRC)/arch/$$(SRCARCH)/include/uapi \
                -I$(KSRC)/arch/$$(SRCARCH)/include/generated \
                -I$(KSRC)/arch/$$(SRCARCH)/include/generated/uapi \
                -I$(KDIR)/include/generated/uapi \
                -I$(KDIR)/arch/$$(SRCARCH)/include/generated \
                -I$(KDIR)/arch/$$(SRCARCH)/include/generated/uapi'

OFA_KERNEL_LINK = $(OFA_KERNEL_PATH)
OFA_BUILD_LINK = $(OFA_BUILD_PATH)
endif

cflags-y += $(EXTRA_CFLAGS)

ifneq ($(KERNELRELEASE),)

obj-m += bnxt_re.o
bnxt_re-y := bnxt_re_main.o bnxt_re_ib_verbs.o bnxt_re_debugfs.o bnxt_re_compat.o	\
	     bnxt_qplib/bnxt_qplib_res.o bnxt_qplib/bnxt_qplib_rcfw.o			\
	     bnxt_qplib/bnxt_qplib_sp.o bnxt_qplib/bnxt_qplib_fp.o

else

default:
	make -C $(LINUX) SUBDIRS=$(shell pwd) $(OFED_INCLUDES) modules

yocto_all:
	$(MAKE) -C $(LINUXSRC) M=$(shell pwd)

modules_install:
	$(MAKE) -C $(LINUXSRC) M=$(shell pwd) modules_install

endif

install: default
	echo $(PREFIX)
	echo $(BCMMODDIR)
	echo $(BCM_DRV)
	mkdir -p $(PREFIX)/$(BCMMODDIR);
	install -m 444 $(BCM_DRV) $(PREFIX)/$(BCMMODDIR);
	@if [ "$(PREFIX)" = "" ]; then /sbin/depmod -a ;\
	else echo " *** Run '/sbin/depmod -a' to update the module database.";\
	fi

.PHONEY: all clean install

clean:
	-rm -f bnxt_re*.o bnxt_re.mod.c bnxt_re.mod.o .bnxt_re*.*.cmd *.cmd *.markers *.order *.symvers *.unsigned
	-rm -f bnxt_qplib/bnxt_qplib*.o bnxt_qplib/.bnxt_qplib*.*.cmd
	-rm -rf .tmp_versions
	-rm -rf bnxt_re.ko bnxt_re.mod.o bnxt_re.mod.c .bnxt_re.*
	-rm -f Module.markers Module.symvers modules.order
