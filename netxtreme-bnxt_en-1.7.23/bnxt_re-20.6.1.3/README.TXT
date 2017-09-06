                               README Notes
                    Broadcom bnxt_re Linux RoCE Driver
                             Version 20.6.1.3
                                 04/10/2017

                            Broadcom Limited
                         5300 California Avenue,
                            Irvine, CA 92617

                   Copyright (c) 2015-2017 Broadcom
                           All rights reserved


Table of Contents
=================

  Introduction
  Limitations
  BNXT_RE Driver Dependencies
  BNXT_RE Driver compilation
  BNXT_RE Driver Settings
  BNXT_RE Dynamic Debug Messages
  BNXT_RE Driver Defaults
  Configuration Tips
  Unloading and Removing Driver
  LLDPAD configuration
  VF Resource Distribution


Introduction
============

This file describes the bnxt_re Linux RoCE driver for the Broadcom NetXtreme-C
and NetXtreme-E BCM573xx and BCM574xx 10/20/25/40/50 Gbps Ethernet Network
Controllers.


Limitations
===========

- The current version of the driver will compile on RHEL7.x, RHEL6.7/6.8,
  SLES11 SP4, SLES12 SP2, Ubuntu 16.04 and most 3.x/4.x kernels, and some
  2.6 kernels starting from 2.6.32-573.

- The current version of the driver supports only Ubuntu 14.04.4 and
  14.04.5 (latest) with 4.x kernel

- RoCE V2 is supported only on RHEL 7.3 or 4.7 kernels or latest kernels.

- When remote directories are mounted using NFS-RDMA, unloading bnxt_re shall
  cause system hang and the system needs a reboot for normal operations.
  Always unmount all active NFS mounts over bnxt_re interface, before unloading
  bnxt_re driver.

- Using same MTU on both client and server is recommended.  User can see unexpected
  results if there is a mismatch in MTUs on Client and Server.

- Changing MAC address of the interface while bnxt_re is loaded can trigger failure
  during GID deletion. Unload bnxt_re driver before changing the interface MAC address.

- The krping tool requires an update in order to operate under the RHEL7.2.
  The driver has passed the 4 standard test cases using (get_dma, fast_reg,
  mr, and mw).

- HW supports upto 239 applications per RoCE function

- The legacy FMR Pool is not supported yet.

- Resize CQ is not supported yet.

- Raw Ethertype QP is not supported yet.

- Tunnel is not supported yet.

- A max of 65278 QPs, 65535 SRQs, 65535 CQs, and 65536 MR/MWs are being supported.

- Linux RoCE driver supports only 127 entries deep GID table per port.
  Thus, effectively only 126 different VLANs could be active in a RoCE V1 only
  mode. If RoCE V2 is supported, driver supports upto 63 VLANs.

- Current driver doesn't support VLAN 0 priority tagging.

- On SLES11 SP4 default kernel(3.0.101-63-default), tc command to map the
  priority to traffic class throws error and hence ETS b/w will not get
  honored when NIC + RoCE traffic is run together.
  This issue is fixed in 3.0.101-91-default. Users are advised to upgrade to
  this kernel while testing ETS.

- On RHEL7.3 kernel (3.10.0-514.el7.x86_64), the following issues are seen
  with NFSoRDMA stack. The issues are fixed in upstream kernel.

  1. In some rare conditions, while recovering from errors due to connection
     loss, the nfs server side could crash with the following message:
	"kernel BUG at drivers/iommu/iova.c:208!"
     This is fixed upstream in 'svcrdma' kernel module by this commit:
	commit ce1ca7d2d140a1f4aaffd297ac487f246963dd2f
	svcrdma: avoid duplicate dma unmapping during error recovery

  2. In some rare conditions, after recovering from errors due to connection
     loss, the mount point could become unresponsive on the nfs client. The
     nfs client logs the following message in this condition:
	"RPC: rpcrdma_buffer_get: out of reply buffers"
     This is fixed upstream in 'xprtrdma' kernel module by this commit:
	commit 05c974669ecec510a85d8534099bb75404e82c41
	xprtrdma: Fix receive buffer accounting

  3. The nfs server crashes with the following message when the IP address
     of a network interface is changed on the server:
	"general protection fault: 0000 [#1] SMP"
     This is fixed upstream in 'sunrpc' kernel module by this commit:
	commit ea08e39230e898844d9de5b60cdbb30067cebfe7
	sunrpc: svc_age_temp_xprts_now should not call setsockopt non-tcp
		transports

- For enabling RoCE SR-IOV on RH 6.x, the following driver load sequence should
  be followed. bnxt_re driver load fails otherwise.

	#service NetworkManager stop
	#modprobe bnxt_re
	#modprobe bnxt_en num_vfs=<num_vfs>
	#ifconfig <iface> up
	#modprobe bnxt_en num_vfs=<num_vfs>


BNXT_RE Driver Dependencies
===========================

The RoCE driver has dependencies on the bnxt_en networking counterpart.

 -  Note that the current driver release requires a special RoCE enabled
    version of bnxt_en included in the package.

  - It also has dependencies on the IB verbs kernel component
    (Details given below).

BNXT_RE Driver compilation
==========================

bnxt_re driver compilation depends on whether IB stack is available along with
the OS distribution or an external OFED is required.

 => Distros that has IB Stack available along with OS distribution:
    RH7.1/7.2/7.3/6.7/6.8, SLES12SP2 and Ubuntu 16.04/14.04

To compile bnxt_re:
	$make

 => Distros that need external OFED to be installed:
    SLES11SP4

Please refer OFED release notes from the following link and install
OFED before compiling bnxt_re driver.
http://downloads.openfabrics.org/downloads/OFED/release_notes/OFED_3.18-2_release_notes

To compile bnxt_re:
	$export OFED_VERSION=OFED-3.18-2
	$make


Configuration Tips
==================

- It is recommended to use same host OS version on client and server while
  running NFS-RDMA or iSER tests. Heterogeneous host OS may lead to unexpected
  results. This is due to the incompatible ULP server and Client kernel modules.

- It is recommended to assign at least 3GB RAM to VMs used for memory intensive
  applications like NFSoRDMA, iSER, NVMoF etc.

- When using large number of QPs (close to maximum supported) along with large
  message sizes it is recommended to increase the `max_map_count` kernel parameter
  using sysctl to avoid memory map failures in the application.
  Please refer to https://www.kernel.org/doc/Documentation/sysctl/vm.txt on how to tune
  this kernel parameter.

- When L2 and RoCE traffic are running simultaneously with high work load or
  RoCE traffic with high work load, it could result in high CPU utilization
  leading to CPU soft lockup. Hence it is recommended to spread the workload
  across the available CPU cores. This can be achieved by setting the SMP
  affinity of the interrupts and RoCE applications.
  Please refer to OS documentation for setting smp_affinity and specific
  commands like taskset etc.

BNXT_RE Driver Settings
=======================

The driver supports debugFS which allows statistics and debug parameters be dumped
to the debugFS.  The following list of info will be displayed when the bnxt_re
debugFS info file is queried as follows:

cat /sys/kernel/debug/bnxt_re/info

bnxt_re debug info:
Adapter count:  1
=====[ IBDEV bnxt_re0 ]=============================
	link state: UP
	Max QP: 0xff7f
	Max SRQ: 0xffff
	Max CQ: 0xffff
	Max MR: 0x10000
	Max MW: 0x10000
	Active QP: 0x2
	Active SRQ: 0x0
	Active CQ: 0x21
	Active MR: 0x4
	Active MW: 0x0


BNXT_RE Dynamic Debug Messages
==============================
The bnxt_re driver now supports dynamic debug feature.
With this change, the driver debug module parameter
- "debug_level", is removed.
All error, warning and info messages are logged by default.
Any debug messages if needed, could be enabled by writing to
the standard <debugfs>/dynamic_debug/control file.
Debug messages can be enabled/disabled at various granularities
like - module, file, function, a range of line numbers or a
specific line number.

The following kernel document describes this in detail with examples:
https://www.kernel.org/doc/Documentation/dynamic-debug-howto.txt

A few examples on how to use this with bnxt_re driver:

1) To check the debug messages that are available in bnxt_re:
# cat /sys/kernel/debug/dynamic_debug/control | grep bnxt_re

2) To enable all debug messages in bnxt_re during load time:
# insmod bnxt_re.ko  dyndbg==p

3) To enable all debug messages in bnxt_re after loading:
# echo "module bnxt_re +p" > /sys/kernel/debug/dynamic_debug/control

4) To disable all debug messages in bnxt_re after loading:
# echo "module bnxt_re -p" > /sys/kernel/debug/dynamic_debug/control

5) To enable a debug message at a specific line number in a file:
# echo -n "file bnxt_qplib_fp.c line 2554 +p" > /sys/kernel/debug/dynamic_debug/control

BNXT_RE Compiler Switches
=========================

ENABLE_DEBUGFS - Enable debugFS operation

ENABLE_RE_FP_SPINLOCK - Enable spinlocks on the fast path bnxt_re_qp queue
			resources

ENABLE_FP_SPINLOCAK - Enable spinlocks on the fast path bnxt_qplib queue
		      resources

ENABLE_DEBUG_SGE - Enable the dumping of SGE info to the journal log


BNXT_RE Driver Defaults
=======================


Unloading and Removing Driver
=============================

rmmod bnxt_re


LLDPAD configuration
========================
Note: If the switches are capable of handling RoCE TLVs, the following
settings are not required and adapter will override local settings, if any,
with the switch settings.

Note: VF inherits the PFC settings of the PF. VF doesn't have privilege to
set DCB parameters using lldptool. No need of running lldpad service on the VM.

Note: The driver supports only one priority for RoCE traffic. Please use same
DCB priority for both RoCE-v1 and RoCE-v2 traffic.

Following sequence of commands are recommended to configure
the local adapter to set DCB parameters, in case switches are not capable
of DCB negotiations.

# Load L2 driver and make sure port and Link are  UP
# service lldpad start
# lldptool -L -i p6p1 adminStatus=rxtx
For RoCE-V1 protocol with Priority-5
# lldptool -T -i p6p1 -V APP app=5,1,35093
For RoCE-V2 protocol with Priority-5
# lldptool -T -i p6p1 -V APP app=5,3,4791
# lldptool -T -i p6p1 -V ETS-CFG tsa="0:ets,1:ets,2:strict,3:strict,4:strict,5:strict,6:strict,7:strict \
    up2tc=0:1,1:1,2:1,3:1,4:1,5:0,6:1,7:1  tcbw=90,10,0,0,0,0,0,0
# lldptool -T -i p6p1 -V PFC enabled=5
# service lldpad restart
# sleep 180
# load RoCE driver

Note: Please refer man pages of lldptool, lldptool-app,
lldptool-ets, lldptool-pfc, etc. for more details


VF Resource Distribution
==========================

If SR-IOV is supported on the adapter, QPs, SRQs, CQs and MRs are distributed
across VF by the bnxt_re driver. Driver allocates 64K of QPs, SRQs and CQs
for the PF pool. It creates 256K MRs for the PF pool. If SRIOV is enabled on
the adapter, and if VFs are created (active VFs), 32K of each of these resources
are reserved for PF and remaining is divided equally amongst active number of VFs.

For eg: Active number of VFs can be obtained from the following command.
	$cat /sys/class/net/p6p1/device/sriov_numvfs

If sriov_numvfs is 2, each VF can create resources (QP, SRQ and CQ)
upto 16K (32K divided across 2 VFs). MRs per VF would be 112K ((256K - 32K) divided
across 2 VFs)

Note: Since PF is in privileged mode, it is allowed to use the
entire PF pool resources. But VFs are restricted to create max configured
by the above calculation. User must ensure that total resources created by
PF and its VFs shall be less than Max configured (64K for QPs/SRQs/CQs and 256K for MRs).

Use following command to get the active resource count.
$cat /sys/kernel/debug/bnxt_re/info
