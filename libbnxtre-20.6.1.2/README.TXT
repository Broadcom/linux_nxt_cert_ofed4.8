			Installation Notes
		Broadcom Linux User Space RoCE Driver
             		Version 20.6.1.2
			    04/10/2017

		 	     Broadcom
			5300 California Avenue
		      Irvine, California  92617

		Copyright (C) 2016-2017 Broadcom
			All Rights Reserved


Table of Contents
=================

  Introduction
  Limitations
  Driver Dependencies
  Packaging
  Building Driver
  Driver Settings
  Driver Defaults
  Unloading and Removing Driver
  Setup Verification

Introduction
============

This file describes the libbnxtre Linux RoCE user space driver for the
Broadcom NetXtreme-C and NetXtreme-E BCM573xx and BCM574xx 10/20/25/40
/50 Gbps Ethernet Network Controllers.

This is the first release of linux user space RoCE driver. The source
code is maintained in int_nxt branch of the NetXtreme project GIT
repository. Following is the path to the source-code in the int_nxt
branch
...main/Cumulus/drivers/linux/rocelib

The next few sections describe on packaging, compiling, and installation.


Limitations
===========

The current engineering release has been tested only on RHEL-7.2 (3.10 kernel)
distribution with inbox infiniBand stack.


Driver Dependencies
===================

The user space RoCE driver depends on following kernel modules:

1. Ethernet driver for NetXtreme devices (bnxt_en.ko)
2. RoCE driver for NetXtreme devices (bnxt_re.ko)
3. uVerbs device interface, it is an IB-stack component (ib_uverbs.ko)
4. User space RDMA-CM, it is an IB-stack component (rdma_ucm.ko)


Packaging
=========

To install or replace an older previously installed user-space driver, follow
the instructions below:

The user-space driver code is released in the form of a tar.gz file


Building Driver
===============

The following are general guidelines to build and install the driver.

1. Use following command to check if libibverbs-devel is installed on
   the target host:

   rpm -qa| grep libibverbs-devel

   If the rpm is not installed, then install this rpm from the OS distribution
   disk.

2. Create a directory and extract the files:

   tar xvzf libbnxtre-<version>.tar.gz

3. Build and install:

   cd libbnxtre-<version>
   ./configure
   make
   make install


Driver Settings
===============

1. Use following command to copy bnxtre.driver file to /etc/libibverbs.d
   directory

   cp bnxtre.driver /etc/libibverbs.d

2. Edit /etc/ld.so.conf file and append following line to it

   /usr/local/lib

   save and quit the editor and run following command

   ldconfig -v


Driver Defaults
===============

Install Path: /usr/local/lib


Unloading and Removing Driver
=============================


Setup Verification
==================

This section list the basic commands to verify the user space RoCE driver
configuration on the target host

List RoCE devices
-----------------

# ibv_devices
    device                 node GUID
    ------              ----------------
    bnxt_re1            001018fffead1c91
    bnxt_re0            001018fffead1c90


# ibv_devinfo

hca_id: bnxt_re1
        transport:                      InfiniBand (0)
        node_guid:                      0010:18ff:fead:1c91
        sys_image_guid:                 0010:18ff:fead:1c91
        vendor_id:                      0x14e4
        vendor_part_id:                 5847
        hw_ver:                         0x1405
        phys_port_cnt:                  1
                port:   1
                        state:                  PORT_ACTIVE (4)
                        max_mtu:                4096 (5)
                        active_mtu:             1024 (3)
                        sm_lid:                 0
                        port_lid:               0
                        port_lmc:               0x00
                        link_layer:             Ethernet

hca_id: bnxt_re0
        transport:                      InfiniBand (0)
        node_guid:                      0010:18ff:fead:1c90
        sys_image_guid:                 0010:18ff:fead:1c90
        vendor_id:                      0x14e4
        vendor_part_id:                 5847
        hw_ver:                         0x1405
        phys_port_cnt:                  1
                port:   1
                        state:                  PORT_ACTIVE (4)
                        max_mtu:                4096 (5)
                        active_mtu:             1024 (3)
                        sm_lid:                 0
                        port_lid:               0
                        port_lmc:               0x00
                        link_layer:             Ethernet

Traffic Test
------------

Server: rping -s -d -v -a <ip of server bnxt interface>
For example
rping -s -a 192.172.1.1 -Vv -C 3
server ping data: rdma-ping-0: ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqr
server ping data: rdma-ping-1: BCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrs
server ping data: rdma-ping-2: CDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrst

Client: rping -c -d -v -a <ip of server bnxt interface>
For example
rping -c -a 192.172.1.1 -C 3 -vV
ping data: rdma-ping-0: ABCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqr
ping data: rdma-ping-1: BCDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrs
ping data: rdma-ping-2: CDEFGHIJKLMNOPQRSTUVWXYZ[\]^_`abcdefghijklmnopqrst
