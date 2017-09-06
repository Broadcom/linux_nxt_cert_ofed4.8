Prerequisites
-------------
Install OFED 4.8 with all packages.


Driver versions to be installed 
-------------------------------
L2 driver: 1.7.23
RoCE driver: 20.6.1.3
RoCE library: 20.6.1.2


Installation Steps
------------------
1. Go to basedir containing the install scripts, driver and library source code.
2. Run install_driver.sh script and provide the OFED-4.8 directory path as first parameter:
    ./install_driver.sh /root/OFED-4.8/
3. The script will install the drivers and bring up the RoCE interfaces.


Notes
-----
1. The installation is only verified to work with OFED-4.8 release and SL 7.3 at this time.


