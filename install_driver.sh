#!/bin/sh

# save current directory
basedir=$(pwd)
echo $basedir

if [ -z "$1" ]
then
    echo "ofed dir path not provided"
    echo "usage: sh install.sh /root/OFED-4.8/"
    exit 1
else
    if [ -d $1 ]
    then
        ofeddir=$1
        echo "ofed_dir = $ofeddir"
    else
        echo "OFED directory path is not correct"
        exit 1
    fi       
fi

#check if ofed is installed
ofed_ver=`ofed_info -s | grep "OFED" | cut -d':' -f1`
if [ -n $ofed_ver ]
then
    echo "ofed_version = $ofed_ver "
else
    echo "OFED is not installed"
    exit 1
fi


#Patch and creating softlink
echo "creating softlinks for infiniband/driver.h"
cd $ofeddir
rpm -ivh --define "_topdir $PWD" SRPMS/rdma-core-13-1.src.rpm
cd SOURCES
tar -zxf rdma-core-13.tgz
cd rdma-core-13
./build.sh
cd build
tmpdir=$(pwd)

if [ -e "/usr/include/infiniband/util" ]; then
  unlink "/usr/include/infiniband/util"
fi
ln -s $tmpdir/include/util /usr/include/infiniband/util 

if [ -e "/usr/include/infiniband/util" ]; then
  unlink "/usr/include/infiniband/driver.h"
fi
ln -s $tmpdir/include/infiniband/driver.h /usr/include/infiniband/driver.h

cd $basedir

# sanity function to check return value
error_check()
{
   if [ $? -ne 0 ]
   then
     echo ">---- $1 Failed ----<"
     exit 1
   fi
}

# remove roce and l2 driver
echo "<---- remove inbox drivers ---->"
lsmod | grep -q bnxt_re && rmmod bnxt_re
lsmod | grep -q bnxt_en && rmmod bnxt_en
sleep 1


# install new driver
echo "<---- install l2 and roce driver ---->"
cd $(ls | grep netxtreme-bnxt_en)
make clean
echo "OFED Version = $ofed_ver"
export OFED_VERSION=$ofed_ver
make install
error_check driver-compilation


# roce lib install
echo "<---- install roce lib ---->"
cd $basedir
echo $(pwd)
cd $(ls | grep libbnxtre)
echo $(pwd)
./configure
make
make install
error_check library-compilation
cp -f bnxtre.driver /etc/libibverbs.d
grep -q -F '/usr/local/lib' /etc/ld.so.conf || echo '/usr/local/lib' >> /etc/ld.so.conf
ldconfig -v



echo "<---- load drivers ---->"
modprobe bnxt_en
error_check l2_driver-load
sleep 1
modprobe bnxt_re
error_check roce_driver-load
sleep 1
if ibv_devinfo | grep -q bnxt_re0 ; then
echo "<---- roce interfaces are up ---->" 
else
echo "<---- error::roce interfaces are not up ---->"
exit 1
fi

echo "<---- successfully installed and loaded the driver!! ---->"



