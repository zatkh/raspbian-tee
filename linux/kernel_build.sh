#!/bin/bash


#git clone https://github.com/raspberrypi/tools ~/tools

# for 32 bit
#echo PATH=\$PATH:~/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian/bin >> ~/.bashrc
#source ~/.bashrc

#for 64 bit
#echo PATH=\$PATH:~/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/bin >> ~/.bashrc
#source ~/.bashrc

#echo PATH=\$PATH:~/tools/arm-bcm2708/gcc-linaro-arm-linux-gnueabihf-raspbian-x64/bin >> ~/.bashrc
source ~/.bashrc

#git clone --depth=1 https://github.com/raspberrypi/linux

#sudo apt-get install git bison flex libssl-dev

#For Pi 2, Pi 3, Pi 3+, or Compute Module 3:

#cd linux
KERNEL=kernel7
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- bcm2709_defconfig -j8
make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- zImage modules dtbs -j8

mkdir -p mnt
mkdir -p mnt/fat32
mkdir -p mnt/ext4

sudo make ARCH=arm CROSS_COMPILE=arm-linux-gnueabihf- INSTALL_MOD_PATH=mnt/ext4 modules_install

#get the raspbian image
#wget http://downloads.raspberrypi.org/raspbian/images/raspbian-2015-11-24/2015-11-21-raspbian-jessie.zip
#unzip 2015-11-21-raspbian-jessie.zip