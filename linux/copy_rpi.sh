
#!/bin/bash

# sudo /sbin/fdisk -lu 2015-11-21-raspbian-jessie.img 
#Check start of W95 FAT32 (LBA) partition. It is 8192. Sector size is 512. So calculate offset in bytes 8192 * 512 = 4194304.
#Disk 2015-11-21-raspbian-jessie.img: 3.7 GiB, 3934257152 bytes, 7684096 sectors
#Units: sectors of 1 * 512 = 512 bytes
#Sector size (logical/physical): 512 bytes / 512 bytes
#I/O size (minimum/optimal): 512 bytes / 512 bytes
#Disklabel type: dos
#Disk identifier: 0xea0e7380
#Device                          Boot  Start     End Sectors  Size Id Type
#2015-11-21-raspbian-jessie.img1        8192  131071  122880   60M  c W95 FAT32 (LBA)
#2015-11-21-raspbian-jessie.img2      131072 7684095 7553024  3.6G 83 Linux

#wget http://downloads.raspberrypi.org/raspbian/images/raspbian-2015-11-24/2015-11-21-raspbian-jessie.zip
#unzip 2015-11-21-raspbian-jessie.zippi

IMG= $1 #2015-11-21-raspbian-jessie.img
BOOT=/home/zt/boot/
FS=/home/zt/rootfs/
LINUX_BOOT_DIR=$PWD/arch/arm/boot
LINUX_MODULES_DIR=$PWD/../out/rootfs/lib/modules/4.19.42-v7/



#sudo mount -o loop,offset=4194304 $IMG $BOOT
#sudo mount -o loop,offset=67108864 $IMG $FS
#sudo mount /dev/sdb6 mnt/fat32
#sudo mount /dev/sdb7 mnt/ext4

echo "copy .dtbs"
sudo cp -R $LINUX_BOOT_DIR/dts/*.dtb $BOOT
sudo cp -R  $LINUX_BOOT_DIR/dts/*.dtb $BOOT
sudo cp -R $LINUX_BOOT_DIR/dts/overlays/*.dtb* $BOOT/overlays/

echo "copy modules"
sudo cp -R $LINUX_MODULES_DIR $FS/modules
echo "copy kernel"
sudo cp $LINUX_BOOT_DIR/zImage $BOOT/kernely.img

#mkdir $COPY_DIR
#cp $BOOT/kernel7.img $COPY_DIR
#cp $BOOT/bcm2709-rpi-2-b.dtb $COPY_DIR
