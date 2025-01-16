#!/bin/bash

#export ARCH=arm


# platform C
#export CROSS_COMPILE=/opt/platform-c/toolchain/bin/arm-none-linux-gnueabi-
#export KERNELDIR=/opt/platform-c/kernel/5300


# platform M-1G
#export CROSS_COMPILE=/opt/platform-m/mano_platform/tools/host/usr/bin/arm-linux-gnueabihf-
#export KERNELDIR=/opt/platform-m/mano_platform/kernel/linux_kernel

# platform M-2G
#export CROSS_COMPILE=/opt/platform-m/mano_platform-2G/tools/host/usr/bin/arm-linux-gnueabihf-
#export KERNELDIR=/opt/platform-m/mano_platform-2G/kernel/linux_kernel




###################################################
########## maipu############
###################################################

#export ARCH=arm64

#export CROSS_COMPILE=/opt/maipu/toolchain/aarch64-gnu-4.8/bin/aarch64-linux-gnu-
#export KERNELDIR=/opt/maipu/kernel/kernel-3.14

#export CROSS_COMPILE=/opt/maipu/toolchain/aarch64-gnu-4.8/bin/aarch64-linux-gnu-
#export KERNELDIR=/opt/maipu/kernel_switch/kernel-3.14

###################################################
########## maipu xinsihe############
###################################################

#export ARCH=arm64

#export CROSS_COMPILE=/opt/maipuxinsihe/gcc-linaro-6.2.1-2016.11-x86_64_aarch64-linux-gnu/bin/aarch64-linux-gnu-
#export KERNELDIR=/opt/maipuxinsihe/klinux-maipu-v3



###################################################
########## shiliandongli ############
###################################################

#export ARCH=arm

#export CROSS_COMPILE=/opt/shiliandongli/arm-hisiv400-linux/arm-hisiv400-linux/bin/arm-hisiv400-linux-gnueabi-
#export KERNELDIR=/opt/shiliandongli/linux-3.10.y



###################################################
########## bentu_saomiaoyi ############
###################################################

export ARCH=csky

export CROSS_COMPILE=/opt/bentu_saomiaoyi/csky_compilers/Linuxx86_32/bin/csky-abiv2-linux-
export KERNELDIR=/opt/bentu_saomiaoyi/2700_kernel/kernel/work/BS
