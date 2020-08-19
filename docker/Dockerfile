FROM ubuntu:20.04

RUN sed -i '/deb-src/s/^# //' /etc/apt/sources.list && \
	dpkg --add-architecture i386 && \
	apt-get update && \
	apt-get install -y build-essential git sudo bison flex libssl-dev bc kmod wget vim u-boot-tools

# Download optee toolchains
RUN mkdir -p /toolchains && \
	cd /toolchains && \
	wget https://developer.arm.com/-/media/Files/downloads/gnu-a/8.3-2019.03/binrel/gcc-arm-8.3-2019.03-x86_64-arm-linux-gnueabihf.tar.xz && \
	wget https://developer.arm.com/-/media/Files/downloads/gnu-a/8.3-2019.03/binrel/gcc-arm-8.3-2019.03-x86_64-aarch64-linux-gnu.tar.xz

RUN cd /toolchains && \
	mkdir aarch32 && \
	umask 022 && \
	tar xf *-arm-linux-gnueabihf.tar.xz -C aarch32 --strip-components=1

RUN cd /toolchains && \
	mkdir aarch64 && \
	umask 022 && \
	tar xf *-aarch64-linux-gnu.tar.xz -C aarch64 --strip-components=1

ENV CROSS_COMPILE /toolchains/aarch32/bin/arm-linux-gnueabihf-
ENV CROSS_COMPILE_AARCH64 /toolchains/aarch64/bin/aarch64-linux-gnu-

# Additional optee build deps
RUN DEBIAN_FRONTEND="noninteractive" apt-get -y install tzdata
RUN apt-get install -y android-tools-adb android-tools-fastboot \
	autoconf automake bc bison build-essential ccache cscope curl device-tree-compiler \
        expect flex ftp-upload gdisk iasl libattr1-dev libc6:i386 libcap-dev \
        libfdt-dev libftdi-dev libglib2.0-dev libhidapi-dev libncurses5-dev \
        libpixman-1-dev libssl-dev libstdc++6:i386 libtool libz1:i386 make \
        mtools netcat python-crypto python3-crypto python-pyelftools \
        python3-pycryptodome python3-pyelftools \
        rsync unzip uuid-dev xdg-utils xterm xz-utils zlib1g-dev python
