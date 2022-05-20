sudo apt install git bc bison flex libssl-dev make -y
git clone --depth=1 https://github.com/raspberrypi/linux
cd linux
KERNEL=kernel8
make bcm2711_defconfig