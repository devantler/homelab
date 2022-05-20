# Build Raspberry Pi OS kernel with Ceph support

<https://gist.github.com/devantler/7dfcf13f12cb68b65eaa0e6f93dc2b19>

<https://github.com/raspberrypi/linux/issues/4375>

## Configs to set

- `CONFIG_BLK_DEV_DRBD=m`
- `CONFIG_BLK_DEV_RBD=m`
- `CONFIG_BLK_DEV_NBD=m`
- `CONFIG_ARM64_VA_BITS_48=y`