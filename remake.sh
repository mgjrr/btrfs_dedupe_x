umount /home/a/data
rmmod btrfs
make modules SUBDIRS=fs/btrfs
insmod /home/a/ksrc/linux-dedupe_latest/fs/btrfs/btrfs.ko
mount /dev/sdc /home/a/data
