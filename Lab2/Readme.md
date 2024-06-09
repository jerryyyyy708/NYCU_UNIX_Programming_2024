# 312551086 Lab2
## Prepare rootfs for QEMU
Place all file required (.ko) into ideal path, then pack whole dist into rootfs.cpio.bz2. 
```
find . -print0 | cpio --null -ov --format=newc > rootfs.cpio
bzip2 rootfs.cpio
mv rootfs.cpio.bz2 ../
```

## Kernel Module Commands
Install Module
```
insmod [module]
```
Remove Module
```
rmmod [module]
```
Check Loaded Module
```
lsmod
```