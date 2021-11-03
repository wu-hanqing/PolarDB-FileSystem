Curve for pfs
===

直接使用curvebs sdk给pfsd提供I/O驱动，可以有更好的性能，目前驱动程序已经完成，分支为curvebs_sdk_devio，
经过测试，工作良好。

使用时需要注意的点：
===

- 传给函数pfsd_mount()的curve 卷名不要包含‘cbd:’ 前缀。

  因为测试过程中发现fio命令
行包含冒号就会工作不正常, 所以干脆传给pfsd_mount的pbd name不包含cbd:前缀。

- ‘//’ 分隔符也需要替换成‘@@’

  因为字符‘/’会被 pfs解析为目录分隔符，而实际上这
个路径不在pfs的解析范围，而是属于curve后台系统解析范围。所以为避免把pfs搞混，
需要替换‘/’为‘@’。例如需要mount卷名为cbd:pool//pfs_test_的卷以读写方式打开，可以使用的调用方式：
ret = pfsd_mount(“curve”, “pool@@pfs_test_”, 1, PFS_RDWR);

- 卷名不能超过64个字符

  pfsd内部规定了pbd name不能超过64个字符，否则需要修改宏，并重新编译。

- 启动pfsdaemon
 
  启动pfsdaemon的命令行参数也需要变换，例如
/usr/local/polarstore/pfsd/bin/start_pfsd.sh -p pool@@pfs_test_
