# appkmsg 中文文档
Copyright © 2023 Liao Jian All rights reserved.
## 使用前的准备工作
### 1.安装基本开发环境
```
sudo apt install build-essential expect
```
### 2.编译装载驱动程序
```
cd appkmsg/
make
sudo insmod appkmsg.ko
```
### * 支持的内核版本
|类型|内核版本|
|:------:|:-----:|
|最新适配|Linux-6.4|
|最低兼容|Linux-4.1|
### * 需要开启以下内核配置选项
```
CONFIG_ZSMALLOC
```
## 使用说明
### 1.相关接口描述
|接口名称|读写权限|功能描述|
|:------|:-----:|:-----:|
|/dev/appkmsg|R/W|记录I/O数据的虚拟设备|
|/proc/appkmsg/all|R|详细统计信息|
|/proc/appkmsg/latest|R|指向最新记录项的链接|
|/proc/appkmsg/*|R|所有历史记录项|
|/sys/appkmsg/destroy|W|删除指定记录项|
|/sys/appkmsg/destroy_all|W|清空所有记录项|
|/sys/appkmsg/compress_algo|R/W|查询/设置数据压缩算法|
|/sys/appkmsg/version|R|显示当前版本信息|
### A. 只记录输出部分
```
app > /dev/appkmsg
```
### B. 只记录输入部分
```
unbuffer -p app < /dev/appkmsg
```
### C. 同时记录输入输出
```
unbuffer -p app < /dev/appkmsg > /dev/appkmsg
```
### D. 查看所有记录的详细统计信息
```
cat /proc/appkmsg/all
```
### E. 查看最新生成的记录
```
cat /proc/appkmsg/latest
```
### F. 删除指定记录 (PID可通过步骤D获取)
```
echo PID > /sys/appkmsg/destroy
```
### G. 清空所有记录 (写入任意字符亦可)
```
echo 0 > /sys/appkmsg/destroy_all
```
### H. 查看当前选择的数据压缩算法
```
cat /sys/appkmsg/compress_algo
```
### I. 设置数据压缩算法 (以zstd为例)
```
echo zstd > /sys/appkmsg/compress_algo
```
### J. 查看当前驱动版本信息
```
cat /sys/appkmsg/version
```
# FAQ
#### Q: 操作提示: /dev/appkmsg: Permission denied?
#### A: sudo -i
---
#### Q: 使用前有什么注意事项吗?
#### A: 如果你对稳定性持怀疑态度，优先在虚拟机测试审慎评估。
---
#### Q: 使用前有什么建议吗?
#### A: 如果决定在实体机运行，建议在安装并启用kdump的前提下使用本驱动，以便崩溃时自动重启和BUG定位。
---
#### Q: unbuffer命令是什么，为什么记录输入时需要它?
#### A: 它是expect软件包的一部分，用来抵消命令行的缓冲特性，只是一个临时方案。
---
#### Q: 它记录的数据是完整的吗？
#### A: 最简单的办法是，你可以随便丢一个文件到/dev/appkmsg，然后对两者做校验。
```
例如:
ls -al / > /tmp/test
cat /tmp/test > /dev/appkmsg
sha256sum -b /tmp/test
sha256sum -b /proc/appkmsg/latest
cmp -b /tmp/test /proc/appkmsg/latest
```
---
#### Q: 既然通过PID删除记录，那么旧的PID会不会被内核重新分配给新的进程使用而造成冲突?
#### A: 只有在删除记录或卸载模块时才会释放该PID并真正返还内核。
---
#### Q: 下个版本什么时候更新?
#### A: 待定。
