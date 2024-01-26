README
=========

1. OpenIPMI 安装至 /opt/openipmi

2. 编译bhtest

   cd tools/bmtest/bhtest
   make

3. 创建Baremetal实例

./tools/bmtest.py <bm\_dir> <bridge> <BMC\_IP> <BMC\_IP\_MASK> <INDEX>

4. 启动Baremetal

cd <bm\_dir>
./bm\_start > /dev/null 2>&1 &

配置正常的情况下，平台会发现注册上来一台Baremetal，之后可以对该Baremetal进行相应的操作。

5. 如何判断Baremetal哪个串口是控制台


    # cat /proc/tty/driver/serial
    serinfo:1.0 driver revision:
    0: uart:16550A port:000003F8 irq:4 tx:239 rx:8 RTS|CTS|DTR|DSR|CD
    1: uart:unknown port:000002F8 irq:3
    2: uart:unknown port:000003E8 irq:4
    3: uart:unknown port:000002E8 irq:3

有RTS/CTS/DTR等字样的串口是控制台的串口，这里为ttyS0
