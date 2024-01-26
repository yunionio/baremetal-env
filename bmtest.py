#!/usr/bin/env python3

import sys
import stat
import os
import os.path
import uuid

sys.path.insert(0, os.path.dirname(os.path.dirname(__file__)))

from common import qemuimg
from common import qemutils
from common import fileutils
from common import regutils


def mark_exec(path):
    os.chmod(path, stat.S_IRUSR | stat.S_IWUSR | stat.S_IXUSR)


def save_file_exec(path, content):
    fileutils.file_put_contents(path, content)
    mark_exec(path)


def get_of_rules():
    return [
        (9500, 'table=0 in_port=$PORT udp tp_src=68 tp_dst=67', 'local'),
        (8000, 'table=0 in_port=$PORT', 'resubmit(,1)')
    ]


def add_flow(r):
    s = ''
    s += "ovs-ofctl add-flow $SWITCH \"%s" % r[1]
    s += " priority=%d" % r[0]
    s += " actions=%s\"\n" % r[2]
    return s


def del_flow(r):
    s = "ovs-ofctl del-flows $SWITCH \"%s\"\n" % r[1]
    return s


def ifup_scripts(bridge, ifname):
    cmd = "#!/bin/bash\n\n"
    cmd += "SWITCH=%s\n" % (bridge)
    cmd += "IF=%s\n" % (ifname)
    cmd += "ifconfig $IF 0.0.0.0 up\n"
    cmd += "ovs-vsctl add-port $SWITCH $IF\n"
    # no need to setup flow
    # cmd += "PORT=$(ovs-ofctl show $SWITCH | grep $IF | cut -d '(' -f 1 | awk '{print $1}')\n"
    # for r in get_of_rules():
    #     cmd += add_flow(r)
    return cmd


def ifdown_scripts(bridge, ifname):
    cmd = "#!/bin/bash\n\n"
    cmd += "SWITCH=%s\n" % (bridge)
    cmd += "IF=%s\n" % (ifname)
    # no need to setup flow
    # cmd += "PORT=$(ovs-ofctl show $SWITCH | grep $IF | cut -d '(' -f 1 | awk '{print $1}')\n"
    # for r in get_of_rules():
    #     cmd += del_flow(r)
    cmd += "ifconfig $IF 0.0.0.0 down\n"
    cmd += "ovs-vsctl -- --if-exists del-port $SWITCH $IF\n"
    return cmd


def lan_conf(home, addr, infname, bmc_port, ser_port):
    cont = ""
    cont += "name \"ipmisim1\"\n"
    cont += "\n"
    cont += "set_working_mc 0x20\n"
    cont += "  startlan 1\n"
    cont += "    addr %s 623\n" % (addr)
    cont += "    priv_limit admin\n"
    cont += "    allowed_auths_callback none md2 md5 straight\n"
    cont += "    allowed_auths_user none md2 md5 straight\n"
    cont += "    allowed_auths_operator none md2 md5 straight\n"
    cont += "    allowed_auths_admin none md2 md5 straight\n"
    cont += "    guid %s\n" % (uuid.uuid4().hex)
    lanctl_path = os.path.join(home, "ipmi_sim_lancontrol")
    cont += "    lan_config_program \"%s %s\"\n" % (lanctl_path, infname)
    cont += "  endlan\n\n"
    chassis_ctl_path = os.path.join(home, "ipmi_sim_chassiscontrol")
    cont += "  chassis_control \"%s 0x20\"\n" % (chassis_ctl_path)
    cont += "  serial 15 localhost %d codec VM\n" % (bmc_port)
    start_path = os.path.join(home, "start")
    cont += "  startcmd \"%s\"\n" % (start_path)
    cont += "  sol \"telnet:localhost:%d\" 115200\n" % (ser_port)
    cont += "  startnow true\n"
    cont += "  user 1 true \"\" \"test\" user 10 none md2 md5 straight\n"
    cont += "  user 2 true \"root\" \"test\" admin 10 none md2 md5 straight\n"
    cont += "\n"
    cont += "set_working_mc 0x30\n"
    cont += "  startnow false\n"
    return cont


def _copy_exec(src, dst, home):
    src = os.path.join(os.path.dirname(__file__), "bmtest/%s" % src)
    dst =  os.path.join(home, dst)
    from shutil import copyfile
    copyfile(src, dst)
    mark_exec(dst)


def run(home, bridge, addr, mask, cpu, mem, disk_cnt, disk_size_mb, idx=0):
    nic_cnt = 2
    lan_conf_path = os.path.join(home, "lan.conf")
    bmname = "bmtest%d" % (idx)
    infname = "vbmc%d0" % (idx)
    infname1 = "vbmc%d1" % (idx)
    bmc_port = 29002 + idx
    ser_port = 39002 + idx

    _copy_exec('dhtest/dhtest', 'dhtest', home)

    lanconf = lan_conf(home, addr, infname, bmc_port, ser_port)
    fileutils.file_put_contents(lan_conf_path, lanconf)
    sim_cmd_file = os.path.join(home, 'ipmisim1.emu')
    for f in ['functions', 'ipmisim1.emu', 'ipmi_sim_chassiscontrol', 'ipmi_sim_lancontrol']:
        _copy_exec(f, f, home)
    stat_dir = os.path.join(home, "ipmi_stat")
    ifn = uuid.uuid4().hex[:8]
    mac = "00:22:%s:%s:%s:%s" % (ifn[:2], ifn[2:4], ifn[4:6], ifn[6:])

    cmd = "mkdir -p %s\n" % stat_dir
    cmd += "ip link add %s type veth peer name %s\n" % (infname, infname1)
    cmd += "ifconfig %s hw ether %s\n" % (infname, mac)
    cmd += "ifconfig %s %s netmask %s up\n" % (infname, addr, mask)
    cmd += "ifconfig %s 0 up\n" % (infname1)
    cmd += "ovs-vsctl add-port %s %s\n" % (bridge, infname1)
    cmd += "/opt/openipmi/bin/ipmi_sim -c %s -f %s -s %s\n" % (lan_conf_path, sim_cmd_file, stat_dir)
    cmd += "ovs-vsctl del-port %s %s\n" % (bridge, infname1)
    cmd += "ifconfig %s 0 down\n" % (infname1)
    cmd += "ifconfig %s 0 down\n" % (infname)
    cmd += "ip link delete %s\n" % (infname)
    bm_run_file = os.path.join(home, "bm_run")
    save_file_exec(bm_run_file, cmd)

    cmd = "#!/bin/bash\n\n"
    cmd += ". %s\n" % os.path.join(home, "functions")
    cmd += "requires_root\n"
    cmd += "screen_it %s %s\n" % (bmname, bm_run_file)
    bm_start_file = os.path.join(home, "bm_start")
    save_file_exec(bm_start_file, cmd)

    cmd = ""
    cmd += "ovs-vsctl del-port %s %s\n" % (bridge, infname1)
    cmd += "ifconfig %s 0 down\n" % (infname1)
    cmd += "ifconfig %s 0 down\n" % (infname)
    cmd += "ip link delete %s\n" % (infname)
    bm_cleanup_file = os.path.join(home, "bm_cleanup")
    save_file_exec(bm_cleanup_file, cmd)

    cmd = "#!/bin/bash\n\n"
    cmd += ". %s\n" % os.path.join(home, "functions")
    cmd += "requires_root\n"
    cmd += "stop_screen %s\n" % (bmname)
    cmd += "%s\n" % (bm_cleanup_file)
    bm_stop_file = os.path.join(home, "bm_stop")
    save_file_exec(bm_stop_file, cmd)

    cmd = qemutils.get_qemu()
    cmd += " -enable-kvm -cpu host -rtc base=utc,clock=host,driftfix=none -daemonize -nodefaults -nodefconfig -no-kvm-pit-reinjection"
    cmd += " -global kvm-pit.lost_tick_policy=discard -machine pc,accel=kvm -k en-us -smp %d" % cpu
    cmd += " -name bmtest -m %d" % mem
    cmd += " -boot order=ncd -usb -device usb-kbd -device usb-tablet -vga std"
    cmd += " -vnc :%d" % (200 + idx)
    cmd += " -device virtio-scsi-pci,id=scsi"
    # cmd += " -device megasas,id=scsi"
    # cmd += " -device megasas-gen2,id=scsi"
    for i in range(disk_cnt):
        disk_path = os.path.join(home, "disk%d" % i)
        img = qemuimg.QemuImage(disk_path)
        img.create_qcow2(disk_size_mb)
        cmd += " -drive file=%s,if=none,id=drive_%d,cache=none,aio=native" % (disk_path, i)
        cmd += " -device scsi-hd,drive=drive_%d,bus=scsi.0" % (i)
    for i in range(nic_cnt):    
        ifn = uuid.uuid4().hex[:8]
        ifname = "bm-%s" % ifn
        upscript = os.path.join(home, "if-up-%d.sh" % i)
        save_file_exec(upscript, ifup_scripts(bridge, ifname))
        downscript = os.path.join(home, "if-down-%d.sh" % i)
        save_file_exec(downscript, ifdown_scripts(bridge, ifname))
        mac = "00:22:%s:%s:%s:%s" % (ifn[:2], ifn[2:4], ifn[4:6], ifn[6:])
        cmd += " -netdev type=tap,id=vnet%d,ifname=%s,vhost=on,vhostforce=off,script=%s,downscript=%s" % (i, ifname, upscript, downscript)
        cmd += " -device virtio-net-pci,netdev=vnet%d,mac=%s,addr=0x%x" % (i, mac, 0xf + i)
    pidfile = os.path.join(home, "pid")
    cmd += " -pidfile %s" % pidfile
    cmd += " -chardev socket,id=ipmi0,host=localhost,port=%d,reconnect=10" % (bmc_port)
    cmd += " -device ipmi-bmc-extern,id=bmc0,chardev=ipmi0"
    cmd += " -device isa-ipmi-bt,bmc=bmc0"
    cmd += " -serial mon:telnet:localhost:%d,server,telnet,nowait" % (ser_port)
    start_path = os.path.join(home, "start")
    save_file_exec(start_path, cmd)
    stop_path = os.path.join(home, "stop")
    cmd = "#!/bin/bash\n\n"
    cmd += "PID=$(cat %s)\n" % pidfile
    cmd += "kill $PID\n"
    cmd += "rm -f %s\n" % pidfile
    save_file_exec(stop_path, cmd)


if __name__ == '__main__':
    if len(sys.argv) < 5:
        print("Usage: %s <dir> <bridge> <ipmi_addr> <netmask> <index>" % (sys.argv[0]))
        sys.exit(-1)
    if len(sys.argv) > 5:
        index = int(sys.argv[5])
    else:
        index = 0
    if not regutils.match_ip4addr(sys.argv[3]):
        print("illegal ipmi_addr", sys.argv[3])
        sys.exit(-1)
    if not regutils.match_ip4addr(sys.argv[4]):
        print("illegal network mask", sys.argv[4])
        sys.exit(-1)
    run(sys.argv[1], sys.argv[2], sys.argv[3], sys.argv[4], 2, 2560, 2, 100*1000, idx=index)
