import os
import os.path
import re


USER_LOCAL_BIN = '/usr/local/bin'
USER_BIN = '/usr/bin'

def get_qemu_cmd(cmd, version=None):
    if version is not None:
        return _get_qemu_cmd_version(cmd, version)
    else:
        return _get_qemu_cmd(cmd)


def _get_qemu_cmd_version(cmd, version):
    path = os.path.join('/usr/local/qemu-%s/bin' % version, cmd)
    if os.path.exists(path):
        return path
    cmd = cmd + '_' + version
    path = os.path.join(USER_LOCAL_BIN, cmd)
    if os.path.exists(path):
        return path
    path = os.path.join(USER_BIN, cmd)
    if os.path.exists(path):
        return path
    return None


def get_cmd_version(cmd):
    pattern = re.compile(r'_(?P<ver>\d+(\.\d+)+)$')
    m = pattern.search(cmd)
    if m is not None:
        ver = m.group('ver')
        return map(int, ver.split('.'))
    return None


def _get_qemu_version(cmd):
    pattern = re.compile(r'qemu-(?P<ver>\d+(\.\d+)+)$')
    m = pattern.search(cmd)
    if m is not None:
        ver = m.group('ver')
        return map(int, ver.split('.'))
    return None


def _get_qemu_cmd(cmd):
    qemus = []
    for f in os.listdir('/usr/local'):
        if f.startswith('qemu-'):
            qemus.append(f)
    if len(qemus) > 0:
        qemus = sorted(qemus, key=_get_qemu_version)
        path = '/usr/local/%s/bin/%s' % (qemus[-1], cmd)
        if os.path.exists(path):
            return path
    cmds = []
    for f in os.listdir(USER_LOCAL_BIN):
        if f.startswith(cmd):
            cmds.append(f)
    if len(cmds) > 0:
        cmds = sorted(cmds, key=get_cmd_version)
        return os.path.join(USER_LOCAL_BIN, cmds[-1])
    path = os.path.join(USER_BIN, cmd)
    if os.path.exists(path):
        return path
    return None


def get_qemu_img():
    return get_qemu_cmd('qemu-img')

def get_qemu_nbd():
    return get_qemu_cmd('qemu-nbd')

def get_qemu(version=None):
    return get_qemu_cmd('qemu-system-x86_64', version)


if __name__ == '__main__':
    print(get_qemu_nbd())
    print(get_qemu_img())
    print(get_qemu())
    print(get_qemu(version='1.1.2'))
    print(get_qemu(version='2.7.1'))
