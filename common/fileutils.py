import logging
import os
import os.path
import sys
import mmap
import re
import hashlib

from subprocess import CalledProcessError

from . import procutils


def is_dir_writable(directory):
    if not os.path.exists(directory):
        return False
    try:
        tmp_prefix = "write_tester"
        count = 0
        filename = os.path.join(directory, tmp_prefix)
        while(os.path.exists(filename)):
            filename = "{}.{}".format(os.path.join(directory, tmp_prefix), count)
            count = count + 1
        f = open(filename, "w")
        f.close()
        os.remove(filename)
        return True
    except Exception as e:
        logging.error(e)
        return False


def get_dir_size(source):
    total_size = os.path.getsize(source)
    for item in os.listdir(source):
        itempath = os.path.join(source, item)
        if os.path.isfile(itempath):
            total_size += os.path.getsize(itempath)
        elif os.path.isdir(itempath):
            total_size += get_dir_size(itempath)
    return total_size


def get_size(size_str, default_size, base=1024):
    if isinstance(size_str, int):
        size_str = '%d' % size_str
    elif isinstance(size_str, float):
        size_str = '%d' % int(size_str)
    elif not isinstance(size_str, str):
        size_str = str(size_str)
    if re.match(r'^\d+$', size_str):
        size_str += default_size
    if size_str[-1] == 'g' or size_str[-1] == 'G':
        size = int(size_str[:-1])*base*base*base
    elif size_str[-1] == 'm' or size_str[-1] == 'M':
        size = int(size_str[:-1])*base*base
    elif size_str[-1] == 'k' or size_str[-1] == 'K':
        size = int(size_str[:-1])*base
    elif size_str[-1] == 'b' or size_str[-1] == 'B':
        size = int(size_str[:-1])
    return size


def get_size_gb(size_str, default_size, base=1024):
    size = get_size(size_str, default_size, base=base)
    return size/base/base/base


def get_size_mb(size_str, default_size, base=1024):
    size = get_size(size_str, default_size, base=base)
    return size/base/base


def get_size_kb(size_str, default_size, base=1024):
    size = get_size(size_str, default_size, base=base)
    return size/base


def file_put_contents(fn, content, append=False):
    try:
        mode = 'w'
        if append:
            mode = 'a'
        with open(fn, mode) as f:
            from . import stringutils
            f.write(stringutils.ensure_ascii(content))
        return True
    except Exception as e:
        logging.error("Error %s while writing %s" % (str(e), fn))
    return False


def file_get_contents(fn):
    try:
        with open(fn, 'r') as f:
            return f.read()
    except Exception as e:
        logging.error("Error %s while reading %s" % (str(e), fn))
    return None


def get_fs_format(disk_path):
    try:
        ret = procutils.check_output(['blkid',
                                    '-o', 'value', '-s', 'TYPE', disk_path])
        return ''.join(ret).lower()
    except Exception as e:
        print(e)
    return None


def fs_format_to_disk_type(fs_format):
    if fs_format == 'swap':
        return 'linux-swap'
    elif fs_format.startswith('ext') or fs_format in ['xfs']:
        return 'ext2'
    elif fs_format.startswith('fat'):
        return 'fat32'
    elif fs_format == 'ntfs':
        return 'ntfs'
    return None


def get_block_dev_size(disk_path):
    print('get_block_dev_size', disk_path)
    try:
        cmds = ['blockdev', '--getsize64', disk_path]
        lines = procutils.check_output(cmds)
        return int(lines[0])
    except Exception as e:
        try:
            logging.error('Fail to get size by blockdev, try file size: %s' % e)
            return os.path.getsize(disk_path)
        except Exception as e:
            logging.error('Fail to get size: %s' % e)
    return -1


def mkpartition(image_path, fs_format):
    """ fdisk a image """
    t = fs_format_to_disk_type(fs_format)
    if t is None:
        logging.error('Unknown fs_format %s' % fs_format)
        return False
    parted = '/sbin/parted'
    label_type = 'gpt' # always use GPT, incase user extend partition beyond 2T
    # if get_block_dev_size(image_path)/512 > 2048*1024*1024:
    #     label_type = 'gpt'
    try:
        procutils.check_call([parted, '-s', image_path,
                                                        'mklabel', label_type])
    except Exception as e:
        logging.error('mklabel %s %s error %s' % (image_path, fs_format, e))
        return False
    try:
        procutils.check_call([parted, '-s', '-a', 'cylinder',
                        image_path, 'mkpart', 'primary', t, '0', '100%'])
        procutils.check_call(['/sbin/partprobe', image_path])
        return True
    except Exception as e:
        logging.error('mkpart %s %s error %s' % (image_path, fs_format, e))
    return False


def format_partition(path, fs, uuid):
    cmd = None
    cmd_uuid = None
    if fs == 'swap':
        cmd = ['mkswap', '-U', uuid]
    elif fs == 'ext2':
        cmd = ['mkfs.ext2']
        cmd_uuid = ['tune2fs', '-U', uuid]
    elif fs == 'ext3':
        cmd = ['mkfs.ext3']
        cmd_uuid = ['tune2fs', '-U', uuid]
    elif fs == 'ext4':
        cmd = ['mkfs.ext4', '-O', '^64bit', '-E', 'lazy_itable_init=1']
        cmd_uuid = ['tune2fs', '-U', uuid]
    elif fs == 'ext4dev':
        cmd = ['mkfs.ext4dev', '-E', 'lazy_itable_init=1']
        cmd_uuid = ['tune2fs', '-U', uuid]
    elif fs.startswith('fat'):
        cmd = ['mkfs.msdos']
    #elif fs == 'ntfs':
    #    cmd = ['/sbin/mkfs.ntfs']
    elif fs == 'xfs':
        cmd = ['mkfs.xfs', '-f', '-m', 'crc=0', '-i', 'projid32bit=0', '-n', 'ftype=0']
        cmd_uuid = ["xfs_admin", "-U", uuid]
        # cmd_uuid = ['xfs_db', '-x', '-p', 'xfs_admin', '-c', '\'uuid %s\'' % uuid]
    if cmd is not None:
        logging.info("%s", cmd)
        try:
            cmds = []
            cmds.extend(cmd)
            cmds.append(path)
            procutils.check_call(cmds)
            if cmd_uuid is not None:
                cmds = []
                cmds.extend(cmd_uuid)
                cmds.append(path)
                procutils.check_call(cmds)
            return True
        except Exception as e:
            logging.error("format partition %s fail %s", path, e)
    return False


def get_dev_uuid(dev):
    try:
        lines = procutils.check_output(['blkid', dev])
        for l in lines:
            print(l)
            if l.startswith(dev):
                ret = {}
                for part in l.split():
                    dat = part.split('=')
                    if len(dat) == 2 and dat[0].endswith("UUID"):
                        if dat[1][0] in "\"'":
                            ret[dat[0]] = dat[1][1:-1]
                        else:
                            ret[dat[0]] = dat[1]
                return ret
    except Exception as e:
        logging.error("fail to get blkid of %s: %s", dev, e)
    return None


def is_parted_fs_string(fsstr):
    return fsstr.lower() in ['ext2', 'ext3', 'ext4', 'xfs',
                     'fat16', 'fat32',
                     'hfs', 'hfs+', 'hfsx',
                     'linux-swap', 'linux-swap(v1)',
                     'ntfs', 'reiserfs', 'ufs', 'btrfs']


def parted_fs_to_mount_fs(fstr):
    if fstr == 'ntfs':
        return 'ntfs-3g'
    elif fstr == 'hfs+':
        return 'hfsplus'
    elif fstr in ['linux-swap', 'linux-swap(v1)']:
        return 'swap'
    else:
        return fstr


def parse_disk_partitions(dev, lines):
    parts = []
    label = None
    # 1      16065s  80324s  64260s  primary  ext3         boot
    label_pattern = re.compile(r'Partition Table:\s+(?P<label>\w+)')
    pattern = re.compile(r'(?P<idx>\d+)\s+(?P<start>\d+)s\s+(?P<end>\d+)s\s+(?P<count>\d+)s')
    for l in lines:
        if label is None:
            m = label_pattern.search(l)
            if m is not None:
                label = m.group('label')
        m = pattern.search(l)
        if m is not None:
            idx = m.group('idx')
            devname = dev
            if dev[-1] in '0123456789':
                devname += 'p'
            devname += idx
            start = m.group('start')
            end = m.group('end')
            count = m.group('count')
            data = re.split(r'\s+', l.strip())
            disktype = fs = flag = None
            offset = 0
            if len(data) > 4:
                if label == 'msdos':
                    disktype = data[4]
                    if len(data) > 5 and is_parted_fs_string(data[5]):
                        fs = data[5]
                        offset += 1
                    if len(data) > 5 + offset:
                        flag = data[5 + offset]
                elif label == 'gpt':
                    if is_parted_fs_string(data[4]):
                        fs = data[4]
                        offset += 1
                    if len(data) > 4 + offset:
                        disktype = data[4+offset]
                    if len(data) > 4 + offset + 1:
                        flag = data[4 + offset + 1]
            bootable = False
            if flag is not None and 'boot' in flag:
                bootable = True
            parts.append([idx, bootable, start, end, count, disktype, fs,
                            devname])
    return (parts, label)


def get_dev_sector_512_count(dev):
    sizestr = file_get_contents('/sys/block/%s/size' % dev)
    return int(sizestr)


def resize_disk_fs(disk_path, size_mb=0):
    try:
        cmds = ['parted', '-a', 'none', '-s', disk_path, '--',
                    'unit', 's', 'print']
        lines = procutils.check_output(cmds)
        parts, label = parse_disk_partitions(disk_path, lines)
        logging.info('Parts: %s label: %s', parts, label)
        max_sector = get_dev_sector_512_count(os.path.basename(disk_path))
        if label == 'gpt': # fix gpt table
            proc = procutils.InteractiveProcess(['gdisk', disk_path])
            proc.start()
            for cmd in ['r', 'e', 'Y', 'w', 'Y', 'Y']:
                proc.send(cmd)
            ret = proc.get_output_no_exception()
            code = proc.wait()
            if code > 0 and code != 1:
                raise Exception(ret)
        if len(parts) > 0 and \
                (label == 'gpt' or \
                    (label=='msdos' and parts[-1][5] == 'primary')):
            part = parts[-1]
            if size_mb > 0:
                end = size_mb*1024*2
            elif label == 'gpt':
                end = max_sector - 35
            else:
                end = max_sector - 1
            if label == 'msdos' and end >= 4294967296:
                end = 4294967295
            cmds = ['parted', '-a', 'none', '-s', disk_path, '--',
                        'unit', 's',
                        'rm', part[0],
                        'mkpart', part[5]]
            if part[6] is not None:
                cmds.append(part[6])
            cmds.extend([part[2], '%ds' % end])
            if part[1]:
                cmds.extend(['set', part[0], 'boot', 'on'])
            procutils.check_call(cmds)
            if part[6] is not None:
                resize_partition_fs(part[7], part[6], raise_exception=False)
            return True
    except Exception as e:
        logging.error("resize_disk_fs fail: %s", e)
    return False


def fsck_ext_fs(path):
    cmd = ['e2fsck', '-f', '-p', path]
    try:
        procutils.check_call(cmd)
        return True
    except CalledProcessError as e:
        # e2fsck exit code: the sum of the following conditions
        # 1: File system errors corrected
        # 2: File system errors corrected, system should be rebooted
        # others: 4, 8, 16, 32, 128
        if e.returncode < 4:
            return True
    return False


def fsck_xfs_fs(path):
    try:
        cmd = ['xfs_check', path]
        procutils.check_call(cmd)
        return True
    except:
        cmd = ['xfs_repair', path]
        procutils.check_call_no_exception(cmd)
    return False


def resize_partition_fs(path, fs, raise_exception=False):
    if fs is None:
        return False
    cmds = None
    uuids = get_dev_uuid(path)
    if fs.startswith('linux-swap'):
        if "UUID" in uuids:
            cmds = [['mkswap', '-U', uuids["UUID"], path]]
        else:
            cmds = [['mkswap', path]]
    elif fs.startswith('ext'):
        if not fsck_ext_fs(path):
            if raise_exception:
                raise Exception('Failed to fsck ext fs %s' % path)
            return False
        cmds = [['resize2fs', path]]
    elif fs == 'xfs':
        tmp_point = '/tmp/%s' % (path.replace('/', '_'))
        if os.path.ismount(tmp_point):
            procutils.check_call(['umount', '-f', tmp_point])
        fsck_xfs_fs(path)
        cmds = [['mkdir', '-p', tmp_point],
                ['mount', path, tmp_point],
                ['sleep', '2'],
                ['xfs_growfs', tmp_point],
                ['sleep', '2'],
                ['umount', tmp_point],
                ['sleep', '2'],
                ['rm', '-fr', tmp_point]]
    #elif fs == 'ntfs':
    #    cmds = [['ntfsresize', '-P', '-f', path]]
    if cmds is not None:
        try:
            for cmd in cmds:
                procutils.check_call(cmd)
            return True
        except Exception as e:
            print(e)
            if raise_exception:
                raise e
    return False


def md5sum(filename, offset=None, length=None):
    md5 = hashlib.md5()
    with open(filename, 'rb') as f:
        if offset:
            f.seek(offset)
        for chunk in iter(lambda: f.read(128*md5.block_size), b''):
            if length is not None:
                if length == 0:
                    break
                chunk_len = len(chunk)
                if chunk_len > length:
                    chunk = chunk[:length]
                length = length - chunk_len
            md5.update(chunk)
    return md5.hexdigest()


def probe_block_devices():
    """
    :return: {device: size_in_KB}
    """
    try:
        lines = procutils.check_output(['cat', '/proc/partitions'])
        devs = []
        for l in lines:
            parts = re.split(r'\s+', l)
            if len(parts) > 4:
                devs.append(parts[4])
        return devs
    except Exception as e:
        print(e)
    return None


def is_block_device_used(devname):
    if devname.startswith('/dev/'):
        devname = devname[devname.rfind('/')+1:]
    devs = probe_block_devices()
    if devname in devs:
        return True
    else:
        return False

def get_dev_id(path):
    dev = get_dev_of_path(path)
    print('storage dev is %s' % dev)
    if dev is None:
        return ''
    dev_info = procutils.check_output(['ls', '-l', dev])
    if dev_info is not None:
        data = dev_info[0].split(' ')
        data[4] = data[4][:-1]
        return ':'.join([data[4], '0'])
    return ''

def get_dev_mount_dir(dev):
    try:
        lines = procutils.check_output(['mount'])
        for l in lines:
            segs = l.split(' ')
            if segs[0] == dev:
                return segs[2]
    except Exception as e:
        logging.error("get_dev_mount_dir for %s error: %e", dev, e)
    return None

def get_dev_of_path(path):
    try:
        path = os.path.abspath(path)
        lines = procutils.check_output(['mount'])
        max_match_len = 0
        match_dev = None
        match_mount = None
        for l in lines:
            segs = l.split(' ')
            if segs[0].startswith('/dev/'):
                if path.startswith(segs[2]):
                    match_len = len(segs[2])
                    if max_match_len < match_len:
                        max_match_len = match_len
                        match_dev = segs[0]
                        match_mount = segs[2]
        print(path, match_dev, match_mount)
        return match_dev
    except Exception as e:
        print(e)
    return None


def is_block_dev_mounted(bdev):
    try:
        dev_path = '/dev/%s' % bdev
        lines = procutils.check_output(['mount'])
        for l in lines:
            segs = l.split(' ')
            if segs[0].startswith(dev_path):
                return True
    except Exception as e:
        print(e)
    return False


def mkdir_p(path):
    offset = 1
    path = os.path.abspath(path)
    while offset < len(path):
        pos = path.find('/', offset)
        if pos < 0:
            pos = len(path)
        p_path = path[:pos]
        if os.path.exists(p_path):
            if not os.path.isdir(p_path):
                raise Exception('%s not a directory' % p_path)
        else:
            os.mkdir(p_path)
        offset = pos + 1


def change_all_blkdevs_params(params):
    if os.path.exists('/sys/block'):
        block_devs = os.listdir('/sys/block')
        for b in block_devs:
            if is_block_dev_mounted(b):
                for key, value in params.iteritems():
                    change_blkdev_parameter(b, key, value)


def change_blkdev_parameter(dev, key, value):
    try:
        path = '/sys/block/%s/%s' % (dev, key)
        if os.path.exists(path):
            file_put_contents(path, value)
            logging.info('Set %s of %s to %s' % (key, dev, value))
    except Exception as e:
        logging.error('Fail to set %s of %s to %s: %s' % (key, dev, value, e))


def cleandir(path, keepdir):
    if os.path.islink(path):
        return
    for f in os.listdir(path):
        fp = os.path.join(path, f)
        if os.path.islink(fp):
            if not keepdir:
                os.remove(fp)
        elif os.path.isdir(fp):
            cleandir(fp, keepdir)
            if not keepdir:
                os.rmdir(fp)
        elif os.path.isfile(fp):
            os.remove(fp)
        else:
            os.remove(fp)


def zerofiles(path):
    if os.path.islink(path):
        return
    # works for single file
    if os.path.isfile(path):
        file_put_contents(path, '')
        return
    for f in os.listdir(path):
        fp = os.path.join(path, f)
        if os.path.islink(fp):
            return
        elif os.path.isfile(fp):
            file_put_contents(fp, '')
        elif os.path.isdir(fp):
            zerofiles(fp)


def is_file_open(path):
    try:
        procutils.check_call(['lsof', path])
        return True
    except:
        return False


def clean_failed_mountpoints():
    mtfile = '/etc/mtab'
    if not os.path.exists(mtfile):
        mtfile = '/proc/mounts'
    with open(mtfile, 'r') as f:
        for l in f:
            dat = l.split(' ')
            if len(dat) > 1:
                mp = dat[1]
                if not os.path.exists(mp):
                    logging.warning('Mount point %s not exists' % mp)
                    cmds = ['umount', mp]
                    procutils.check_call_no_exception(cmds)


class mmap_open(object):
    def __init__(self, fd, length=0, **kwarg):
        self.fd = fd
        self.length = length
        # kwarg contains optionally offset argument for mmap
        self.kwarg = kwarg

    def __enter__(self):
        self.body = mmap.mmap(self.fd.fileno(), self.length,
                               access=mmap.ACCESS_READ, **self.kwarg)
        return self.body

    def __exit__(self, type, value, traceback):
        if self.body is not None:
            self.body.close()


if __name__ == '__main__':
    #print probe_block_devices()
    if len(sys.argv) > 1:
        #print is_block_device_used(sys.argv[1])
        #mkpartition(sys.argv[1], 'ext4')
        #resize_disk_fs(sys.argv[1])
        #get_dev_of_path(sys.argv[1])
        #change_all_devs_scheduler(sys.argv[1])
        #mkdir_p(sys.argv[1])
        #clean_failed_mountpoints()
        #cleandir(sys.argv[1], True)
        print(get_dev_uuid(sys.argv[1]))
    else:
        print('fileutils.py <image_path>')
