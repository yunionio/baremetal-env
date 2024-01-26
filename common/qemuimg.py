import re
import os.path
import logging
import uuid

from . import procutils
from .qemutils import get_qemu_img

STORAGE_RBD = 'rbd'

class QemuImage(object):

    # QCOW2_SPARSE_OPTIONS  = 'preallocation=metadata,lazy_refcounts=on'
    QCOW2_COMPACT_OPTIONS = []  # 'cluster_size=4K,preallocation=off'

    def __init__(self, path, password=None):
        self.path = path
        self.password = password
        self.parse()

    @classmethod
    def qemu_img_version(cls):
        ver = getattr(cls, '__qemu_img_ver__', None)
        if ver is None:
            lines = procutils.check_output_no_exception([get_qemu_img(), '--version'])
            ver_pattern = re.compile('qemu-img version (?P<ver>\d+\.\d+(\.\d+)?)')
            for line in lines:
                m = ver_pattern.search(line)
                if m is not None:
                    ver = m.group('ver')
                    cls.__qemu_img_ver__ = map(int, ver.split('.'))
                    break
        if not hasattr(cls, '__qemu_img_ver__'):
            raise Exception('Unknown qemu-img version')
        return cls.__qemu_img_ver__

    @classmethod
    def qcow2_sparse_options(cls):
        ver = cls.qemu_img_version()
        if ver <= (1, 1):
            return ['preallocation=metadata', 'cluster_size=2M']
        elif ver <= (1, 7, 1):
            return ['preallocation=metadata', 'lazy_refcounts=on']
        elif ver <= (2, 2):
            return ['preallocation=metadata', 'lazy_refcounts=on', 'cluster_size=2M']
        else:
            return []

    def is_valid(self):
        if self.format is not None:
            return True
        else:
            return False

    def parse(self):
        """
        QEMU Device URL Syntax
        """
        self.format = None
        self.size = 0
        self.size_bytes = 0
        self.actual_size = 0
        self.actual_size_bytes = 0
        self.cluster_size = 0
        self.back_file = None
        self.compat = None
        self.encryption = False
        self.subformat = None
        if self.path.startswith('nbd'):
            # nbd TCP -> nbd:<server-ip>:<port>
            # nbd Unix Domain Sockets -> nbd:unix:<domain-socket-file>
            self.actual_size = 0
        elif self.path.startswith('iscsi'):
            # iSCSI LUN -> iscsi://<target-ip>[:<port>]/<target-iqn>/<lun>
            raise NotImplementedError
        elif self.path.startswith('sheepdog'):
            # sheepdog -> sheepdog[+tcp|+unix]://[host:port]/vdiname[?socket=path][#snapid|#tag]
            raise NotImplementedError
        elif self.path.startswith(STORAGE_RBD):
            self.actual_size_bytes = 0
            self.actual_size = 0
        elif os.path.isfile(self.path):
            # local file
            self.actual_size_bytes = os.path.getsize(self.path)
            self.actual_size = self.actual_size_bytes / 1024 / 1024
        else:
            logging.info("The file does not exist yet: %s", self.path)
            return False
        try:
            cmd = [get_qemu_img(), 'info', self.path]
            prog = procutils.InteractiveProcess(cmd)
            prog.start()
            if self.password:
                prog.send(self.password + '\r')
            lines = prog.get_output()
            for ll in lines:
                ll = ll.strip()
                if ll.startswith('file format:'):
                    fmt = ll[ll.rfind(' ') + 1:]
                    self.format = fmt.strip()
                elif ll.startswith('virtual size:') and self.size == 0:
                    size_str = ll[ll.find('(')+1:ll.rfind(' ')]
                    self.size_bytes = int(size_str)
                    self.size = self.size_bytes/1024/1024
                elif ll.startswith('cluster_size:'):
                    size_str = ll[ll.rfind(' ')+1:]
                    self.cluster_size = int(size_str)
                elif ll.startswith('backing file:'):
                    path_str = ll[ll.rfind(' ')+1:]
                    self.back_file = QemuImage(path_str)
                elif ll.startswith('compat:'):
                    compat = ll[ll.rfind(' ')+1:]
                    self.compat = compat
                elif ll.startswith('encrypted:'):
                    enc_str = ll[ll.rfind(' ')+1:]
                    if enc_str == 'yes':
                        self.encryption = True
                elif ll.startswith('create type:'):
                    subformat = ll[ll.rfind(' ')+1:]
                    self.subformat = subformat
            return True
        except Exception as e:
            logging.info(str(e))
        return False

    def is_chained(self):
        if self.back_file is not None:
            return True
        else:
            return False

    def _clone(self, name, format, options=None, compact=False):
        if not self.is_valid():
            return None
        try:
            cmd = [get_qemu_img(), 'convert']
            if compact:
                cmd.append('-c')
            cmd.extend(['-f', self.format, '-O', format])
            if options is not None and len(options) > 0:
                cmd.extend(['-o', ','.join(options)])
            cmd.extend([self.path, name])
            convert = procutils.check_call(cmd)
            if convert == 0:
                return QemuImage(name)
        except Exception as e:
            logging.error('QemuImg::clone: %s' % e)
            if os.path.exists(name):
                os.remove(name)
        return None

    def copy(self, name):
        if not self.is_valid():
            return None
        try:
            cmds = ['cp', '--sparse=always', self.path, name]
            ret = procutils.check_call(cmds)
            if ret == 0:
                return QemuImage(name)
        except Exception as e:
            print(e)
            if os.path.exists(name):
                os.remove(name)
        return None

    def convert(self, format, options=None, compact=False, password=None, output=None, **kwargs):
        self._convert(format, options=options, compact=compact, password=password, output=output, **kwargs)

    def _convert(self, format, options=None, compact=False, password=None, output=None, **kwargs):
        if not self.is_valid():
            return False
        tmp_file = output
        if tmp_file is None:
            tmp_file = self.path + '.' + str(uuid.uuid4())
        try:
            cmd = [get_qemu_img(), 'convert']
            if kwargs.get('ionice') == 'idle':
                cmd = ['ionice', '-c3'] + cmd
            if compact:
                cmd.append('-c')
            cmd.extend(['-f', self.format, '-O', format])
            if password is not None:
                if options:
                    options.append("encryption=on")
                else:
                    options = ["encryption=on"]
            if options is not None and len(options) > 0:
                cmd.extend(['-o', ','.join(options)])
            cmd.extend([self.path, tmp_file])
            prog = procutils.InteractiveProcess(cmd)
            prog.start()
            if password is not None:
                prog.send(password + '\r')
            prog.get_output()
            convert = prog.get_returncode()
            if convert == 0 and output is None:
                rm = procutils.check_call(['rm', '-f', self.path])
                if rm == 0:
                    mv = procutils.check_call(['mv', '-f', tmp_file, self.path])
                    if mv == 0:
                        if password:
                            self.password = password
                        return self.parse()
            elif convert == 0 and output == tmp_file:
                return self.parse()
        except Exception as e:
            logging.error('qemu-convert error %s' % e)
        try:
            if os.path.exists(tmp_file):
                procutils.check_call(['rm', '-f', tmp_file])
        except Exception as e:
            logging.error(str(e))
        return False

    def convert2qcow2(self, compact=False, back=None, password=None):
        options = []
        if back is not None:
            if isinstance(back, QemuImage):
                path = back.path
            else:
                path = back
            options.append('backing_file=%s' % path)
        elif compact:
            options.extend(self.QCOW2_COMPACT_OPTIONS)
        else:
            options.extend(self.qcow2_sparse_options())
        return self._convert('qcow2', options=options, compact=compact,
                            password=password)

    def convert2vmdk(self, compact=False, back=None, password=None):
        options = [] # 'adapter_type=lsilogic', 'hwversion=13']
        if back is not None:
            if isinstance(back, QemuImage):
                path = back.path
            else:
                path = back
            options.append('backing_file=%s' % path)
        elif compact:
            options.append('subformat=streamOptimized')
        else:
            options.append('subformat=monolithicSparse')
        return self._convert('vmdk', options=options)

    def convert2raw(self):
        return self.convert('raw', options=None, compact=False)

    def is_sparse(self):
        print('is_sparse', self.format, self.cluster_size)
        if self.format == 'raw' or \
                (self.format == 'qcow2' and self.cluster_size >= 1024*1024*2) or \
                (self.format == 'vmdk' and self.subformat != 'streamOptimized'):
            return True
        else:
            return False

    def expand(self):
        if self.is_sparse():
            return True
        else:
            return self.convert2qcow2(compact=False)

    def clone_qcow2(self, name, compact=False, back=None):
        options = []
        if back is not None:
            if isinstance(back, QemuImage):
                path = back.path
            else:
                path = back
            options.append('backing_file=%s' % path)
        elif compact:
            options.extend(self.QCOW2_COMPACT_OPTIONS)
        else:
            options.extend(self.qcow2_sparse_options())
        return self._clone(name, 'qcow2', options=options, compact=compact)

    def clone_vmdk(self, name, compact=False, back=None):
        options = [] # 'adapter_type=lsilogic', 'hwversion=13']
        if back is not None:
            if isinstance(back, QemuImage):
                path = back.path
            else:
                path = back
            options.append('backing_file=%s' % path)
        elif compact:
            options.append('subformat=streamOptimized')
        else:
            options.extend('subformat=monolithicSparse')
        return self._clone(name, 'qcow2', options=options, compact=compact)

    def clone_raw(self, name):
        return self._clone(name, 'raw', options=None, compact=False)

    # def clone_expand(self, name):
    #     if self.is_sparse():
    #         return self.copy(name)
    #     else:
    #         return self.clone_qcow2(name, compact=False)

    def get_backing_file_ver(self, options):
        r = re.findall('backing_file=([^ ]+)', options)
        try:
            backing_file = r[0]
        except:
            return ''
        backing_img = QemuImage(backing_file)
        if backing_img.compat == '0.10':
            return "_1.0"
        return ''

    def _create(self, size_mb, format, options=None):
        if self.is_valid():
            logging.info("The image is valid???")
            return False
        try:
            # if there is a backing file and it's compat
            # is '0.10', use qemu-img_1.0 to create the
            # new qcow2 img.
            # Otherwise use qemu_img
            # ver = self.get_backing_file_ver(options)
            qemu_img = get_qemu_img()
            cmd = [qemu_img, 'create', '-f', format]
            if options:
                cmd.extend(['-o', ','.join(options)])
            cmd.append(self.path)
            if size_mb > 0:
                cmd.append('%dM' % size_mb)
            ret = procutils.check_call(cmd)
            logging.info("qemu-img exit code: %s", ret)
            if ret == 0:
                return self.parse()
        except Exception as e:
            logging.info(str(e))
        return False

    def create_qcow2(self, size_mb=0, compact=False, back=None):
        options = []
        if back is not None:
            if isinstance(back, QemuImage):
                path = back.path
            else:
                path = back
            options.append('backing_file=%s' % (path))
            if not compact:
                options.append('cluster_size=2M')
            size_mb = 0
        elif compact:
            options.extend(self.QCOW2_COMPACT_OPTIONS)
        else:
            options.extend(self.qcow2_sparse_options())
        return self._create(size_mb, 'qcow2', options=options)

    def create_vmdk(self, size_mb=0, compact=False, back=None):
        options = [] # 'adapter_type=lsilogic', 'hwversion=13']
        if back is not None:
            if isinstance(back, QemuImage):
                path = back.path
            else:
                path = back
            options.append('backing_file=%s' % (path))
            size_mb = 0
        elif compact:
            options.append('subformat=streamOptimized')
        else:
            options.append('subformat=monolithicSparse')
        return self._create(size_mb, 'vmdk', options=options)

    def create_raw(self, size_mb):
        return self._create(size_mb, "raw")

    def create(self, format, size_mb=0, compact=False, back=None):
        if format == 'vmdk':
            return self.create_vmdk(size_mb=size_mb, compact=compact, back=back)
        elif format == 'qcow2':
            return self.create_qcow2(size_mb=size_mb, compact=compact, back=back)
        elif format == 'raw':
            return self._create(size_mb, format)
        else:
            raise Exception('Unsupport format %s' % format)

    def resize(self, new_size_mb):
        if not self.is_valid():
            return False
        try:
            ret = procutils.check_call([get_qemu_img(), 'resize',
                                    self.path, '%dM' % int(float(new_size_mb))])
            if ret == 0:
                return self.parse()
        except Exception as e:
            logging.info(str(e))
        return False

    def rebase(self, back, force=False):
        if not self.is_valid():
            return False
        try:
            if isinstance(back, QemuImage):
                path = back.path
            else:
                path = back
            cmds = [get_qemu_img(), 'rebase']
            if force:
                cmds.append('-u')
            cmds.extend(['-b', path, self.path])
            procutils.check_call(cmds)
            return self.parse()
        except Exception as e:
            logging.error(str(e))
        return False

    def delete(self):
        if self.is_valid():
            os.remove(self.path)
            self.format = None
            self.size = 0
            self.actual_size = 0
            self.actual_size_bytes = 0
            self.size_bytes = 0

    def fallocate(self):
        if self.is_valid():
            try:
                cmds = ['fallocate', '-l', '%dm' % self.size, self.path]
                procutils.check_call(cmds)
            except Exception as e:
                logging.error(str(e))

    def whole_chain_format_is(self, req_format):
        if self.format != req_format:
            return False
        if self.back_file is not None:
            return self.back_file.whole_chain_format_is(req_format)
        return True

    def __str__(self):
        return "Qemu %s %d(%d) %s %s" % (self.format, self.size,
                                        self.actual_size,
                                        self.path, self.encryption)

    def __repr__(self):
        return self.__str__()


def vmdk_test():
    img = QemuImage('test')
    img.create_vmdk(1024, compact=True)
    print(img, img.is_sparse())
    img.delete()
    img.create_vmdk(1024, compact=False)
    print(img, img.is_sparse())
    img.convert2vmdk(compact=True)
    print(img, img.is_sparse())
    img.convert2vmdk(compact=False)
    print(img, img.is_sparse())
    img4 = QemuImage('test_top')
    img4.create_vmdk(compact=True, back=img)
    print(img, img.is_sparse())
    print(img4, img4.is_sparse())
    img.convert2vmdk(compact=True)
    print(img, img.is_sparse())
    print(img4, img4.is_sparse())
    # img4.delete()
    # img.delete()


def qcow2_test():
    print(QemuImage.qcow2_sparse_options())
    img = QemuImage('test')
    print(img.create_qcow2(1000, compact=True))
    print(img, img.is_sparse())
    img.delete()
    print(img.create_qcow2(1000, compact=False))
    print(img, img.is_sparse())
    img.convert2qcow2(compact=True)
    print(img, img.is_sparse())
    img.convert2qcow2(compact=False)
    print(img, img.is_sparse())
    img.resize(2048)
    print(img, img.is_sparse())
    img.convert2qcow2(compact=True)
    print(img, img.is_sparse())
    img.expand()
    print('expand', img, img.is_sparse())
    print('Start to encrypt qcows...')
    img.convert2qcow2(password='123456')
    print('encryption', img, img.is_sparse())
    img.delete()
    print('delete', img)
    img.create_qcow2(1000, compact=True)
    print(img, img.is_sparse())
    img2 = img.clone_qcow2('test2', compact=True)
    print(img2, img2.is_sparse())
    # img3 = img2.clone_expand('test3')
    # print img3, img3.is_sparse()
    img2.delete()
    #img3.delete()
    img.convert2qcow2(compact=False)
    img4 = QemuImage('test_top')
    img4.create_qcow2(compact=True, back=img)
    print(img, img.is_sparse())
    print(img4, img4.is_sparse())
    img.convert2qcow2(compact=True)
    print(img, img.is_sparse())
    print(img4, img4.is_sparse())
    img4.delete()
    img.delete()



if __name__ == '__main__':
    import sys
    if len(sys.argv) > 1 and sys.argv[1] == 'vmdk':
        vmdk_test()
    else:
        qcow2_test()
