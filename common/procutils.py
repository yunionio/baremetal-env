import subprocess
import time
import logging
import os
import shlex
import select
import fcntl
import signal


class InteractiveProcess(object):

    def __init__(self, cmds, **kwargs):
        """
        :param cmds: commands(iterable)
        :param disassociate: disassociate child process from parent process group
        :param redirect_file: redirect process's stdout to file, equals to ">" in shell
        """
        timeout = kwargs.pop('timeout', -1)
        if timeout > 0:
            cmds = ['timeout', '--signal=KILL', '%ds' % timeout] + cmds
        self.cmds = map(str, cmds)
        self.disassociate = kwargs.pop('disassociate', False)
        self.redirect_file = kwargs.pop('redirect_file', None)
        self.kwargs = kwargs
        self.is_redirect = False
        self.proc = None

    def start(self):
        self.kwargs.update({'stdin': subprocess.PIPE,
                  'stdout': subprocess.PIPE,
                  'stderr': subprocess.STDOUT,
                  'close_fds': True,
                  })
        if self.redirect_file is not None:
            if not hasattr(self.redirect_file, 'write'):
                raise Exception('%s is not a opening file for IO redirect' % self.redirect_file)
            else:
                self.is_redirect = True
                self.kwargs['stdout'] = self.redirect_file
                self.kwargs['stderr'] = subprocess.PIPE
        if self.disassociate:
            self.kwargs['preexec_fn'] = os.setsid
        self.kwargs['bufsize'] = 0
        self.kwargs['shell'] = False
        self.proc = subprocess.Popen(self.cmds, **self.kwargs)
        fd = self._get_fd()
        fdno = fd.fileno()
        fl = fcntl.fcntl(fdno, fcntl.F_GETFL)
        fcntl.fcntl(fdno, fcntl.F_SETFL, fl | os.O_NONBLOCK)

    def is_started(self):
        return self.proc is not None

    def _get_fd(self):
        return self.proc.stdout if not self.is_redirect else self.proc.stderr

    def get_output_stream(self):
        fd = self._get_fd()
        fdno = fd.fileno()
        try:
            r, w, x = select.select([fdno], [], [fdno], 1)
            if fdno in r:
                return fd.read()
        except Exception as e:
            print(e)
        return None

    def get_output_no_exception(self):
        lines = ''
        is_exit = False
        fd = self._get_fd()
        fdno = fd.fileno()
        while not is_exit:
            try:
                r, w, x = select.select([fdno], [], [fdno], 1)
                if fdno in r:
                    lines += fd.read()
                elif fdno in x:
                    break
            except:
                pass
            is_exit = self.proc.poll() is not None
        try:
            extra = fd.read() # read leftover
            while extra:
                lines += extra
                time.sleep(0.001)
                try:
                    extra = fd.read()
                except:
                    pass
        except:
            pass
        return map(str.strip, lines.split('\n'))

    def get_output(self):
        ret = self.get_output_no_exception()
        self.returncode = self.proc.wait()
        if self.returncode > 0:
            raise Exception('\n'.join(ret))
        return ret

    def wait(self):
        self.returncode = self.proc.wait()
        return self.returncode

    def send(self, cmd):
        self.proc.stdin.write('%s\n' % cmd)
        self.proc.stdin.flush()

    def is_exit(self):
        time.sleep(0.1)
        self.proc.poll()
        if self.proc.returncode is None:
            return False
        else:
            self.returncode = self.proc.returncode
            return True

    def get_returncode(self):
        return self.returncode

    def kill(self):
        self.proc.kill()
        return self.is_exit()

    def get_pid(self):
        if self.proc:
            return self.proc.pid
        else:
            return None

    def get_children_pids(self):
        pids = []
        pid = self.get_pid()
        if pid is not None and os.path.exists('/proc/%d' % pid):
            for f in os.listdir('/proc/%d/task' % pid):
                cpid = int(f)
                if cpid != pid:
                    pids.append(cpid)
        return pids

    def kill_children(self):
        for pid in self.get_children_pids():
            logging.info("Kill children process %d", pid)
            os.kill(pid, signal.SIGTERM)

    def get_pids(self):
        return find_processes(self.cmds)

    def kill_all(self):
        for pid in self.get_pids():
            logging.info("Kill process %d", pid)
            os.kill(pid, signal.SIGTERM)


def check_call(cmds, **kwargs):
    timeout = kwargs.pop('timeout', -1)
    if timeout > 0:
        cmds = ['timeout', '--signal=KILL', '%ds' % timeout] + cmds
    cmds = map(str, cmds)
    return subprocess.check_call(cmds, close_fds=True)


def check_call_no_exception(cmds, **kwargs):
    try:
        if check_call(cmds, **kwargs) == 0:
            return True
    except Exception as e:
        logging.warning(e)
    return False


def check_output(cmds, **kwargs):
    if isinstance(cmds, str):
        cmds = shlex.split(cmds)
    elif not hasattr(cmds, '__iter__'):
        raise Exception('Invalid type of commands')
    proc = InteractiveProcess(cmds, **kwargs)
    proc.start()
    if kwargs.get('ignore_exception', False):
        return proc.get_output_no_exception()
    return proc.get_output()


def check_output_no_exception(cmds, **kwargs):
    try:
        ret = check_output(cmds, **kwargs)
        return ret
    except Exception as e:
        return str(e).split('\n')


def find_processes(keys):
    pids = []
    for f in os.listdir('/proc'):
        import re
        import fileutils
        if re.match(r'\d+', f) and os.path.isdir('/proc/' + f) and \
                os.path.exists('/proc/%s/cmdline' % f):
            cmds = fileutils.file_get_contents('/proc/%s/cmdline' % f)
            cmds = cmds.split('\0')
            while len(cmds) > 0 and len(cmds[-1]) == 0:
                cmds.pop(-1)
            if len(cmds) < len(keys):
                continue
            i = len(keys) - 1
            j = len(cmds) - 1
            while i >= 0 and j >= 0:
                if keys[i] == cmds[j]:
                    i -= 1
                    j -= 1
                else:
                    break
            if i < 0 or j < 0:
                print(f, cmds)
                pids.append(int(f))
    return pids


if __name__ == '__main__':

    # normal
    print(check_output('ls'))
    print(check_output(['ls', '-a']))

    with open('test_io_redirect1', 'w') as f:
        print(check_output('ls -ls', redirect_file=f))

    # exception
    try:
        print(check_output('ls a_not_exsisting_file'))
    except Exception as e:
        print(e)

    try:
        with open('test_io_redirect2', 'w') as f:
            print(check_output('ls a_not_exsisting_file', redirect_file=f))
    except Exception as e:
        print(e)


    print(find_processes(['/usr/sbin/httpd', '-DFOREGROUND']))
