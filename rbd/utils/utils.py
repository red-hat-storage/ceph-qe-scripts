import logging as log 
import shlex
import random
import string
import subprocess


class RbdUtils:
    def __init__(self, k_m=None):
        self.ceph_version = self.get_ceph_version()

    def get_ceph_version(self):
        self.output = self.exec_cmd('ceph -v')
        self.output = int('.'.join(self.output.split()[2].split('.')[:1]))
        if self.output == 10:
            return 2
        elif self.output == 12:
            return 3
        elif self.output == 14:
            return 4

    def exec_cmd(self, cmd):

        try:
            cmd = ' '.join(shlex.split(cmd))

            log.info('executing cmd: %s' % cmd)
            pr = subprocess.Popen(cmd, stdout=subprocess.PIPE,
                                  stderr=subprocess.PIPE, shell=True)

            out, err = pr.communicate()

            if pr.returncode == 0:
                log.info('cmd executed')
                if out or err:
                    log.info('output:' + out.decode(encoding="utf-8") + err.decode(encoding="utf-8"))
                return out.decode(encoding="utf-8")

            else:
                raise Exception("error: %s \nreturncode: %s" % (err, pr.returncode))

        except Exception as e:
            log.error('cmd execution failed')
            log.error(e)
            return False

    def random_string(self, length=8, prefix='', suffix=''):
        self.temp_str = prefix + ''.join([random.choice(string.ascii_letters) for _ in range(length)]) + suffix
        return self.temp_str

    def create_pool(self, **kw):
        self.exec_cmd(cmd='ceph osd pool create {} 64 64'
                      .format(kw.get('poolname')))
        if self.ceph_version >= 3:
            self.exec_cmd(cmd='rbd pool init {}'.format(kw.get('poolname')))

    def delete_pool(self, **kw):
        self.exec_cmd('ceph osd pool delete {pool} {pool} --yes-i-really-really-mean-it'
                      .format(pool=kw.get('poolname')))

    def clean_up(self, **kw):
        # Pools deletion
        if kw.get('pools'):
            [self.delete_pool(poolname=val) for key, val in kw.get('pools').items() if val is not None]

        # ec profile removal
        if kw.get('profile'):
            self.rm_ec_profile(profile=kw.get('profile'))

    def create_ecpool(self, **kw):
        poolname = kw.get('poolname')
        profile = kw.get('profile')
        self.exec_cmd(cmd='ceph osd pool create {} 12 12 erasure {}'
                      .format(poolname, profile))
        self.exec_cmd(cmd='rbd pool init {}'.format(poolname))
        self.exec_cmd(cmd='ceph osd pool set {} allow_ec_overwrites true'
                      .format(poolname))

    def set_ec_profile(self, **kw):
        self.rm_ec_profile(profile=kw.get('profile'))
        self.exec_cmd(cmd='ceph osd erasure-code-profile set {} k={} m={}'
                      .format(kw.get('profile'), kw.get('k', 2), kw.get('m', 1)))

    def rm_ec_profile(self, **kw):
        self.exec_cmd(cmd='ceph osd erasure-code-profile rm {}'.format(kw.get('profile')))
