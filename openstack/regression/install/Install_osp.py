# Install OSP
import subprocess
import argparse
import logging

logging.basicConfig(format='%(asctime)s : %(levelname)s: %(message)s',
                    datefmt='[%m/%d/%Y - %I:%M:%S %p]',
                    filename='ios.log',level=logging.DEBUG)

class Bcolors:
    HEADER = '\033[95m'
    OKGREEN = '\033[92m'
    FAIL = '\033[91m'
    ENDC = '\033[0m'
    BOLD = '\033[1m'


def onscreen(text):
    print "\033[1;36m*%s*\033[1;m" % text

# Register and install OSP.

# step 1
class InstallOSP(object):

    def __init__(self, pool_id, repos, ):
        
        self.pool_id = pool_id
        self.rhel_repos = repos

    def do_install(self):

        # Register to CDN and subscribe to required channels
        onscreen('Registering to CDN')
        subprocess.call(['subscription-manager', 'register'])

        onscreen('Subscribing to RHEL7 channel')
        subprocess.call(['subscription-manager', 'subscribe', '--auto'])

        onscreen('Subscribing to pool id=%s' % self.pool_id)
        subprocess.call(['subscription-manager', 'subscribe', '--pool=%s' % self.pool_id])
        subprocess.call(['subscription-manager', 'repos', '--disable=*'])

        onscreen('Enabling openstack 7.0 and other dependent repos')
        for each_repo in self.rhel_repos:
            subprocess.call(['subscription-manager', 'repos', '--enable=%s' % each_repo])

        # Disable NetworkManager
        onscreen('Disabling NetworkManager')
        subprocess.call(['systemctl', 'disable', 'NetworkManager'])

        # Install openstack with packstack
        onscreen('Subscription completed. Packstack installation begins')
        subprocess.call(['yum', 'install', '-y', 'openstack-packstack'])
        subprocess.call(['packstack', '--allinone'])


if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Install OSP')

    parser.add_argument('-pid', "--pool_id", dest = "pid", help= 'Enter the RHEL Pool Id')
    parser.add_argument('-r', '--repo', dest='r', nargs= '*',  help= 'Enter RHEL Ceph RPMS')

    args = parser.parse_args()

    v2 = InstallOSP(args.pid,args.r)
    v2.do_install()

    #v2_install('8a85f9823e3d5e43013e3ddd4e2a0977', 'RHEL-7-server-rpms', 'RHEL-7-server-rh-common-rpms','RHEL-7-server-openstack-7.0-rpms' )