# Install OSP
import subprocess
import argparse
import logging
import sys

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


def log_msgs(msgs):
    logging.info(msgs)
    print msgs
    
    
def log_errors(msgs):
    logging.error(msgs)
    print msgs

class InstallOSP(object):

    def __init__(self, pool_id, repos, qa_username, qa_password ):
        
        self.pool_id = pool_id
        self.rhel_repos = repos
        self.user_name = qa_username
        self.passw = qa_password

        self.exec_cmd = lambda cmd: subprocess.check_output(cmd, shell=True, stderr=subprocess.STDOUT)

    def do_install(self):

        try:
            onscreen('Unregistering to CDN')
            unregister_cmd = 'sudo subscription-manager  unregister'
            log_msgs(unregister_cmd)
            self.exec_cmd(unregister_cmd)

            onscreen('Registering to CDN')
            register_cmd = ('sudo subscription-manager register --username=%s --password=%s' % (self.user_name, self.passw))
            log_msgs(register_cmd)
            self.exec_cmd(register_cmd)

            onscreen('Subscribing to RHEL7 channel')
            subscribe_cmd = 'sudo subscription-manager subscribe --auto'
            log_msgs(subscribe_cmd)
            self.exec_cmd(subscribe_cmd)

            onscreen('Subscribing to pool id=%s' % self.pool_id)
            attach_pool = 'sudo subscription-manager attach --pool=%s' % self.pool_id
            log_msgs(attach_pool)
            self.exec_cmd(attach_pool)

            onscreen('Disabling Repos')
            disable_repos = 'sudo subscription-manager repos --disable=*'
            log_msgs(disable_repos)
            self.exec_cmd(disable_repos)

            onscreen('Enabling openstack 7.0 and other dependent repos')
            for each_repo in self.rhel_repos:
                enable_repo = 'sudo subscription-manager repos --enable=%s' % each_repo
                log_msgs(enable_repo)
                self.exec_cmd(enable_repo)

            onscreen('Disabling NetworkManager')
            disable_network = 'sudo systemctl disable NetworkManager'
            log_msgs(disable_network)
            self.exec_cmd(disable_network)

            onscreen('removing mod ssl')
            removing_mod_ssl = 'sudo yum remove mod_ssl-* -y'
            log_msgs(removing_mod_ssl)
            self.exec_cmd(removing_mod_ssl)

            onscreen('Subscription completed. Packstack installation begins')
            install_packstack = 'sudo yum install -y openstack-packstack'
            log_msgs(install_packstack)
            self.exec_cmd(install_packstack)

            packstack_all = 'sudo packstack --allinone'
            log_msgs(packstack_all)
            self.exec_cmd(packstack_all)

            return True, 0

        except subprocess.CalledProcessError as e:
            error = Bcolors.FAIL + Bcolors.BOLD + e.output + str(e.returncode) + Bcolors.ENDC
            print error
            log_errors(error)
            return False, e.returncode

if __name__ == '__main__':

    parser = argparse.ArgumentParser(description='Install OSP')

    parser.add_argument('-pid', "--pool_id", dest = "pid", help= 'Enter the RHEL Pool Id')
    parser.add_argument('-r', '--repo', dest='r', nargs= '*',  help= 'Enter RHEL Ceph RPMS')
    parser.add_argument('-u',  '--username,', dest='u', help = "Enter QA the Username")
    parser.add_argument('-p',  '--password', dest='p', help = 'Enter QA Password')

    args = parser.parse_args()

    log_msgs('pool id: %s' % args.pid)
    log_msgs('rpms : %s' % args.r)
    log_msgs('qa_username : %s' % args.u)
    log_msgs('qa_password : %s' % args.p)

    try:

        v2 = InstallOSP(args.pid,args.r, args.u, args.p)
        installed = v2.do_install()

        assert installed[0], "Installation Failed"
        onscreen('Installation completed')
        log_msgs('Installation completed')

    except AssertionError, e :
        log_errors(e)
        log_errors('Installation Failed')
        print e
        sys.exit(1)



    # pool_id = 8a85f9823e3d5e43013e3ddd4e2a0977
    # rpms = ['rhel-7-server-rpms', 'rhel-7-server-rh-common-rpms', 'rhel-7-server-openstack-7.0-rpms']
    # username = qa@redhat.com
    # password = QMdMJ8jvSWUwB6WZ
