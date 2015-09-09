import subprocess

# Register to CDN and subscribe to required channels
print "\033[1;36m*Registering to CDN*\033[1;m"
subprocess.call(['subscription-manager', 'register'])

print "\033[1;36m*Subscribing to RHEL7 channel*\033[1;m"
subprocess.call(['subscription-manager', 'subscribe', '--auto'])

print "\033[1;36m*Subscribing to pool id=8a85f9823e3d5e43013e3ddd4e2a0977*\033[1;m"
subprocess.call(['subscription-manager', 'subscribe', '--pool=8a85f9823e3d5e43013e3ddd4e2a0977'])
subprocess.call(['subscription-manager', 'repos', '--disable=*'])

print "\033[1;36m*Enabling openstack 7.0 and other dependent repos*\033[1;m"
subprocess.call(['subscription-manager', 'repos', '--enable=rhel-7-server-rpms'])
subprocess.call(['subscription-manager', 'repos', '--enable=rhel-7-server-rh-common-rpms'])
subprocess.call(['subscription-manager', 'repos', '--enable=rhel-7-server-openstack-7.0-rpms'])

#Disable NetworkManager
print "\033[1;36m*Disabling NetworkManager*\033[1;m"
subprocess.call(['systemctl', 'disable', 'NetworkManager'])

#Install openstack with packstack
print "\033[1;36m*Subscription completed. Packstack installation begins*\033[1;m"
subprocess.call(['yum', 'install', '-y', 'openstack-packstack'])
subprocess.call(['packstack', '--allinone'])


