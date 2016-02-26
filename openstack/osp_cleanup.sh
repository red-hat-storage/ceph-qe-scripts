echo "---------------Cleaning up Openstack Installation--------------"
sudo yum remove openstack-* -y
sudo yum remove redhat-access-plugin-openstack-7.0.0-0.el7ost.noarch  python-django-openstack-auth-1.2.0-5.el7ost.noarch python-openstackclient-1.0.3-3.el7ost.noarch -y
sudo rm -rf packstack-answers-*
sudo rm -rf keystonerc*
sudo rm -rf /var/lib/cinder
sudo rm -rf ceph-qe-scripts co.log conf_admin.log ios.log cephtest
echo "---------------Remove complete----------"