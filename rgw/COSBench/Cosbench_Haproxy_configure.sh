#!/bin/bash

# Install and Unpack Cosbench on the Controller and Driver nodes
# Install HAProxy on the Driver nodes
# Requires [controller] and [drivers] sections to be populated in /etc/ansible/hosts

echo "Installing Cosbench on Controller"
ansible controller -m shell -a "yum install nc java-1.8.0-openjdk.x86_64 unzip -y"

echo "Installing Cosbench on Drivers"
ansible drivers -m shell -a "yum install nc java-1.8.0-openjdk.x86_64 unzip -y"

#disable Iptables and Firewall
ansible controller -m shell -a "systemctl stop iptables; systemctl disable iptables"
ansible drivers -m shell -a "systemctl stop iptables; systemctl disable iptables"

ansible controller -m shell -a "systemctl stop firewalld; systemctl disable firewalld"
ansible drivers -m shell -a "systemctl stop firewalld; systemctl disable firewalld"

#Download Cosbench
ansible controller -m shell -a "wget https://github.com/intel-cloud/cosbench/releases/download/v0.4.2.c4/0.4.2.c4.zip"
ansible drivers -m shell -a "wget https://github.com/intel-cloud/cosbench/releases/download/v0.4.2.c4/0.4.2.c4.zip"

#Unzip and configure executable
ansible controller -m shell -a "unzip 0.4.2.c4.zip"
ansible drivers -m shell -a "unzip 0.4.2.c4.zip"

ansible controller -m shell -a "cd 0.4.2.c4; chmod 755 *.sh"
ansible drivers -m shell -a "cd 0.4.2.c4; chmod 755 *.sh"

echo " Installing HAproxy on the driver nodes"
ansible controller -m shell -a "yum install haproxy -y"
ansible drivers -m shell -a "yum install haproxy -y"

echo "Installation complete"
echo "Configure the driver details in conf/controller.conf on the Controller Node"
echo "Configure /etc/haproxy/haproxy.cfg with the Frontend and Backend details on the Controller node"
echo "Run the below commands"
echo "ansible drivers -m shell -a \"cd /root/v0.4.2.c4;./start-driver.sh"\"
echo "ansible controller -m shell -a \"cd /root/v0.4.2.c4; ./start-controller.sh"\"
echo "ansible drivers -m copy -a \“src=/root/haproxy.cfg dest=/etc/haproxy/haproxy.cfg”\"
echo "ansible drivers -m shell -a \"systemctl start haproxy"\"
