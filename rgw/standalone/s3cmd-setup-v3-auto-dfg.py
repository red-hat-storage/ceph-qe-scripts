#!/usr/bin/python3
'''
> download this script for auto configure s3cmd and create a bucket and upload 3 types of files.
> use - chmod +x script_name.py and then run - ./script_name.py
> compatible with python version 3
> script functionalities
        - enable epel
        - install python2-pip, upgarde pip, install s3cmd
        - create a user = 'operator'
        - configure .s3cfg file
        - create 3 files(500kb, 500mb, 4gb) and upload that in bucket (with 50000 objects)
        - delete 3 files created in the system
'''
import os, sys, random
print('enable the epel repo or by default it may be installed')
enable_epel = os.system('yum-config-manager --enable epel')
print(enable_epel)
print("----------------------------------------------------------------------")
install_python3_pip = os.system('yum install python3-pip -y')
print(install_python3_pip)
print("----------------------------------------------------------------------")
upgrade_pip = os.system('pip3 install --upgrade pip')
print(upgrade_pip)
print("----------------------------------------------------------------------")
install_s3cmd = os.system('yum install s3cmd -y; pip3 install s3cmd')
print(install_s3cmd)
print("----------------------------------------------------------------------")
access_key='12345'
secret_key='67890'
create_user = os.system("radosgw-admin user create --uid=\"operator\" --display-name=\"S3 Operator\" --email=\"operator@example.com\" --access_key={} --secret={}".format(access_key, secret_key))
print(create_user)
print("----------------------------------------------------------------------")
print('It will remove the default /root/.s3cfg file')
s3cmd_configure = os.system('s3cmd --configure --dump-config > /root/.s3cfg')
print(s3cmd_configure)
print("----------------------------------------------------------------------")
print('Make some changes to .s3cfg file')
hostname = os.uname()[1]
port_number='8080'
os.system('sed -i -e \'s,^host_base *=.*,host_base = http://{}:{},;s,host_bucket *=.*,host_bucket = http://{}:{},;s,website_endpoint *=.*,website_endpoint = http://%(bucket)s.{}-%(location)s,;s,access_key *=.*,access_key = {},;s,secret_key *=.*,secret_key = {},;s,use_https *=.*,use_https = False,;s,gpg_command *=.*,gpg_command = /usr/bin/gpg,;s,progress_meter *=.*,progress_meter = True,;s,proxy_port *=.*,proxy_port = 0,\' /root/.s3cfg'.format(hostname, port_number, hostname, port_number, hostname, access_key, secret_key))
s3cmd_work = os.system('s3cmd ls')
exit_status = os.system('echo $?')
if exit_status == 0:
        print(port_number)
else:
        os.system('sed -i -e \'s,^host_base *=.*,host_base = http://{}:80,;s,host_bucket *=.*,host_bucket = http://{}:80,;s,website_endpoint *=.*,website_endpoint = http://%(bucket)s.{}-%(location)s,;s,access_key *=.*,access_key = {},;s,secret_key *=.*,secret_key = {},;s,use_https *=.*,use_https = False,;s,gpg_command *=.*,gpg_command = /usr/bin/gpg,;s,progress_meter *=.*,progress_meter = True,;s,proxy_port *=.*,proxy_port = 0,\' /root/.s3cfg'.format(hostname, hostname, hostname, access_key, secret_key))
s3cmd_work = os.system('s3cmd ls')
print(s3cmd_work)
print("----------------------------------------------------------------------")
print('Create a bucket')
random_letter = random.randint(1,1000)
random_letter_convert = str(random_letter)
bkt_name = hostname+random_letter_convert
bkt_create = os.system('s3cmd mb s3://{}'.format(bkt_name))
print(s3cmd_work)
print('Bucket created with name as {}'.format(bkt_name))
print("----------------------------------------------------------------------")
print('Create 3 files of 3 diff sizes')
file1="f1"
file2="f2"
file3="f3"
file_name1 = hostname+random_letter_convert+file1
file_name2 = hostname+random_letter_convert+file2
file_name3 = hostname+random_letter_convert+file3

file_create1 = os.system('head -c 500KB /dev/zero > {}'.format(file_name1))
file_created1 = os.system('ls -l  {}'.format(file_name1))
print(file_created1)

file_create2 = os.system('head -c 500MB /dev/zero > {}'.format(file_name2))
file_created2 = os.system('ls -l  {}'.format(file_name2))
print(file_created2)

file_create3 = os.system('head -c 4GB /dev/zero > {}'.format(file_name3))
file_created3 = os.system('ls -l  {}'.format(file_name3))
print(file_created3)

print("----------------------------------------------------------------------")
print('Upload above file on that created bucket')
for i in range(1,25001):
        os.system('s3cmd put {} s3://{}/{}{}.iso'.format(file_name1, bkt_name, file_name1, i))
print('1 set done')
for i in range(1,15001):
        os.system('s3cmd put {} s3://{}/{}{}.iso'.format(file_name2, bkt_name, file_name2, i))
print('2 set done')
for i in range(1,10001):
        os.system('s3cmd put {} s3://{}/{}{}.iso'.format(file_name3, bkt_name, file_name3, i))
print('3 set done')
print("Press ENTER once the uploading is done")
print("----------------------------------------------------------------------")
print('Object deleted that was created to upload')
file_delete = os.system('rm -rf {}'.format(file_name1))
file_delete = os.system('rm -rf {}'.format(file_name2))
file_delete = os.system('rm -rf {}'.format(file_name3))
print(file_delete)
print("------------------------RGW IO OPERATION DONE---------------------------------")
