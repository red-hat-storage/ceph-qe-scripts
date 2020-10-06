#!/usr/bin/python3
import boto.s3.connection
import boto
from subprocess import PIPE, Popen
import time
import os
import requests
import subprocess
from configparser import ConfigParser
parser = ConfigParser()


def cmdline(command):
    process = Popen(
        args=command,
        stdout=PIPE,
        shell=True
    )
    return process.communicate()[0].decode()


def rgwops():

    unique_id = time.strftime("%Y%m%d%H%M%S")
    user = f"operator_{unique_id}"
    disp_name = f"s3 {user}"
    email = f"{user}@example.com"
    access_key = '123451'
    secret_key = '678901'
    hostname = os.uname()[1]


    # create user , named = operator_unique_id
    admin_create_command = f"""radosgw-admin user create --uid="{user}" --display-name="{disp_name}" \
    --email="{email}" --access_key="{access_key}" --secret="{secret_key}" """
    cmdline(admin_create_command)

    # create bucket named = test_unique_id and upload some objects
    conn = boto.connect_s3(
        aws_access_key_id = access_key,
         aws_secret_access_key = secret_key,
        host = hostname,
         port = 8080,
        is_secure=False,               # uncomment if you are not using ssl

        calling_format = boto.s3.connection.OrdinaryCallingFormat(),
        )

    bkt_name = f"test1_{unique_id}"
    bucket = conn.create_bucket(bkt_name)
    bucket = conn.get_bucket(bkt_name)

    #bucket.configure_versioning(versioning=True)
    config = bucket.get_versioning_status()
    print(config)

    for i in range(1, 10):
        creat_name = 'logC_' + str(i)
        print("creating object" + creat_name)
        key = bucket.new_key(creat_name+'/')
        key.set_contents_from_string('hello how are you')

    # install and setup s3cmd for the above user
    print('It will create a file as /root/.s3cfg_{}'.format(user))
    s3cmd_configure = os.system('s3cmd --configure --dump-config > /root/.s3cfg_{}'.format(user))
    print(s3cmd_configure)
    print('Make some changes to .s3cfg file')
    port_number = '8080'
    os.system(
        'sed -i -e \'s,^host_base *=.*,host_base = http://{}:{},;s,host_bucket *=.*,host_bucket = http://{}:{},;s, \
        website_endpoint *=.*,website_endpoint = http://%(bucket)s.{}-%(location)s,;s,access_key *=.*,access_key = {},\
        ;s,secret_key *=.*,secret_key = {},;s,use_https *=.*,use_https = False,;s,gpg_command *=.*,gpg_command = /usr/bin/gpg,\
        ;s,progress_meter *=.*,progress_meter = True,;s,proxy_port *=.*,proxy_port = 0,\' /root/.s3cfg_{}'.format(
            hostname, port_number, hostname, port_number, hostname, access_key, secret_key, user))
    s3cmd_work = os.system('s3cmd ls -c /root/.s3cfg_{}'.format(user))
    exit_status = os.system('echo $?')
    if exit_status == 0:
        print("Bucket list above and below")
    else:
        os.system(
            'sed -i -e \'s,^host_base *=.*,host_base = http://{}:80,;s,host_bucket *=.*,host_bucket = http://{}:80,;s, \
            website_endpoint *=.*,website_endpoint = http://%(bucket)s.{}-%(location)s,;s,access_key *=.*,access_key = {},\
            ;s,secret_key *=.*,secret_key = {},;s,use_https *=.*,use_https = False,;s,gpg_command *=.*,gpg_command = /usr/bin/gpg,\
            ;s,progress_meter *=.*,progress_meter = True,;s,proxy_port *=.*,proxy_port = 0,\' /root/.s3cfg_{}'.format(
                hostname, hostname, hostname, access_key, secret_key, user))
    s3cmd_work = os.system('s3cmd ls -c /root/.s3cfg_{}'.format(user))
    print(s3cmd_work)

    # check the acl info of the bucket created
    acl_info_check(bkt_name, user)

    # setacl --public-read
    acl_set = f"s3cmd setacl --acl-public s3://{bkt_name} -c .s3cfg_{user}"
    print(cmdline(acl_set))

    # after setting acl , again check the info
    acl_info_check(bkt_name, user)

    # change the conf file
    ceph_conf_change(hostname)

    # restart and status
    restart_and_status(hostname)

    # curl url from s3cmd info
    # install package requests - if using requests

    URL = f"http://{hostname}:8080/{bkt_name}/"
    print(URL)
    print(type(URL))

    # check the time
    time.sleep(5)
    get_time = time.strftime("%H:%M:%S")
    print(get_time)
    d1 = '1 min ago'
    d2 = '+\'%T\''
    completed = subprocess.run(['date', d2, '-d', d1], stdout=subprocess.PIPE, )
    date_1 = completed.stdout.decode('utf-8').strip(' \' , \n')
    print(date_1)

    r = requests.get(url=URL)
    print("The response is ::", r)


    # regex uid+anonymous part search where grep for current min and 1 min back for the perfect scenario and match
    str_check = "uid+anonymous"
    grep_file = f"grep -A 200 -e {date_1} -e {get_time} /var/log/ceph/ceph-rgw-{hostname}.rgw0.log | grep {str_check}"
    print(cmdline(grep_file))

    # delete user and remove .s3cfg file after search
    del_user = f"radosgw-admin user rm --uid={user} --purge-data"
    cmdline(del_user)
    remove_s3cfg_file = f"rm -rf .s3cfg_{user}"
    cmdline(remove_s3cfg_file)

    # reset the conf changes
    reset_conf_change(hostname)

    # restart and status
    restart_and_status(hostname)


def ceph_conf_change(hostname):
    # set the debug rgw = 20 , debug ms = 1,  in the .rgw0 instance
    file_name = '/etc/ceph/ceph.conf'
    section_name = 'client.rgw.{}.rgw0'.format(hostname)
    parser.read(file_name)
    parser.set(section_name, 'debug ms', '1')
    parser.set(section_name, 'debug rgw', '20')
    with open(file_name, 'w') as f:
        parser.write(f)
    f.close()
    print(parser.get(section_name, 'debug ms'))
    print(parser.get(section_name, 'debug rgw'))


def reset_conf_change(hostname):
    file_name = '/etc/ceph/ceph.conf'
    section_name = 'client.rgw.{}.rgw0'.format(hostname)
    parser.read(file_name)
    parser.remove_option(section_name, 'debug ms')
    parser.remove_option(section_name, 'debug rgw')
    with open(file_name, 'w') as f:
        parser.write(f)
    f.close()


def restart_and_status(hostname):
    # restart the rgw
    restart_rgw = f"systemctl restart ceph-radosgw@rgw.{hostname}.rgw0.service"
    cmdline(restart_rgw)
    # status of rgw
    status_rgw = f"systemctl status ceph-radosgw@rgw.{hostname}.rgw0.service"
    print(cmdline(status_rgw))


def acl_info_check(bkt_name, user):
    # check the acl info of the bucket created
    acl_check = f"s3cmd info s3://{bkt_name} -c .s3cfg_{user}"
    print(cmdline(acl_check))


if __name__ == '__main__':
    rgwops()

