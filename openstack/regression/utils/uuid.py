from subprocess import Popen, PIPE
import os


def uuid_gen():

    cmd = "uuidgen"
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    return out.rstrip()


def secret_xml():
    uuid = uuid_gen()
    cmd = "cat > /root/secret.xml <<EOF\n<secret ephemeral='no' private='no'>\n<uuid>%s</uuid>" \
          "\n<usage type='ceph'>\n<name>client.cinder secret</name>\n</usage>\n</secret>\nEOF" % uuid
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    return out.rstrip()


def secret_define():
    uuid = uuid_gen()
    cmd = "sudo virsh secret-define --file secret.xml"
    p = Popen(cmd, shell=True, stdout=PIPE, stderr=PIPE)
    out, err = p.communicate()
    cmd1 = "sudo virsh secret-set-value --secret %s " \
           "--base64 $(cat client.cinder.key) && rm client.cinder.key && rm secret.xml" % uuid
    p1 = Popen(cmd1, shell=True, stdout=PIPE, stderr=PIPE)
    out1, err1 = p1.communicate()
    return out.rstrip(), out1.rstrip()


def get_val_from_keystonerc_admin(keystone_rc_path ="/root/keystonerc_admin", key=None):

    keyname = 'export ' + key

    myvars = {}
    with open(keystone_rc_path) as myfile:
        for line in myfile:
            name, var = line.partition("=")[::2]
            myvars[name.strip()] = var

    val = (myvars[keyname]).rstrip()

    return val


def set_env():

    # del os.environ['OS_SERVICE_TOKEN']

    os.environ["OS_USERNAME"] = get_val_from_keystonerc_admin(key="OS_USERNAME")
    os.environ["OS_PASSWORD"] = get_val_from_keystonerc_admin(key="OS_PASSWORD")
    os.environ["OS_AUTH_URL"] = get_val_from_keystonerc_admin(key="OS_AUTH_URL")
    os.environ["PS1"] = get_val_from_keystonerc_admin(key="PS1")
    os.environ["OS_TENANT_NAME"] = get_val_from_keystonerc_admin(key="OS_TENANT_NAME")
    os.environ["OS_REGION_NAME"] = get_val_from_keystonerc_admin(key="OS_REGION_NAME")


