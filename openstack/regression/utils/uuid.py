from subprocess import Popen, PIPE


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



