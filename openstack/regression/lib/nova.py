import os
import novaclient.v2.client as nvclient
import random


class Nova:
    def __init__(self):
        nv= {}
        nv['username'] = os.environ['OS_USERNAME']
        nv['api_key'] = os.environ['OS_PASSWORD']
        nv['auth_url'] = os.environ['OS_AUTH_URL']
        nv['project_id'] = os.environ['OS_TENANT_NAME']
        self.nova = nvclient.Client(**nv)

        self.flavor = self.nova.flavors.findall(name='m1.medium')[0]
        network = self.nova.networks.findall(label='private')[0]
        self.nics = [{'net-id': network.id}]

    def list_nova(self):
        servers = self.nova.servers.list()
        if servers:
            return servers

    def boot_vm(self):
        image = self.nova.images.findall(name='cirros-test')[0]
        vm_name = "test-vm-" + str(random.randint(1, 20))
        vm = self.nova.servers.create(name=vm_name, image=image, nics=self.nics, availability_zone='nova',
                                      flavor=self.flavor)
        return vm.id

    def delete_vm(self, server):
        self.nova.servers.delete(server)

    def vm_details(self, server):
        return self.nova.servers.get(server)

    def volume_attach(self, server, volume):
        if volume.status == "available":
            self.nova.volumes.create_server_volume(server, volume)
            return server, volume
        else:
            print "Failed to attach volume. %s is not available" % volume

    def volume_detach(self, server, volume):
        self.nova.volumes.delete_server_volume(server, volume)

    def create_snap(self, server):
        self.image = server + "-snap"
        self.nova_snap = self.nova.servers.create_image(server, image_name=image)
        return self.nova_snap.id, self.image

    def boot_from_snap(self):
        vm_name = self.nova_snap.id + "vm"
        self.nova.servers.create(name=vm_name, image=self.image, flavor=self.flavor, nics=self.nics)
















