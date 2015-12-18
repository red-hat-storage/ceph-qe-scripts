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

    def list_nova(self):
        servers = self.nova.servers.list()
        if servers:
            return servers

    def boot_vm(self):
        flavor = self.nova.flavors.findall(name='m1.medium')[0]
        network = self.nova.networks.findall(label='private')[0]
        nics = [{'net-id': network.id}]
        image = self.nova.images.findall(name='cirros-test')[0]
        vm_name = "test-vm-" + str(random.randint(1, 20))
        vm = self.nova.servers.create(name=vm_name, image=image, nics=nics, availability_zone='nova',
                                      flavor=flavor)
        return vm.id

    def delete_vm(self, server):
        self.nova.servers.delete(server)

    def vm_details(self, server):
        return self.nova.servers.get(server)












