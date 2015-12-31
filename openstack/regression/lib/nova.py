import os
import novaclient.v2.client as nvclient
import random
import log
from glance import Glance
from cinder import Cinder
import time


class Nova:

    def __init__(self):
        nv = {}
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
            log.info("Listing all servers")
            return servers
        else:
            log.info("No servers to list")

    def boot_vm(self, image):
        glance = Glance()
        img = glance.get_image(image)
        vm_name = "test-vm-" + str(random.randint(1, 20))
        log.info("Creating instance from image %s" % img)
        vm = self.nova.servers.create(name=vm_name, image=img, nics=self.nics, availability_zone='nova',
                                      flavor=self.flavor)
        log.info("Successfully created instance %s from %s " % (vm_name, img))
        return vm

    def delete_vm(self, server):
        log.info("Deleting nova instance")
        vm = self.nova.servers.find(name=server)
        self.nova.servers.delete(vm)

    def vm_details(self, server):
        log.info("Get instance info")
        vm = self.nova.servers.find(name=server)
        return vm

    def boot_from_snap(self, server):
        log.info("Creating snapshot of instance %s" % server)
        vm = self.nova.servers.find(name=server)
        image = vm.name + "-snap"
        nova_snap = self.nova.servers.create_image(vm, image_name=image)
        glance = Glance()
        snap = glance.get_image_by_name(image_id=nova_snap)
        time.sleep(10)
        img = glance.get_image(snap)
        vm_name = snap + '-vm'
        log.info("Creating instance from nova snapshot %s " % snap)
        vm = self.nova.servers.create(name=vm_name, image=img, flavor=self.flavor, availability_zone='nova',
                                      nics=self.nics)
        log.info("Successfully created instance %s from snapshot %s " % (vm, snap))
        return vm

    def extract_name(self, server):
        vm = self.nova.servers.find(name=server)
        return vm.id

    def volume_attach(self, server, volume):
        cinder = Cinder()
        vol = cinder.get_volume(volume)
        vm = self.extract_name(server)
        log.info("Attaching volume %s to server %s" % (volume, vm))
        self.nova.volumes.create_server_volume(vm, vol, device='/dev/vdc')

    def volume_detach(self, server, volume):
        cinder = Cinder()
        vol = cinder.get_volume(volume)
        vm = self.extract_name(server)
        log.info("Detaching volume %s from server %s" % (vol, vm))
        self.nova.volumes.delete_server_volume(vm, vol)













