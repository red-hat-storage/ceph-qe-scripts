import os
import novaclient.v2.client as nv_client
import novaclient.exceptions as nv_exceptions
import log


class NovaReturnStack(object):
    def __init__(self):
        pass


class NovaAuth(object):

    def __init__(self):

        self.nv = {}
        self.nv['username'] = os.environ['OS_USERNAME']
        self.nv['api_key'] = os.environ['OS_PASSWORD']
        self.nv['auth_url'] = os.environ['OS_AUTH_URL']
        self.nv['project_id'] = os.environ['OS_TENANT_NAME']

    def auth(self):

        """

        :return:auth_stack
                - auth_stack.nova : nova object after authenticating
                - auth_stack.status : True or False

        """

        auth_stack = NovaReturnStack()

        log.info('Authenticating nova')

        try:
            nova = nv_client.Client(**self.nv)

            auth_stack.nova, auth_stack.status = nova, True

            log.info('Nova Auth successful')

        except nv_exceptions.AuthorizationFailure, e:
            auth_stack.nova, auth_stack.status = None, False
            log.error('Nova auth failed')
            log.error(e.message)

        return auth_stack


class NovaActions(object):

    def __init__(self, nova_auth):
        self.nova = nova_auth
        self.flavor = self.nova.flavors.findall(name='m1.small')[0]
        network = self.nova.networks.findall(label='private')[0]
        self.nics = [{'net-id': network.id}]

    def boot_vm(self, name, image=None, volume_id=None, **kwargs):

        """

        :param image: glance image object(if boot from image)
        :param name: string
        :param volume_id: volume object uuid(if boot from volume)
        :return: nova_boot.vm: vm object
                 nova_boot.status: True or False

        """

        log.info("Creating nova instance")

        nova_boot = NovaReturnStack()

        boot_kwargs = dict(**kwargs)

        if image:
            boot_kwargs['image'] = image
        else:
            boot_kwargs['volume_id'] = volume_id

        try:
            log.info('Initializing vm creating')

            if volume_id:
                log.info('Booting vm from volume')
                bdm = [
                    {'source_type': 'volume', 'uuid': volume_id, 'destination_type': 'volume',
                     'boot_index': '0'}
                ]
                server = self.nova.servers.create(name=name, image='',
                                                  block_device_mapping_v2=bdm, nics=self.nics, availability_zone='nova',
                                                  flavor=self.flavor)
                nova_boot.server, nova_boot.status = server, True
            else:
                log.info('Booting vm from image')
                server = self.nova.servers.create(name=name, image=image, nics=self.nics, availability_zone='nova',
                                                  flavor=self.flavor)
                nova_boot.server, nova_boot.status = server, True

        except nv_exceptions.ClientException, e:
            log.error(e)
            nova_boot.vm, nova_boot.status = None, False

        return nova_boot

    def list_vms(self):

        """

        :return: nova_list
                nova_list.vms : list of vm instances
                nova_list.status: True or False
        """

        nova_list = NovaReturnStack()

        nova_list.vms = []

        try:
            log.info("List nova instances")
            servers = self.nova.servers.list()
            nova_list.status = True
            if servers:
                return nova_list.vms == servers

        except nv_exceptions.ClientException, e:
            log.error(e)
            nova_list.status = False

        return nova_list

    def vm_delete(self, server):

        """

        :param server: vm object
        :return: vm_delete
                vm_delete.execute: True or False

        """

        vm_delete = NovaReturnStack()
        vm_delete.execute = False

        try:
            log.info("Deleting nova instance")
            self.nova.servers.delete(server)
            vm_delete.execute = True
            log.info('delete instance executed')

        except (nv_exceptions.ClientException, nv_exceptions.NotFound), e:
            log.error(e)
            vm_delete.execute = False

        return  vm_delete

    def vm_details(self, server):

        """

        :param server: server object
        :return: vm_info
                vm_info.vm : vm object
                vm_info.status:  True or False
        """

        vm_info = NovaReturnStack()
        vm_info.vm = None

        try:
            log.info("Get instance info")
            vm = self.nova.servers.get(server=server)
            vm_info.vm, vm_info.status = vm, True

        except (nv_exceptions.ClientException, nv_exceptions.NotFound), e:
            log.error(e)
            vm_info.status = False

        return vm_info

    def vm_snap(self, server, name):

        """

        :param server: vm object
        :param name: string
        :return: snap_create
                    snap_create.snap: vm snap object
                    snap_create.status: True or False

        """

        snap_create = NovaReturnStack()
        snap_create.snap = None

        try:
            log.info("Creating snapshot of instance %s")
            nova_snap = self.nova.servers.create_image(server, image_name=name)
            snap_create.snap, snap_create.status = nova_snap, True

        except nv_exceptions.ClientException, e:
            log.error(e)
            snap_create.status = False

        return snap_create

    def boot_from_snap(self, snap, name):

        """

        :param snap: vm snap object from vm_snap()
        :param name: string
        :return: snap_vm
                    snap_vm.server: server object
                    snap_vm.status: True or False


        """

        snap_vm = NovaReturnStack()
        snap_vm.server = None

        try:
            log.info("Creating instance from nova snapshot")
            server = self.nova.servers.create(name=name, image=snap, flavor=self.flavor, availability_zone='nova',
                                              nics=self.nics)
            snap_vm.server, snap_vm.status = server, True

        except nv_exceptions.ClientException, e:
            log.error(e)
            snap_vm.status = False

        return snap_vm

    def attach_volume(self, server, volume, device):

        """

        :param server: vm object
        :param volume: cinder volume object
        :param device: string
        :return: volume_attach

        """

        volume_attach = NovaReturnStack()
        volume_attach.vol = None

        try:
            log.info("Attaching volume to server")
            volume = self.nova.volumes.create_server_volume(server, volume, device=device)
            volume_attach.vol, volume_attach.status = volume, True
        except (nv_exceptions.ClientException, nv_exceptions.ResourceNotFound), e:
            log.error(e)
            volume_attach.status = False

        return volume_attach

    def detach_volume(self, server, volume):

        """

        :param server: vm object
        :param volume: cinder volume object
        :return: volume_detach

        """

        volume_detach = NovaReturnStack()

        try:
            log.info("Detaching volume from server")
            self.nova.volumes.delete_server_volume(server, volume)
            volume_detach.status = True
        except (nv_exceptions.ClientException, nv_exceptions.ResourceNotFound), e:
            log.error(e)
            volume_detach.status = False

        return volume_detach











