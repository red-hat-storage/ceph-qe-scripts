from lib.nova import NovaAuth, NovaActions
from lib.glance import GlanceAuth, GlanceActions
from lib.cinder import CinderAuth, CinderVolumes
import lib.log as log
from lib.test_desc import AddTestInfo
from utils import wait
import time


class GlanceCycle(object):

    def __init__(self, glance):

        self.timer = wait.Wait()
        self.glance_image = GlanceActions(glance.glance)
        self.img = None

    def image_create(self, name):

        add_test_info.sub_test_info('1', 'create glance image')
        image = self.glance_image.upload_images(name=name)
        assert image.status, 'Image creation failure'
        log.info('image name: %s' % image.image.name)
        self.timer.wait_for_state_change(image.image.status, 'queued')
        img = self.glance_image.get_image(image.image)
        self.img = img.image
        log.info('Image created')
        add_test_info.sub_test_completed_info()
        return self.img


class CinderCycle(object):

    def __init__(self, cinder):

        self.timer = wait.Wait()
        self.cinder_vol = CinderVolumes(cinder.cinder)
        self.volume = None

    def vol_create(self, name, size):

        add_test_info.sub_test_info('1', 'create_volume')
        init_create_volume = self.cinder_vol.create_volume(name, size)
        assert init_create_volume.status, "Volume create initialize error"
        log.info('volume name: %s' % init_create_volume.vol.name)
        self.timer.wait_for_state_change(init_create_volume.vol.status, 'creating')
        volume = self.cinder_vol.get_volume(init_create_volume.vol)
        self.volume = volume.volume
        log.info('Volume exists')
        add_test_info.sub_test_completed_info()
        return self.volume


class NovaCycle(object):

    def __init__(self, nova):

        self.timer = wait.Wait()
        self.nova_server = NovaActions(nova.nova)
        self.vm = None

    def boot_server(self, image, name):

        add_test_info.sub_test_info('1', 'Create VM')
        vm = self.nova_server.boot_vm(image=image, name=name)
        assert vm.status, 'Vm creation initialization error'
        log.info('server name: %s' % vm.server.name)
        self.timer.wait_for_state_change(vm.server.status, 'BUILD')
        time.sleep(10)
        self.vm = self.nova_server.vm_details(vm.server)
        log.debug('status: %s' % self.vm.vm.status)
        log.info('VM created')
        add_test_info.sub_test_completed_info()

    def attach_vol(self, volume, device):

        add_test_info.sub_test_info('2', 'Attach volume to VM')
        attached_volume = self.nova_server.attach_volume(self.vm.vm.id, volume=volume.id, device=device)
        time.sleep(10)

        if attached_volume:
            log.debug('volume %s attached to server %s' % (attached_volume.vol.volumeId, self.vm.vm.name))
            log.info('Volume attached to VM successfully')
        else:
            log.error('volume attach failed')

        add_test_info.sub_test_completed_info()

"""
    def delete_server(self):

        add_test_info.sub_test_info('2', 'delete vm')

        vm_to_delete = self.nova_server.vm_delete(self.vm.vm)
        assert vm_to_delete.execute, 'VM deletion error'
        vm_exists = self.nova_server.vm_details(self.vm.vm)
        self.timer.wait_for_state_change(vm_exists.vm.status, 'ACTIVE')

        log.info('status: %s' % vm_exists.vm.status)
        time.sleep(10)

        vm_exists = self.nova_server.vm_details(self.vm.vm)

        if not vm_exists.status:
            log.info('VM deleted')
        else:
            log.error('VM status: %s' % vm_exists.vm.status)
            raise AssertionError("VM still exists")

        add_test_info.sub_test_completed_info()
"""


def exec_test():

    global add_test_info

    add_test_info = AddTestInfo(1, 'Nova server create test')

    try:

        add_test_info.started_info()
        nova = NovaAuth()
        nova = nova.auth()
        glance = GlanceAuth()
        glance = glance.auth()
        cinder = CinderAuth()
        cinder = cinder.auth()

        assert nova.status, "Nova authentication failed"

        assert glance.status, "Glance authentication failed"

        assert cinder.status, "Cinder authentication failed"

        nova_cycle = NovaCycle(nova)
        glance_cycle = GlanceCycle(glance)
        volume_cycle = CinderCycle(cinder)
        image = glance_cycle.image_create(name='testimg')
        volume = volume_cycle.vol_create('testvol', 2)
        nova_cycle.boot_server(image=image, name='testvm')
        nova_cycle.attach_vol(volume, device='/dev/vdc')

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')

    add_test_info.completed_info()


if __name__ == "__main__":

    exec_test()