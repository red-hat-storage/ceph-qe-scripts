"""
Create a VM, take a snapshot, boot a VM out of the snap. Clean up the image, VM, snapshot instances
"""


from lib.nova import NovaAuth, NovaActions
from lib.glance import GlanceAuth, GlanceActions
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

        add_test_info.sub_test_info('1', 'Create glance image')
        self.image = self.glance_image.upload_images(name=name)
        assert self.image.status, 'Image creation failure'
        log.info('image name: %s' % self.image.image.name)
        self.timer.wait_for_state_change(self.image.image.status, 'queued')
        img = self.glance_image.get_image(self.image.image)
        self.img = img.image
        log.info('Image created')
        add_test_info.sub_test_completed_info()
        return self.img

    def image_delete(self):

        add_test_info.sub_test_info('7', 'Delete glance image')

        image_to_delete = self.glance_image.delete_image(self.img.id)
        assert image_to_delete.execute, 'Image deletion failure'
        self.timer.wait_for_state_change(self.image.image.status, 'active')

        image_exists = self.glance_image.get_image(self.image.image)

        if not image_exists.status:
            log.info('Image deleted')
        else:
            log.error('Image status: %s' % image_exists.image.status)
            raise AssertionError("Image still exists")

        add_test_info.sub_test_completed_info()


class NovaCycle(object):

    def __init__(self, nova):

        self.timer = wait.Wait()
        self.nova_server = NovaActions(nova.nova)
        self.vm = None

    def boot_server(self, image, name):

        add_test_info.sub_test_info('2', 'Create VM')
        vm = self.nova_server.boot_vm(image=image, name=name)
        assert vm.status, 'Vm creation initialization error'
        log.info('server name: %s' % vm.server.name)
        self.timer.wait_for_state_change(vm.server.status, 'BUILD')
        self.vm = self.nova_server.vm_details(vm.server)
        log.debug('status: %s' % self.vm.vm.status)
        log.info('VM created')

        add_test_info.sub_test_completed_info()
        return self.vm.vm

    def create_snap(self, name):

        add_test_info.sub_test_info('3', 'Create VM snap')
        snapshot = self.nova_server.vm_snap(self.vm.vm, name=name)
        assert snapshot.status, 'Vm snap creation error'
        self.snap = self.nova_server.get_snap(snapshot.snap)
        log.info('VM snap name: %s' % self.snap.snap.name)
        time.sleep(10)
        self.timer.wait_for_state_change(self.snap.snap.status, 'SAVING')
        if self.snap:
            log.info('Snap %s created' % self.snap)
        else:
            log.error('Snap creation failed')

        add_test_info.sub_test_completed_info()

    def boot_from_snap(self, name):

        add_test_info.sub_test_info('4', 'Boot VM from snap')
        server = self.nova_server.boot_from_snap(self.snap.snap.id, name=name)
        assert server.status, 'VM frm snap creation successful'
        log.info('VM name: %s' % server.server.name)
        self.timer.wait_for_state_change(server.server.status, 'BUILD')
        vm = self.nova_server.vm_details(server.server)
        log.debug('status: %s' % vm.vm.status)
        log.info('VM from snap created')

        add_test_info.sub_test_completed_info()
        return vm.vm

    def delete_server(self, server):

        add_test_info.sub_test_info('5', 'Delete VM')

        vm_to_delete = self.nova_server.vm_delete(server)
        assert vm_to_delete.execute, 'VM deletion error'
        vm_exists = self.nova_server.vm_details(server)
        self.timer.wait_for_state_change(vm_exists.vm.status, 'ACTIVE')

        log.info('status: %s' % vm_exists.vm.status)
        time.sleep(10)

        vm_exists = self.nova_server.vm_details(server)

        if not vm_exists.status:
            log.info('VM deleted')
        else:
            log.error('VM status: %s' % vm_exists.vm.status)
            raise AssertionError("VM still exists")

        add_test_info.sub_test_completed_info()

    def delete_snap(self):

        add_test_info.sub_test_info('6', 'Delete VM snap')
        snap_to_delete = self.nova_server.snap_delete(self.snap.snap)
        assert snap_to_delete.execute, 'Snap deletion error'
        snapshot = self.nova_server.get_snap(self.snap.snap)
        self.timer.wait_for_state_change(snapshot.snap.status, 'ACTIVE')

        log.info('status: %s' % snapshot.snap.status)

        snap_exists = self.nova_server.get_snap(self.snap.snap)

        if snap_exists.snap.status == 'DELETED':
            log.info('VM snap deleted')
        else:
            log.error('Snap status: %s' % snap_exists.snap.status)
            raise AssertionError('VM snap still exists')

        add_test_info.sub_test_completed_info()


def exec_test():

    global add_test_info

    add_test_info = AddTestInfo(8, 'Nova server create test')

    try:

        add_test_info.started_info()
        nova = NovaAuth()
        nova = nova.auth()
        glance = GlanceAuth()
        glance = glance.auth()

        assert nova.status, "Nova authentication Failed"

        assert glance.status, "Glance authentication failed"

        nova_cycle = NovaCycle(nova)
        glance_cycle = GlanceCycle(glance)
        image = glance_cycle.image_create(name='testimg')
        source_server = nova_cycle.boot_server(image=image, name='testvm')
        nova_cycle.create_snap(name='testvm-snap')
        snap_server = nova_cycle.boot_from_snap(name='snap-vm')
        nova_cycle.delete_server(snap_server)
        nova_cycle.delete_snap()
        nova_cycle.delete_server(source_server)
        glance_cycle.image_delete()

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')

    add_test_info.completed_info()


if __name__ == "__main__":

    exec_test()