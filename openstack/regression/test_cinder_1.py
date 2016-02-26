"""
Create volume, extend the volume and delete it
"""


import lib.log as log
from lib.cinder import CinderAuth, CinderVolumes
from lib.test_desc import AddTestInfo
from utils import wait, uuid
import sys




class CinderVolumeTest(object):
    def __init__(self, cinder):
        self.timer = wait.Wait()
        self.cinder_volume = CinderVolumes(cinder.cinder)
        self.volume = None

    def create_vol(self, name, size):

        add_test_info.sub_test_info('1', 'create volume')

        init_create_volume = self.cinder_volume.create_volume(name, size)

        assert init_create_volume.status, "Volume Create initialize error"

        log.info('volume_name %s' % init_create_volume.vol.name)

        self.timer.wait_for_state_change(init_create_volume.vol.status, 'creating')
        volume = self.cinder_volume.get_volume(init_create_volume.vol)

        assert volume.status, "Volumes Does Exist, hence did not create"

        self.volume = volume.volume

        log.info('volume exist status: %s' % volume.volume.status)

        add_test_info.sub_test_completed_info()

    def extend_vol(self, extend_size):

        add_test_info.sub_test_info('2', 'extend volume')

        old_size = self.volume.size
        new_size = old_size + extend_size
        log.info('new size: %s' % new_size)
        log.info('old size: %s' % old_size)
        extended = self.cinder_volume.extend_volume(self.volume, new_size)

        assert extended.execute, "volume extend initialize error"

        volume = self.cinder_volume.get_volume(self.volume)
        self.timer.wait_for_state_change(volume.volume.status, 'extending')
        volume = self.cinder_volume.get_volume(self.volume)

        if volume.volume.size == new_size:
            log.info('volume extended, size: %s' % volume.volume.size)
            self.volume = volume.volume
        else:
            raise AssertionError("volume did not extend")

        add_test_info.sub_test_completed_info()

    def delete_vol(self):

        add_test_info.sub_test_info('3', 'delete volume')

        vol_delete = self.cinder_volume.delete_volume(self.volume)

        assert vol_delete.execute, "volume delete initialize error"
        volume_exists = self.cinder_volume.get_volume(self.volume)
        self.timer.wait_for_state_change(volume_exists.volume.status, 'deleting')
        volume_exists = self.cinder_volume.get_volume(self.volume)

        if not volume_exists.status:
            log.info('volume deleted')
        else:
            log.error('volume status: %s' % volume_exists.volume.status)
            raise AssertionError("volume still exists")

        add_test_info.sub_test_completed_info()


def exec_test():

    uuid.set_env()

    global add_test_info

    add_test_info = AddTestInfo(1, 'Cinder Volume Test')
    try:

        add_test_info.started_info()
        cinder_auth = CinderAuth()
        auth = cinder_auth.auth()

        assert auth.status, "Authentication Failed"

        cinder_volume = CinderVolumeTest(auth)

        cinder_volume.create_vol('test-volume1', 2)
        cinder_volume.extend_vol(2)
        cinder_volume.delete_vol()

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')
        sys.exit(1)

    add_test_info.completed_info()


if __name__ == '__main__':

    exec_test()
