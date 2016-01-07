import lib.log as log
from lib.cinder import Cinder, CinderVolumes
from lib.test_desc import AddTestInfo
from utils import wait
import time


class CindeVolumeTest(object):
    def __init__(self, cinder, add_test_info):
        self.timer = wait.Wait()
        self.cinder_volume = CinderVolumes(cinder)
        self.volume = None

        self.add_test_info = add_test_info


    def create_vol(self, name, size):

        self.add_test_info.sub_test_info('1', 'create volume')

        init_create_volume = self.cinder_volume.create_volume(name, size)

        assert init_create_volume.status, "Volume Create initialize error"

        log.info('volume_name %s' % init_create_volume.vol.name)

        self.timer.wait_for_state_change(init_create_volume.vol.status, 'creating')
        volume = self.cinder_volume.get_volume(init_create_volume.vol)

        assert volume.status, "Volumes Does Exist, hence did not create"

        self.volume = volume.volume

        log.info('volume exist status: %s' % volume.volume.status)

    def extend_vol(self, extend_size):

        self.add_test_info.sub_test_info('2', 'extend volume')

        old_size = self.volume.size
        new_size = old_size + extend_size
        log.info('new size: %s' % new_size)
        log.info('old size: %s' % old_size)
        extended = self.cinder_volume.extend_volume(self.volume, new_size)

        assert extended.execute, "volume extend initialize error"

        volume = self.cinder_volume.get_volume(self.volume)
        self.timer.wait_for_state_change(volume.status, 'extending')
        volume = self.cinder_volume.get_volume(self.volume)

        if volume.volume.size == new_size:
            log.info('volume extended, size: %s' % volume.volume.size)
            self.volume = volume.volume
        else:
            raise AssertionError("volume did not extend")

    def delete_vol(self, volume_obj=None):

        self.add_test_info.sub_test_info('3', 'delete volume')

        #self.volume = volume_obj

        vol_delete = self.cinder_volume.delete_volume(self.volume)

        assert vol_delete.execute, "volume delete initlize error"

        time.sleep(5)

        volume_exists = self.cinder_volume.get_volume(self.volume)

        if not volume_exists.status:
            log.info('volume deleted')
        else:
            log.error('volume status: %s' % volume_exists.volume.status)
            raise AssertionError("volume still exists")

    def list_all_volumes(self):

        log.info('listing all volumes')

        volumes_list = self.cinder_volume.list_volumes()

        assert volumes_list.status, "error in listing volumes"

        if not volumes_list.volumes:
            raise AssertionError("did not get any volumes")

        for each_vol in volumes_list.volumes:
            log.info('volume name: %s' % each_vol.name)
            log.info('volume id: %s' % each_vol.id)
            log.info('volume size %s' % each_vol.size)

            #self.delete_vol(each_vol)


def exec_test():

    add_test_info = AddTestInfo(1, 'Cinder Volume Test')
    try:

        add_test_info.started_info()
        cinder_obj = Cinder()
        auth = cinder_obj.auth()

        assert auth.status, "Authentication Failed"

        cinder_volume = CindeVolumeTest(auth.cinder, add_test_info)

        #cinder_volume.list_all_volumes()

        cinder_volume.create_vol('test-volume1', 2)
        cinder_volume.extend_vol(5)
        cinder_volume.delete_vol()

        add_test_info.status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.status('error')

    add_test_info.completed_info()


if __name__ == '__main__':

    exec_test()
