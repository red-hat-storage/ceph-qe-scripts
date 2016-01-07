from lib.cinder import Cinder, CinderVolumes, CinderSnapshot
import lib.log as log
from lib.test_desc import AddTestInfo
from utils import wait
import time


class CinderSnapCycle(object):

    def __init__(self, cinder, add_test_info):
        self.timer = wait.Wait()
        self.cinder_volume = CinderVolumes(cinder)
        self.cinder_snap = CinderSnapshot(cinder)
        self.volume = None
        self.add_test_info = add_test_info

    def vol_create(self, name, size):

        self.add_test_info.sub_test_info('1', 'create_volume')
        init_create_volume = self.cinder_volume.create_volume(name, size)
        assert init_create_volume.status, "Volume create initialize error"
        log.info('volume name: %s' % init_create_volume.vol.name)
        self.timer.wait_for_state_change(init_create_volume.vol.status, 'creating')
        volume = self.cinder_volume.get_volume(init_create_volume.vol)
        self.volume = volume.volume
        log.info('Volume exists')

    def snapshot_create(self, name):

        self.add_test_info.sub_test_info('2', 'Snapshot creation')
        self.snap = self.cinder_snap.create_snapshot(self.volume, name)
        assert self.snap.status, "Snap create initialize error"
        log.info('snap name: %s' % self.snap.volume_snapshot.name)
        self.timer.wait_for_state_change(self.snap.volume_snapshot.status, 'creating')
        snapshot = self.cinder_snap.get_snapshot(self.snap.volume_snapshot)
        self.snapshot = snapshot.snapshot
        log.info('Snapshot exists')

    def snap_vol_create(self, name, size):

        self.add_test_info.sub_test_info('3', "Create snapshot out of volume")

        snap_vol = self.cinder_snap.create_vol_from_snap(self.snapshot.id, size=size, name=name)
        assert snap_vol.status, "Volume from snap create initialize error"
        log.info('snapshot volume name: %s' % snap_vol.volume.name)
        self.timer.wait_for_state_change(snap_vol.status, 'creating')
        self.snapshot_volume = self.cinder_volume.get_volume(snap_vol.volume)
        log.info('Snapshot volume exists')

    def delete_vol(self):

        self.add_test_info.sub_test_info('4', 'delete snapshot volume')
        vol_to_delete = self.cinder_volume.delete_volume(self.snapshot_volume.volume)
        assert vol_to_delete.execute, "snapshot volume delete initialize error"
        volume_exists = self.cinder_volume.get_volume(self.snapshot_volume.volume)
        time.sleep(5)
        if not volume_exists.status:
            log.info('snapshot volume deleted')
        else:
            log.error('volume status: %s' % volume_exists.volume.status)
 #           raise AssertionError("snapshot volume still exists")

    def snapshot_delete(self):

        self.add_test_info.sub_test_info('5', 'delete snapshot')
        snap_delete = self.cinder_snap.delete_snapshot(self.snapshot)
        assert snap_delete, "Snapshot delete initialize error"
        snapshot_exists = self.cinder_snap.get_snapshot(self.snapshot)
        time.sleep(5)
        if not snapshot_exists.status:
            log.info('snapshot deleted')
        else:
            log.error('snapshot status: %s' % snapshot_exists.snapshot)
#            raise AssertionError("snapshot still exists")


def exec_test():

    add_test_info = AddTestInfo(1, 'Cinder Snap Test')
    try:

        add_test_info.started_info()
        cinder_obj = Cinder()
        auth = cinder_obj.auth()

        assert auth.status, "Authentication Failed"

        cinder_snap = CinderSnapCycle(auth.cinder, add_test_info)

        cinder_snap.vol_create('test-volume2', 1)
        cinder_snap.snapshot_create('test-snap2')
        cinder_snap.snap_vol_create('test-snap2-vol', 1)
        cinder_snap.delete_vol()
        cinder_snap.snapshot_delete()

        add_test_info.status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.status('error')

    add_test_info.completed_info()


if __name__ == '__main__':

    exec_test()