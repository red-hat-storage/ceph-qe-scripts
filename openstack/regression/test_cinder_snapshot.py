"""
Create a volume, take a snapshot, create a volume out of snapshot, delete the volumes and the snapshot
"""

from  lib.cinder import CinderAuth, CinderVolumes, CinderSnapshot
import lib.log as log
from lib.test_desc import AddTestInfo
from utils import wait


class CinderSnapCycle(object):

    def __init__(self, cinder):
        self.timer = wait.Wait()
        self.cinder_volume = CinderVolumes(cinder.cinder)
        self.cinder_snap = CinderSnapshot(cinder.cinder)
        self.volume = None
        self.snapshot = None

    def vol_create(self, name, size):

        add_test_info.sub_test_info('1', 'create_volume')
        init_create_volume = self.cinder_volume.create_volume(name, size)
        assert init_create_volume.status, "Volume create initialize error"
        log.info('volume name: %s' % init_create_volume.vol.name)
        self.timer.wait_for_state_change(init_create_volume.vol.status, 'creating')
        volume = self.cinder_volume.get_volume(init_create_volume.vol)
        self.volume = volume.volume
        log.info('Volume exists')

        add_test_info.sub_test_completed_info()
        return self.volume

    def snapshot_create(self, name):

        add_test_info.sub_test_info('2', 'Snapshot creation')

        snap = self.cinder_snap.create_snapshot(self.volume, name)

        assert snap.status, "Snap create initialize error"

        log.info('snap name: %s' % snap.volume_snapshot.name)

        self.timer.wait_for_state_change(snap.volume_snapshot.status, 'creating')
        snapshot = self.cinder_snap.get_snapshot(snap.volume_snapshot)

        self.snapshot = snapshot.snapshot
        log.info('Snapshot exists')

        add_test_info.sub_test_completed_info()

    def create_volume_from_snap(self,name, size):

        add_test_info.sub_test_info('3', "Create volume out of snapshot")

        snap_vol = self.cinder_snap.create_vol_from_snap(self.snapshot.id, name=name, size=size)
        assert snap_vol.status, "Volume from snap create initialize error"
        log.info('snapshot volume name: %s' % snap_vol.volume.name)
        self.timer.wait_for_state_change(snap_vol.volume.status, 'creating')
        snapshot_volume = self.cinder_volume.get_volume(snap_vol.volume)
        self.snapshot_volume = snapshot_volume.volume
        log.debug('status %s' % self.snapshot_volume.status)
        log.info('Snapshot volume exists')

        add_test_info.sub_test_completed_info()
        return self.snapshot_volume

    def delete_vol(self, volume):

        add_test_info.sub_test_info('4', 'delete volume')
        vol_to_delete = self.cinder_volume.delete_volume(volume=volume)

        assert vol_to_delete.execute, "snapshot volume delete initialize error"

        volume_exists = self.cinder_volume.get_volume(volume)
        self.timer.wait_for_state_change(volume_exists.volume.status, 'deleting')

        log.info('status: %s' % volume_exists.volume.status)
        volume_exists = self.cinder_volume.get_volume(volume)

        if not volume_exists.status:
            log.info('snapshot volume deleted')
        else:
            log.error('volume status: %s' % volume_exists.volume.status)
            raise AssertionError("snapshot volume still exists")

        add_test_info.sub_test_completed_info()

    def snapshot_delete(self):

        add_test_info.sub_test_info('5', 'delete snapshot')
        snap_delete = self.cinder_snap.delete_snapshot(self.snapshot)

        assert snap_delete, "Snapshot delete initialize error"

        snapshot_exists = self.cinder_snap.get_snapshot(self.snapshot)
        self.timer.wait_for_state_change(snapshot_exists.snapshot.status, 'deleting')

        log.info('status: %s' % snapshot_exists.snapshot.status)
        snapshot_exists = self.cinder_snap.get_snapshot(self.snapshot)

        if not snapshot_exists.status:
            log.info('snapshot deleted')
        else:
            log.error('snapshot status: %s' % snapshot_exists.snapshot.status)
            raise AssertionError("snapshot still exists")

        add_test_info.sub_test_completed_info()


def exec_test(volume_name, volume_size):

    snapshot_name = 'snap_' + volume_name

    volume_name_from_snapshot = 'vol_' + snapshot_name

    volume_size_from_snapshot = volume_size + 1

    global add_test_info

    add_test_info = AddTestInfo(2, 'Cinder Snap Test')
    try:

        add_test_info.started_info()
        cinder = CinderAuth()
        auth = cinder.auth()

        assert auth.status, "Authentication Failed"

        cinder_snap = CinderSnapCycle(auth)

        source_volume = cinder_snap.vol_create(volume_name, volume_size)
        cinder_snap.snapshot_create(snapshot_name)

        snap_volume = cinder_snap.create_volume_from_snap(volume_name_from_snapshot, volume_size_from_snapshot)

        cinder_snap.delete_vol(snap_volume)
        cinder_snap.snapshot_delete()
        cinder_snap.delete_vol(source_volume)

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')

    add_test_info.completed_info()

if __name__ == '__main__':

    volume_name = 'test_volume'
    volume_size = 1

    exec_test(volume_name, volume_size)