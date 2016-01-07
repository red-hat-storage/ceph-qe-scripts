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


def exec_test():

    global add_test_info

    add_test_info = AddTestInfo(2, 'Cinder Snap Test')
    try:

        add_test_info.started_info()
        cinder = CinderAuth()
        auth = cinder.auth()

        assert auth.status, "Authentication Failed"

        cinder_snap = CinderSnapCycle(auth)

        cinder_snap.vol_create('test-volume2', 2)
        cinder_snap.snapshot_create('test-snap2')

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')

    add_test_info.completed_info()


if __name__ == '__main__':

    exec_test()