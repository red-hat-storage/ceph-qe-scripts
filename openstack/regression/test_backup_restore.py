"""
Create a volume, take a backup and restore to a volume with same size
"""

import lib.log as log
from lib.cinder import CinderAuth, CinderVolumes, CinderBackup
from lib.test_desc import AddTestInfo
from utils import wait
import time


class CindeVolumeTest(object):
    def __init__(self, cinder):
        self.timer = wait.Wait()
        self.cinder_volume = CinderVolumes(cinder.cinder)
        self.cinder_backup = CinderBackup(cinder.cinder)
        self.volume = None
        self.backup = None

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

        return self.volume

    def extend_vol(self, extend_size):

        add_test_info.sub_test_info('2', 'extend volume')

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

        add_test_info.sub_test_completed_info()

        return self.volume

    def take_backup(self, volume, backup_name):

        backup = self.cinder_backup.create_backup(volume, name=backup_name)

        assert backup.status, "creating backup failed"

        self.backup = backup.volume_backup

        time.sleep(10)

        return self.backup

    def restore_backup(self, backup, volume):

        restore = self.cinder_backup.restore_backup(backup, volume)

        assert restore.status, "Restoring Failed"

        return restore


def exec_test_1():

    global add_test_info

    add_test_info = AddTestInfo(4, 'Restore Backup of the volume to a new volume of the same size')
    try:

        add_test_info.started_info()
        cinder_auth = CinderAuth()
        auth = cinder_auth.auth()

        assert auth.status, "Authentication Failed"

        cinder_volume = CindeVolumeTest(auth)

        volume1 = cinder_volume.create_vol('test_volume1', 2)

        backup = cinder_volume.take_backup(volume1, 'test_volume1_bkp')

        volume2 = cinder_volume.create_vol('test_volume_2', 2)

        restore = cinder_volume.restore_backup(backup, volume2)

        log.info('restore obj %s:' % restore)

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')

    add_test_info.completed_info()


def exec_test_2():

    global add_test_info

    add_test_info = AddTestInfo(5, 'Restore Backup of the volume to to the same volume by extending it. ')
    try:

        add_test_info.started_info()
        cinder_auth = CinderAuth()
        auth = cinder_auth.auth()

        assert auth.status, "Authentication Failed"

        cinder_volume = CindeVolumeTest(auth)

        volume1 = cinder_volume.create_vol('test_volume1', 2)

        backup = cinder_volume.take_backup(volume1, 'test_volume1_bkp2')

        extended_volume = cinder_volume.extend_vol(5)

        restore = cinder_volume.restore_backup(backup, extended_volume)

        log.info('restore obj %s:' % restore)

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')

    add_test_info.completed_info()


def exec_test_3():

    global add_test_info

    add_test_info = AddTestInfo(6, 'Restore Backup of the volume to a larger volume ')
    try:

        add_test_info.started_info()
        cinder_auth = CinderAuth()
        auth = cinder_auth.auth()

        assert auth.status, "Authentication Failed"

        cinder_volume = CindeVolumeTest(auth)

        volume1 = cinder_volume.create_vol('test_volume1', 2)

        backup = cinder_volume.take_backup(volume1, 'test_volume1_bkp2')

        volume2 = cinder_volume.create_vol('test_extended_volume', 8)

        restore = cinder_volume.restore_backup(backup, volume2)

        log.info('restore obj %s:' % restore)

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')

    add_test_info.completed_info()


if __name__ == '__main__':

    exec_test_1()
    exec_test_2()
    exec_test_3()
