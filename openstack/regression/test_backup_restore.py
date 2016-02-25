"""
1. Create a volume, take a backup and restore to a volume with same size
2. Create a volume, take a backup and restore to a volume with larger size
"""

import lib.log as log
from lib.cinder import CinderAuth, CinderVolumes, CinderBackup
from lib.test_desc import AddTestInfo
from utils import wait
import sys


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

    def delete_vol(self, volume):

        add_test_info.sub_test_info('4', 'delete volume')
        vol_to_delete = self.cinder_volume.delete_volume(volume=volume)

        assert vol_to_delete.execute, "snapshot volume delete initialize error"

        volume_exists = self.cinder_volume.get_volume(volume)
        self.timer.wait_for_state_change(volume_exists.status, 'deleting')

        log.info('status: %s' % volume_exists.status)
        volume_exists = self.cinder_volume.get_volume(volume)

        if not volume_exists.status:
            log.info('snapshot volume deleted')
        else:
            log.error('volume status: %s' % volume_exists.volume.status)
            raise AssertionError("snapshot volume still exists")

        add_test_info.sub_test_completed_info()

    def take_backup(self, volume, backup_name):

        add_test_info.sub_test_info('2', 'Create volume backup')

        backup = self.cinder_backup.create_backup(volume, name=backup_name)
        assert backup.status, "creating backup failed"

        self.backup = backup.volume_backup
        self.timer.wait_for_state_change(self.backup.status, 'backing-up')

        add_test_info.sub_test_completed_info()

        return self.backup

    def restore_backup(self, backup, volume):

        add_test_info.sub_test_info('3', 'Restore volume backup')

        restore = self.cinder_backup.restore_backup(backup, volume)
        restored_vol = self.cinder_volume.get_volume(volume)
        self.timer.wait_for_state_change(restored_vol.volume.status, 'restoring-backup')

        assert restore.execute, "Restoring Failed"
        add_test_info.sub_test_completed_info()

        return restore

    def delete_backup(self, backup):

        add_test_info.sub_test_info('5', 'delete backup')
        backup_to_delete = self.cinder_backup.delete_backup(backup)

        assert backup_to_delete.execute, "Backup delete initialize error"

        backup_exists = self.cinder_backup.get_backup(backup_to_delete)
        self.timer.wait_for_state_change(backup_exists.status, 'deleting')

        log.info('status: %s' % backup_exists.status)
        backup_exists = self.cinder_backup.get_backup(backup_to_delete)

        if not backup_exists.status:
            log.info('backup deleted')
        else:
            log.error('Backup status: %s' % backup_exists.status)
            raise AssertionError("Backup still exists")

        add_test_info.sub_test_completed_info()


def exec_test_1():

    global add_test_info

    add_test_info = AddTestInfo(4, 'Restore Backup of the volume to a new volume of the same size')
    try:

        add_test_info.started_info()
        cinder_auth = CinderAuth()
        auth = cinder_auth.auth()

        assert auth.status, "Authentication Failed"

        cinder_volume = CindeVolumeTest(auth)

        volume1 = cinder_volume.create_vol('test_volume1', 1)

        backup = cinder_volume.take_backup(volume1, 'test_volume1_bkp')

        volume2 = cinder_volume.create_vol('test_volume_2', 1)

        restore = cinder_volume.restore_backup(backup, volume2)

        cinder_volume.delete_vol(volume2)

        cinder_volume.delete_backup(backup)

        cinder_volume.delete_vol(volume1)

        log.info('restore obj %s:' % restore)

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')
        sys.exit(1)

    add_test_info.completed_info()


def exec_test_2():

    global add_test_info

    add_test_info = AddTestInfo(5, 'Restore Backup of the volume to a larger volume ')
    try:

        add_test_info.started_info()
        cinder_auth = CinderAuth()
        auth = cinder_auth.auth()

        assert auth.status, "Authentication Failed"

        cinder_volume = CindeVolumeTest(auth)

        volume1 = cinder_volume.create_vol('test_volume1', 1)

        backup = cinder_volume.take_backup(volume1, 'test_volume1_bkp2')

        volume2 = cinder_volume.create_vol('test_volume2', 2)

        restore = cinder_volume.restore_backup(backup, volume2)

        cinder_volume.delete_vol(volume2)

        cinder_volume.delete_backup(backup)

        cinder_volume.delete_vol(volume1)

        log.info('restore obj %s:' % restore)

        add_test_info.success_status('ok')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')
        sys.exit(1)

    add_test_info.completed_info()


if __name__ == '__main__':

    exec_test_1()
    exec_test_2()
