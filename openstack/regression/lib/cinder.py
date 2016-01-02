import os
import random
from cinderclient.v2 import client as c_client
import log
import time


class Cinder(object):

    def __init__(self):
        os_username = os.environ['OS_USERNAME']
        os_api_key = os.environ['OS_PASSWORD']
        os_auth_url = os.environ['OS_AUTH_URL']
        os_tenant = os.environ['OS_TENANT_NAME']
        self.cinder = c_client.Client(auth_url=os_auth_url, username=os_username, api_key=os_api_key,
                                      project_id=os_tenant, service_type='volumev2')

    def list_volumes(self):
        log.info("List cinder volumes")
        volumes = self.cinder.volumes.list()
        if volumes:
            return volumes

    def create_volume(self, size=2, image_id=None):
        log.info("Create volume")
        name = "test-vol-" + str(random.randint(1, 20))
        volume = self.cinder.volumes.create(name=name, size=size, imageRef=image_id)
        return volume

    def get_volume(self, volume_name):
        vol_list = self.cinder.volumes.list()
        for vol in vol_list:
            if vol.name == volume_name:
                return vol.id

    def get_volume_by_name(self, volume_name):
        vol_list = self.cinder.volumes.list()
        for vol in vol_list:
            if vol.name == volume_name:
                return vol.name

    def get_volume_size(self, volume_name):
        vol_list = self.cinder.volumes.list()
        for vol in vol_list:
            if vol.name == volume_name:
                return vol.size

    def get_volume_status(self, volume_name):
        vol_list = self.cinder.volumes.list()
        for vol in vol_list:
            if vol.name == volume_name:
                return vol.status

    def extend_volume(self, volume, newsize):
        vol = self.get_volume(volume)
        self.cinder.volumes.extend(vol, newsize)
        time.sleep(5)
        size = self.get_volume_size(volume)
        if size == newsize:
            log.info("Volume %s extended to %s" % (vol, newsize))
        else:
            log.error("Failed to extend volume %s " % vol)

    def create_backup(self, volume, incremental=False):
        vol = self.get_volume(volume)
        name = volume + "-back" + str(random.randint(1, 20))
        self.cinder.backups.create(vol, name=name, incremental=incremental)
        return name

    def get_backup(self, backup_name):
        backup_list = self.cinder.backups.list()
        for bac in backup_list:
            if bac.name == backup_name:
                return bac.id

    def delete_backup(self, backup_name):
        back_vol = self.get_backup(backup_name)
        self.cinder.backups.delete(back_vol)

    def list_backup(self):
        backups = self.cinder.backups.list()
        if backups:
            return backups

    def create_snapshot(self, volume):
        volume_status = self.get_volume_status(volume)
        vol = self.get_volume(volume)
        if volume_status == "available":
            snap_name = 'snap-' + str(random.randint(1, 20))
            snapshot = self.cinder.volume_snapshots.create(vol, name=snap_name, force=False)
            return snapshot.name
        elif volume_status == "in-use":
            snap_name = 'snap-' + str(random.randint(1, 20))
            snapshot = self.cinder.volume_snapshots.create(vol, name=snap_name, force=True)
            return snapshot.name

    def get_snapshot(self, snapshot_name):
        snapshot_list = self.cinder.volume_snapshots.list()
        for snap in snapshot_list:
            if snap.name == snapshot_name:
                return snap.id

    def create_vol_from_snap(self, snapshot, size=2):
        snap = self.get_snapshot(snapshot)
        return self.cinder.volumes.create(size=size, snapshot_id=snap)

    def delete_snapshot(self, snapshot):
        snap = self.get_snapshot(snapshot)
        self.cinder.volume_snapshots.delete(snap)

    def list_snapshot(self):
        snapshots = self.cinder.volume_snapshots.list()
        if snapshots:
            return snapshots
