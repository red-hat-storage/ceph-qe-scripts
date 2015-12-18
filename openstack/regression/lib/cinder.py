import os
import random
import config as cfg
from cinderclient.v2 import client as c_client


class Cinder(object):

    def __init__(self):
        os_username = os.environ['OS_USERNAME']
        os_api_key = os.environ['OS_PASSWORD']
        os_auth_url = os.environ['OS_AUTH_URL']
        os_tenant = os.environ['OS_TENANT_NAME']
        self.cinder = c_client.Client(auth_url=os_auth_url, username=os_username, api_key=os_api_key, project_id=os_tenant, service_type='volumev2')

    def list_cinder(self):
        volumes = self.cinder.volumes.list()
        if volumes:
            return volumes

    def create_volume(self, size=1, image_id=None):
        name = "test-vol-" + str(random.randint(1, 20))
        volume = self.cinder.volumes.create(name=name, size=size, imageRef=image_id)
        return self.cinder.volumes.get(volume.id)

    def extend_volume(self, volume, newsize):
        self.cinder.volumes.extend(volume, newsize)
        return self.cinder.volumes.get(volume.id)

    def attach_volume(self, volume, server, mount=cfg.mountpoint):
        self.cinder.volumes.attach(volume, server.id, mount)
        return self.cinder.volumes.get(volume.id)




























