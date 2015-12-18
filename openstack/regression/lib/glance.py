import os
import urllib
import keystoneclient.v2_0.client as ksclient
import glanceclient.v2.client as glclient
import config as cfg
import random

# Download a test image to temporary location and upload the image to glance


class Glance(object):

    def __init__(self):
        keystone = {}
        keystone['username'] = os.environ['OS_USERNAME']
        keystone['password'] = os.environ['OS_PASSWORD']
        keystone['auth_url'] = os.environ['OS_AUTH_URL']
        keystone['tenant_name'] = os.environ['OS_TENANT_NAME']
        ks_creds = ksclient.Client(**keystone)
        glance_endpoint = ks_creds.service_catalog.url_for(service_type='image')
        self.glance = glclient.Client(glance_endpoint, token=ks_creds.auth_token)


# Upload an image to glance from the given location
    def upload_images(self):
        urllib.urlretrieve(cfg.image_loc, cfg.download_loc)
        fimage = cfg.download_loc
        name = "test-img-" + str(random.randint(1, 20))
        image = self.glance.images.create(name=name, disk_format="raw", container_format="bare")
        self.glance.images.upload(image.id, open(fimage, 'rb'))
        imageid = image.id
        return imageid


# List images
    def list_image(self):
        images = self.glance.images.list()
        if images:
            return list(images)

    def get_image(self, image_name):
        image_list = self.glance.images.list()
        for img in image_list:
            if img.name == image_name:
                return img
        return None


# Delete image
    def delete_images(self, image):
        return self.glance.images.delete(image)











