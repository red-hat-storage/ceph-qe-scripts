import os
import urllib
import keystoneclient.v2_0.client as ksclient
import glanceclient.v2.client as glclient
import config as cfg
import random
import log

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
        log.info("Uploading image to glance")
        urllib.urlretrieve(cfg.image_loc, cfg.download_loc)
        fimage = cfg.download_loc
        if not fimage:
            log.error("Image not found")
            return False
        else:
            log.info("Creating glance image")
            name = "test-img-" + str(random.randint(1, 20))
            image = self.glance.images.create(name=name, disk_format="raw", container_format="bare")
            try:
                self.glance.images.upload(image.id, open(fimage, 'rb'))
            except Exception as e:
                log.error("Cannot upload glance image")
                log.error(e)
            image_name = image.name
            log.debug("Image uploaded %s" % image_name)
            return image_name


# List images

    def list_image(self):
        images = self.glance.images.list()
        if not images:
            log.debug("No images to list")
        else:
            return list(images)

# Get image by id

    def get_image(self, image_name):
        image_list = self.glance.images.list()
        for img in image_list:
            if img.name == image_name:
                return img.id

# Get image by name

    def get_image_by_name(self,image_id):
        image_list = self.glance.images.list()
        for img in image_list:
            if img.id == image_id:
                return img.name

# Delete image

    def delete_image(self, image_name):
        img = self.get_image(image_name)
        img_del = self.glance.images.delete(img)
        if img_del is None:
            log.info("Deleted the image %s successfully" % img_del)
        else:
            log.debug("Cannot delete image %s" % img_del)




















