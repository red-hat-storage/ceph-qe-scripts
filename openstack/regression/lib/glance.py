import os
import keystoneclient.v2_0.client as ksclient
import glanceclient.v2.client as glclient
import keystoneclient.exceptions as ks_exceptions
import glanceclient.common.exceptions as gl_exceptions
import log
from utils import getimage


class GlanceReturnStack(object):

    def __init__(self):
        pass


class GlanceAuth(object):

    def __init__(self):

        self.keystone = {}
        self.keystone['username'] = os.environ['OS_USERNAME']
        self.keystone['password'] = os.environ['OS_PASSWORD']
        self.keystone['auth_url'] = os.environ['OS_AUTH_URL']
        self.keystone['tenant_name'] = os.environ['OS_TENANT_NAME']
        self.ks_creds = ksclient.Client(**self.keystone)
        self.glance_endpoint = self.ks_creds.service_catalog.url_for(service_type='image')

    def auth(self):

        """

        :return: :auth_stack
                - auth_stack.glance : glance object after authenticating
                - auth_stack.status : True or False
        """

        auth_stack = GlanceReturnStack()

        log.info('Authenticating glance')

        try:
            glance = glclient.Client(self.glance_endpoint, token=self.ks_creds.auth_token)
            auth_stack.glance, auth_stack.status = glance, True
            log.info("Glance auth successful")

        except ks_exceptions.AuthorizationFailure, e:
            auth_stack.glance, auth_stack.status = None, False
            log.error('Glance auth failed')
            log.error(e.message)

        return auth_stack


class GlanceActions(object):

    """ Upload an image to glance from the given location """

    def __init__(self, glance_auth):
        self.glance = glance_auth

    def upload_images(self, name):

        """
        :param name: string
        :return: upload_images.image : image object
                 upload_images.status: True or False
        """

        log.info("Uploading image to glance")

        glance_create = GlanceReturnStack()

        fimage = getimage.download_image()

        try:
            log.info('initialized image creation')
            img = self.glance.images.create(name=name, disk_format="raw", container_format="bare")
            self.glance.images.upload(img.id, open(fimage, 'rb'))
            glance_create.image, glance_create.status = img, True

        except gl_exceptions.ClientException as e:
            log.error(e)
            glance_create.image, glance_create.status = None, False

        return glance_create

    def list_images(self):


        """
       :return volumes_list
                - image_list.images : list of image objects
                - image_list.status  : True or False
        """

        image_list = GlanceReturnStack()
        image_list.images = []

        try:
            log.info("Listing images")
            images = self.glance.images.list()

            image_list.status = True
            if images:
                image_list.images = images

        except (gl_exceptions.ClientException, gl_exceptions.NotFound), e:
            log.error(e)
            image_list.status = False

        return image_list

    def get_image(self, image):

        """
        :param image: glance image object
        :return:each_image
                - each_image.image : image object
                - each_image.status : True or False

        """

        each_image = GlanceReturnStack()
        each_image.image = None

        try:
            log.info('Get image attributes')
            image = self.glance.images.get(image.id)
            each_image.image = image
            each_image.status = True

        except (gl_exceptions.ClientException, gl_exceptions.NotFound), e:
            log.error(e)
            each_image.status = False

        return each_image

    def delete_image(self, image):

        """
        :param image: image object
        :return: image_delete
                 - image_delete.execute: True or False
        """

        log.info('Deleting image')
        image_delete = GlanceReturnStack()
        image_delete.execute = False

        try:
            self.glance.images.delete(image)
            image_delete.execute = True
            log.info('delete image executed')
        except (gl_exceptions.NotFound, gl_exceptions.ClientException), e:
            log.error(e)
            image_delete.execute = False

        return image_delete




















