"""
Sample test case. Create glance image
"""

from lib.glance import GlanceAuth, GlanceActions
import lib.log as log
from lib.test_desc import AddTestInfo
from utils import wait
import sys


class GlanceCycle(object):

    def __init__(self, glance, add_test_info):

        self.timer = wait.Wait()
        self.glance_img = GlanceActions(glance)
        self.add_test_info = add_test_info
        self.image = None

    def img_create(self, name):

        self.add_test_info.sub_test_info('1', 'create_image')
        create_image = self.glance_img.upload_images(name=name)
        assert create_image.status, "Image create initialize error"
        log.info('image name: %s' % create_image.image.name)
        self.timer.wait_for_state_change(create_image.image.status, 'creating')
        image = self.glance_img.get_image(create_image.image)
        self.image = image.image
        log.info('Image exists')


def exec_test():

    add_test_info = AddTestInfo(6, 'Glance image create Test')

    try:

        add_test_info.started_info()
        glance_obj = GlanceAuth()
        auth = glance_obj.auth()

        assert auth.status, "Authentication Failed"

        image_cycle = GlanceCycle(auth.glance, add_test_info)
        image_cycle.img_create('test-img')

    except AssertionError, e:
        log.error(e)
        add_test_info.failed_status('error')
        sys.exit(1)

    add_test_info.completed_info()


if __name__ == "__main__":

    exec_test()
