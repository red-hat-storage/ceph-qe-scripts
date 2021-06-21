import inspect
import os
from shutil import copyfile, move

from libs import log


class AddTestInfo(object):
    def __init__(self, id, name):
        self.id = id
        self.name = name
        self.msg = None

        self.status = False

    def started_info(self):
        log.info(
            "\n==========================================================================================="
            "============== \ntest details"
            "\n---------\ntest_id:%s\ntest_name:%s\n============================="
            % (self.id, self.name)
        )

        print "---------------------------"
        print "test_started:%s" % self.name
        print "test_id:%s" % self.id

    def success(self, status):
        self.msg = "success"
        log.info("**********  %s  *********" % status)
        print "**********  %s  *********" % status
        self.status = True

    def failed(self, status):
        self.msg = "failed"
        log.info("!!!!!!!!!!! %s !!!!!!!!!!!!" % status)
        print "!!!!!!!!!!! %s !!!!!!!!!!!!" % status
        self.status = False

    def completed_info(self, log_path):
        log.info(
            "\n======================================================\nTest Completed\n==============================="
        )

        print "test completed"
        print "--------------------------"

        test_details = dict(status=self.status, id=self.id, name=self.name)

        frame = inspect.stack()[1]
        module = inspect.getmodule(frame[0])
        destination_file = os.path.basename(os.path.splitext(module.__file__)[0])

        destination_file = (
            "test_id_" + str(self.id) + "_" + str(self.msg) + "_" + destination_file
        )

        log_copy_file = os.path.join(log_path, destination_file)

        print log_copy_file

        if not os.path.exists(log_path):
            os.makedirs(log_path)

        src = log.LOG_NAME

        copyfile(src, log_copy_file)

        with open(src, "w"):
            pass

        return test_details
