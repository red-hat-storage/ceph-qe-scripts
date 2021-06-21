import log


class Bcolors:

    HEADER = "\033[95m"
    OKGREEN = "\033[92m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


class AddTestInfo(object):
    def __init__(self, id, name):
        self.id = id
        self.name = name

    def started_info(self):

        log.info(
            "\n========================================================================================================= \ntest details"
            "\n---------\ntest_id:%s\ntest_name:%s\n============================="
            % (self.id, self.name)
        )

        print "---------------------------"
        print Bcolors.HEADER + "test_started:%s" % self.name + Bcolors.ENDC
        print Bcolors.HEADER + "test_id:%s" % self.id + Bcolors.ENDC
        print "---------------------------"

    def sub_test_info(self, sub_test_id, sub_test_name):

        sub_test_id = str(self.id) + "." + str(sub_test_id)

        log.info(
            "\n========================== \nSub test details"
            "\n---------\nsub_test_id:%s\nsub_test_name:%s\n================="
            % (sub_test_id, sub_test_name)
        )

        log.info("\n=========================================")

        print "---sub test id: %s" % sub_test_id
        print "---sub test name: %s" % sub_test_name

    def sub_test_completed_info(self):

        log.info("\n========================== Sub Test Completed ====================")
        print "---sub test completed"
        print "---------------------------"

    def failed_status(self, status):

        log.info(
            "\n======================================================================\n"
            "**********  %s  *********" % status
        )

        print Bcolors.FAIL + "test status %s" % status + Bcolors.ENDC

    def success_status(self, status):

        log.info(
            "\n======================================================================\n"
            "**********  %s  *********" % status
        )

        print Bcolors.OKGREEN + "test status %s" % status + Bcolors.ENDC

    def completed_info(self):
        log.info(
            "======================================================\nTest Completed\n======="
            "=================================================================================================="
        )

        print Bcolors.HEADER + "test completed" + Bcolors.ENDC
        print "---------------------------"
