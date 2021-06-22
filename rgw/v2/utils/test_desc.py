import logging

log = logging.getLogger(__name__)


class Bcolors:
    HEADER = "\033[95m"
    OKGREEN = "\033[92m"
    FAIL = "\033[91m"
    ENDC = "\033[0m"
    BOLD = "\033[1m"


class AddTestInfo(object):
    def __init__(self, name, id=None):
        self.id = id
        self.name = name

    def started_info(self):
        colourify = lambda val: Bcolors.HEADER + str(val) + Bcolors.ENDC

        log.info(f"test_name: {colourify(self.name)}")
        log.info(f"test_id: {colourify(self.id)}")

    def sub_test_info(self, sub_test_id, sub_test_name):
        sub_test_id = str(self.id) + "." + str(sub_test_id)

        log.info(f"sub_test_id: {sub_test_id}\n")
        log.info(f"sub_test_name: {sub_test_name}")

    def sub_test_completed_info(self):
        log.info("sub test completed")

    def failed_status(self, status):
        failed = Bcolors.FAIL + status + Bcolors.ENDC
        log.info(f"status: {failed}")

    def success_status(self, status):
        success = Bcolors.OKGREEN + status + Bcolors.ENDC
        log.info(success)

    def completed_info(self):
        completed = Bcolors.HEADER + "Test completed" + Bcolors.ENDC
        log.info(completed)
