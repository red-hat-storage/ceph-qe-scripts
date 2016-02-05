import time


class Wait(object):

    def __init__(self):
        pass

    def wait_for_state_change(self, expected_status, from_status):
        for i in range(0, 20):
            if expected_status != from_status:
                break
            time.sleep(1)

