from libs import log


class AddTestInfo(object):
    def __init__(self, id, name):
        self.id = id
        self.name = name

        self.status = False

    def started_info(self):
        log.info(
            '\n==========================================================================================='
            '============== \ntest details'
            '\n---------\ntest_id:%s\ntest_name:%s\n=============================' % (self.id, self.name))

        print '---------------------------'
        print 'test_started:%s' % self.name
        print 'test_id:%s' % self.id

    def success(self, status):
        log.info('**********  %s  *********' % status)
        print '**********  %s  *********' % status
        self.status = True

    def failed(self, status):
        log.info('!!!!!!!!!!! %s !!!!!!!!!!!!' % status)
        print '!!!!!!!!!!! %s !!!!!!!!!!!!' % status
        self.status = False

    def completed_info(self):
        log.info(
            "\n======================================================\nTest Completed\n===============================")

        print 'test completed'
        print '--------------------------'

        test_details = dict(status=self.status,
                            id=self.id,
                            name=self.name
                            )

        return test_details
