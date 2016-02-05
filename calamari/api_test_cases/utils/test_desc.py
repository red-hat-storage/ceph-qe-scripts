import log


class AddTestInfo(object):

    def __init__(self, id, name):
        self.id = id
        self.name = name

    def started_info(self):

        log.info('\n========================================================================================================= \ntest details'
                 '\n---------\ntest_id:%s\ntest_name:%s\n=============================' %(self.id, self.name))

        print '---------------------------'
        print 'test_started:%s' % self.name
        print 'test_id:%s' % self.id

    def status(self, status):
        log.info('**********  %s  *********' % status)
        print 'test status %s' % status

    def completed_info(self):
        log.info("\n======================================================\nTest Completed\n=========================================================================================================")

        print 'test completed'
        print '--------------------------'
