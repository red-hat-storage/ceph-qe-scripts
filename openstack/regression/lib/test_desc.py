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

    def sub_test_info(self, sub_test_id, sub_test_name):

        sub_test_id = str(self.id) + '.' + str(sub_test_id)

        log.info('\n========================== \nSub test details'
                 '\n---------\nsub_test_id:%s\nsub_test_name:%s\n=================' %(sub_test_id, sub_test_name))

    def status(self, status):
        log.info('**********  %s  *********' % status)
        print 'test status %s' % status

    def completed_info(self):
        log.info("\n======================================================\nTest Completed\n======="
                 "==================================================================================================")

        print 'test completed'
        print '--------------------------'
