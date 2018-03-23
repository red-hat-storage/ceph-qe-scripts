import psutil
import os
import sys
sys.path.append(os.path.abspath(os.path.join(__file__, "../..")))
import v1.utils.log as log


class Process(object):
    def __init__(self, name):

        log.debug('class: %s' % self.__class__.__name__)
        self.name = name
        log.info('process_name: %s' % self.name)

        self.process = None

    def find(self):

        log.info('finding process')

        for p in psutil.process_iter():
            if self.name in p.name():
                self.process = p
                log.info('found process: %s' % self.process.name())
                log.info('cmd line: %s' % self.process.cmdline())
                break


if __name__ == '__main__':

    process = Process(name='ganesha')
    process.find()

    print process.process.name()
    process.process.kill()


