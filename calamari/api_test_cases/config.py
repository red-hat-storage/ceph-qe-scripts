import libs.log as log
from utils.utils import Machines


class MakeMachines(object):
    def __init__(self):
        pass

    def osd(self):
        osd1 = Machines('10.8.128.41', 'magna041')
        osd2 = Machines('10.8.128.45', 'magna045')
        osd3 = Machines('10.8.128.61', 'magna061')

        return osd1, osd2, osd3

    def mon(self):
        mon1 = Machines('10.8.128.41', 'magna041')

        return mon1

    def calamari(self):

        return dict(username='admin',
                    password='admin123',
                    ip='10.8.128.41',
                    port='8002')
