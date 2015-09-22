#!/bin/python
import os
import random
import time
size=11000
i=0
new_size=0
sh_size=0
while i < 10:
	x=random.randint(1,500)
	new_size=size + x 
	cmd1 = 'rbd resize Tanay-RBD/testingClone_new2 --size %s' %new_size
	print 'cmd is %s' %cmd1
	os.system(cmd1)
	time.sleep(5)
        x=random.randint(1,100)
        sh_size= new_size - x
        cmd2 = 'rbd resize Tanay-RBD/testingClone_new2 --size %s --allow-shrink' %sh_size
        print 'cmd2 is %s' %cmd2
        os.system(cmd2)
        i = i +1
