#!/bin/python
import rbd 
import rados
import subprocess
from subprocess import call
import os
from functools import partial

def create_block_device(name,size):
	dev_number=name[-1:]
	os.system("mknod -m660 %s b 7 %s" %(name,dev_number))
	os.system("chown root.disk %s" %name)
	os.system("chmod 666 %s" %name)
	os.system("dd if=/dev/urandom of=data bs=1M count=%s" %size)
	data=os.popen('cat data').read()
	os.system("losetup %s %s " %(name,r'data'))

def rbd_create(pool,image,size):
	cluster = rados.Rados(conffile='ceph.conf')
	cluster.connect()
	ioctx = cluster.open_ioctx(pool)
	rbd_inst = rbd.RBD()
	rbd_inst.create(ioctx,image,size)
	image = rbd.Image(ioctx, image)
	return image

def get_file_size(filename):
        "Get the file size by seeking at end"
        fd= os.open(filename, os.O_RDONLY)
        try:
                return os.lseek(fd, 0, os.SEEK_END)
        finally:
                os.close(fd)

def blk_import(filename,image):
	offset=0
	length=0
	with open (filename, 'rb') as iteration:
		for chunk in iter(partial(iteration.read, 4194304), ''):
			image.write(chunk,offset)
			length=len(chunk)
			offset+=length
			print length,offset

if __name__=="__main__":
	blk_dev=raw_input("Enter the Loop Device Name, e.g. /dev/loop0:  ")
	size=input("Enter the size you want to create your loop device in MB:  ")
	create_block_device(blk_dev,size)
	size=get_file_size(blk_dev)
        Pool = raw_input("Enter the pool Name:")
        Image = raw_input("Enter the Image Name:")
	image_ctx=rbd_create(Pool,Image,size)	
	blk_import(blk_dev,image_ctx)
