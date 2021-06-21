#!/bin/python
import os
from functools import partial
from subprocess import call

import rados
import rbd


def rbd_info(Pool, Image):
    new_list = []
    cluster = rados.Rados(conffile="ceph.conf")
    cluster.connect()
    ioctx = cluster.open_ioctx(Pool)
    rbd_inst = rbd.RBD()
    image = rbd.Image(ioctx, Image)
    size = image.size()
    new_list.append(image)
    new_list.append(size)
    return new_list


def blk_import(list, fd):
    offset = 0
    size = list[1]
    image = list[0]
    chunk = 4194304
    # for i in range(chunk,size):
    while offset <= size:
        count = size / chunk
        mod = size % chunk
        if size % chunk == 0:
            data = image.read(offset, chunk)
            fd.write(data)
            offset += chunk
            if offset == size:
                break
        else:
            i = 0
            while i < count:
                data = image.read(offset, chunk)
                fd.write(data)
                offset += chunk
                i += 1
        if mod > 0:
            print mod
            data = image.read(offset, mod)
            fd.write(data)
            break


if __name__ == "__main__":
    Pool = raw_input("Enter the pool Name:")
    Image = raw_input("Enter the Image Name:")
    list = rbd_info(Pool, Image)
    print list
    fd = open("rbd", "wb+")
    blk_import(list, fd)
