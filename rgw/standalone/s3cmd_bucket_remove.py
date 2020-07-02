#!/usr/bin/python3

import os
print('s3cmd should be pre configured')
status = 'exit'
while(status != exit):
        os.system('s3cmd ls')
        select_bucket_name = input('Enter the bucket name you want to remove: ')
        #bucket_remove = os.system('s3cmd rb s3://{} --recursive'.format(select_bucket_name))
        bucket_remove = os.system('radosgw-admin bucket rm --bucket {} --purge-objects'.format(select_bucket_name))
        status_check = input('Write exit to break program else press enter: ')
        if status_check == 'exit':
            break
