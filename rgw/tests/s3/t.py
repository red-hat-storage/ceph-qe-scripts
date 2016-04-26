import os
import boto
import boto.s3.connection
import sys
from boto.s3.key import Key

from random import randint

access_key = 'W21H8020LFKYOGMDIQSO'
secret_key = 'OYhR8MhVEYMPqJvXnDntGDERxueNDMG5lnCs9XNo'
#objname = sys.argv[2]
#bucket_name = sys.argv[1]
#filename = '/tmp/big.dat'

conn = boto.connect_s3(
    aws_access_key_id = access_key,
    aws_secret_access_key = secret_key,
    host = 'magna079',
    port = 7280,
    is_secure=False,
    calling_format = boto.s3.connection.OrdinaryCallingFormat(),
    )


bu = conn.lookup('bbuck1')
#bu.configure_versioning(True)

#k = Key(bu)
#k.key = 'my_fle.pdf'
#k.set_contents_from_filename('1.pdf')
#k.set_contents_from_filename('2.pdf')

# versions = list(bu.list_versions('my_fle.pdf'))
# print [k.version_id for k in versions]

bu.delete_key('my_fle.pdf')


print '---------->deleing key'

versions = list(bu.list_versions('my_fle.pdf'))
keys = [k.version_id for k in versions]

keys_lenght = len(keys)
print '------------>keys_lenght: %s' % keys_lenght
print "\n".join(keys)



# all = conn.get_all_buckets()
#
# for i in all:
#     print i

# b = conn.lookup('think.batman')
#
#
# all_keys = b.get_all_keys()
#
# for key in all_keys:
#     print '--------------'
#     print 'name: %s' % key.name
#     print 'size: %s' % key.size
#     print 'etag: %s' % key.etag
#     print 'md5: %s' % key.md5
#     print 'downloading file'
#     key.get_contents_to_filename('downloaded.mpFile')
#
#     print '--------------'


"""
mp = boto.s3.multipart.MultiPartUpload(b)

#mp = b.initiate_multipart_upload('testmpupload2')

fp = open('xaa', 'rb')

mp.upload_part_from_file(fp, 1)

fp.close()

fp = open('xab', 'rb')

mp.upload_part_from_file(fp, 2)

fp.close()

fp = open('xac', 'rb')

mp.upload_part_from_file(fp, 3)

fp.close()

fp = open('xad', 'rb')

mp.upload_part_from_file(fp, 4)

fp.close()

for part in mp:
    print part.part_number, part.size

mp.complete_upload()

"""