# import boto3
# from botocore.client import Config
# import os, hashlib
#
# access_key = '5F9FOGHVOW1CDZNYPIDV'
# secret_key = 'UAomKzbNKj7fCNMJHYQMxf1EyaTH4zSALMNRMcgi'
# hostname = '10.8.128.81'
# port = '8080'
# additional_config = None
# password = "32characterslongpassphraseneeded".encode('utf-8')
# encryption_key = hashlib.md5(password).hexdigest()
#
# def create_file(fname, size):
#
#     # give the size in mega bytes.
#
#     file_size = 1024 * 1024 * size
#
#     with open(fname, 'wb') as f:
#         f.truncate(file_size)
#
#     fname_with_path = os.path.abspath(fname)
#
#     # md5 = get_md5(fname)
#
#     return fname_with_path
#
# #fname  = create_file('sample_upload', 10)
# #print fname
#
#
#
# s3_conn_resource = boto3.resource('s3',
#                              aws_access_key_id=access_key,
#                              aws_secret_access_key=secret_key,
#                              endpoint_url='http://%s:%s' %(hostname, port),
#                              use_ssl=False,
#                              config=additional_config,
#                              )
#
# s3_conn_client = boto3.client('s3',
#                            aws_access_key_id= access_key,
#                            aws_secret_access_key=secret_key,
#                            endpoint_url='http://%s:%s' % (hostname, port),
#                            config=additional_config,
#                            )
#
#
# bucket_name = 'Buck4'
# buck1 = s3_conn_resource.Bucket(bucket_name)
# buck1.create()
#
# # buck1.upload_file('sample_upload2', 'sample')
#
# # with open('sample_upload4', 'r') as data:
# #     buck1.put_object(Body=data, Key='sample_upload4',
# #                      SSECustomerAlgorithm='AES256',
# #                      SSECustomerKey= encryption_key
# #                      )
#
#
# buck1.put_object(Body=open('sample'), Key='sample8',
#                  SSECustomerAlgorithm=None,
#                  SSECustomerKey=None
#                  )
#
# # print(s3_conn_client.put_object(Bucket='Buck2',Key='sample_obj',Body=open('sample'),SSECustomerAlgorithm='AES256',SSECustomerKey=encryption_key))
#
#
# # buck1.put_object(Key='myobject_aes2',Body=open('sample'),SSECustomerAlgorithm='AES256',  SSECustomerKey=encryption_key)
#
# # buck1.download_file('sample', 'sample_downloaded')
#
#
# for object in buck1.objects.all():
#     print object.key
#
# buck1.download_file('sample8','sample_download_enc1',ExtraArgs={'SSECustomerKey':encryption_key,'SSECustomerAlgorithm':'AES256'})
#
#
