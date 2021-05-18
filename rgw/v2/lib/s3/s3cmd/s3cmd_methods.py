"""
Perform s3cmd operations
"""

import subprocess


def create_bucket(bucket_name):
    """
    Creates a bucket
    Args:
        bucket_name(str): Name of the bucket to be created
    """
    response = subprocess.check_output(['s3cmd','mb','s3://'+bucket_name])
    print(response)

def delete_bucket(bucket_name):
    """
    Deletes a bucket
    Args:
        bucket_name(str): Name of the bucket to be deleted
    """
    response = subprocess.check_output(['s3cmd','rb','s3://'+bucket_name])
    print(response)

delete_bucket('rhiniyan')


d = [{"method": "create_bucket", "op": "mb", "params":["s3://bucket"]}]