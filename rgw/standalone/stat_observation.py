# This is RAW script which dumps bucket stats into file for every  5 seconds until bucket syncs completely on both sites
# Please change bucket name with actual bucket name

import json
import subprocess
import time

bucket_name = "<bucket name>"
while True:
    p = subprocess.Popen(
        "cephadm shell -- radosgw-admin sync status", stdout=subprocess.PIPE, shell=True
    )
    check_sync_status, err = p.communicate()
    check_sync_status = str(check_sync_status)

    p = subprocess.Popen("cephadm shell -- date", stdout=subprocess.PIPE, shell=True)
    dt, err = p.communicate()

    cmd = f"cephadm shell -- radosgw-admin bucket stats --bucket {bucket_name} --format json"
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    out, err = p.communicate()

    op = json.loads(out)
    num_object = op["usage"]["rgw.main"]["num_objects"]
    num_shards = op["num_shards"]
    bucket = op["bucket"]
    bucket_id = op["id"]
    actual_size = op["usage"]["rgw.main"]["size_actual"]
    current_data = (
        "DATE: "
        + str(dt)
        + "\t"
        + "Bucket: "
        + str(bucket)
        + " Bucket_ID: "
        + str(bucket_id)
        + " OBJECT_COUNT: "
        + str(num_object)
        + " NUM_SHARDS: "
        + str(num_shards)
        + " Actual_size: "
        + str(actual_size)
    )

    cmd = f"echo {current_data} >> observation_{bucket_name}"
    p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    time.sleep(5)
    if "data is caught up with source" in check_sync_status:
        break
