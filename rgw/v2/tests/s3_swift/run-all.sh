#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

scripts=("sudo python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets.yaml"
         "sudo python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects.yaml"
         "sudo python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_download.yaml"
         "sudo python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_aws4.yaml"
         "sudo python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_compression.yaml"
         "sudo python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_delete.yaml"
         "sudo python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_enc.yaml"
         "sudo python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_multipart.yaml"
         "sudo python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_sharding.yaml"
         "sudo python3 $DIR/test_multitenant_user_access.py -c $DIR/configs/test_multitenant_access.yaml"
         "sudo python3 $DIR/test_swift_basic_ops.py -c $DIR/configs/test_swift_basic_ops.yaml" # needs to check
         "sudo python3 $DIR/test_tenant_user_secret_key.py -c $DIR/configs/test_tenantuser_secretkey_gen.yaml"
         "sudo python3 $DIR/test_versioning_copy_objects.py -c $DIR/configs/test_versioning_copy_objects.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_enable.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_acls.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_copy.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_delete.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_delete_from_another_user.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_enable.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_suspend.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_suspend_from_another_user.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_suspend_re-upload.yaml"
         "sudo python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_suspend.yaml"
         "sudo python3 $DIR/test_bucket_lifecycle_config_ops.py -c $DIR/configs/test_bucket_lifecycle_config_disable.yaml"
         "sudo python3 $DIR/test_bucket_lifecycle_config_ops.py -c $DIR/configs/test_bucket_lifecycle_config_modify.yaml"
         "sudo python3 $DIR/test_bucket_lifecycle_config_ops.py -c $DIR/configs/test_bucket_lifecycle_config_read.yaml"
         "sudo python3 $DIR/test_bucket_lifecycle_config_ops.py -c $DIR/configs/test_bucket_lifecycle_config_versioning.yaml"
         "sudo python3 $DIR/test_bucket_policy_ops.py -c $DIR/configs/test_bucket_policy_delete.yaml"
         "sudo python3 $DIR/test_bucket_policy_ops.py -c $DIR/configs/test_bucket_policy_modify.yaml"
         "sudo python3 $DIR/test_bucket_policy_ops.py -c $DIR/configs/test_bucket_policy_replace.yaml"
         "sudo python3 $DIR/test_bucket_request_payer.py -c $DIR/configs/test_bucket_request_payer.yaml"
         "sudo python3 $DIR/test_bucket_request_payer.py -c $DIR/configs/test_bucket_request_payer_download.yaml"
         "sudo python3 $DIR/test_byte_range.py -c $DIR/configs/test_byte_range.yaml"
         "sudo python3 $DIR/test_dynamic_bucket_resharding.py -c $DIR/configs/test_manual_resharding.yaml" # need to check
         "sudo python3 $DIR/test_dynamic_bucket_resharding.py -c $DIR/configs/test_dynamic_resharding.yaml" # need to check
         "sudo python3 $DIR/test_frontends_with_ssl.py -c $DIR/configs/test_ssl_beast.yaml"
         "sudo python3 $DIR/test_frontends_with_ssl.py -c $DIR/configs/test_ssl_civetweb.yaml"
         "sudo python3 $DIR/user_op_using_rest.py -c $DIR/configs/test_user_with_REST.yaml"
         "sudo python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_date.yaml"
	 "sudo python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_multiple_rule_prefix_current_days.yaml"
	 "sudo python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_rule_prefix_and_tag.yaml"
	 "sudo python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_rule_prefix_non_current_days.yaml"
	 "sudo python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_rule_delete_marker.yaml")

for script in "${scripts[@]}"
do
    eval "$script"
    if [ $? -eq 0 ]
    then
      echo "The script ran ok"
    else
      echo "The script failed" >&2
      echo "$script"
      exit 1
    fi

done
