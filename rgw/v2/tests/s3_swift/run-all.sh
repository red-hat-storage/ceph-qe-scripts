#!/usr/bin/env bash
DIR="$( cd "$( dirname "${BASH_SOURCE[0]}" )" >/dev/null 2>&1 && pwd )"

scripts=(
          "python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets.yaml"
          "python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects.yaml"
          "python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_download.yaml"
          "python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_aws4.yaml"
          "python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_compression.yaml"
          "python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_delete.yaml"
          "python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_enc.yaml"
          "python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_multipart.yaml"
          "python3 $DIR/test_Mbuckets_with_Nobjects.py -c $DIR/configs/test_Mbuckets_with_Nobjects_sharding.yaml"
          "python3 $DIR/test_multitenant_user_access.py -c $DIR/configs/test_multitenant_access.yaml"
          "python3 $DIR/test_swift_basic_ops.py -c $DIR/configs/test_swift_basic_ops.yaml" # needs to check
          "python3 $DIR/test_swift_bulk_delete.py -c $DIR/configs/test_swift_bulk_delete.yaml" # needs to check
          "python3 $DIR/test_tenant_user_secret_key.py -c $DIR/configs/test_tenantuser_secretkey_gen.yaml"
          "python3 $DIR/test_versioning_copy_objects.py -c $DIR/configs/test_versioning_copy_objects.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_enable.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_acls.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_copy.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_delete.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_delete_from_another_user.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_enable.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_suspend.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_suspend_from_another_user.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_objects_suspend_re-upload.yaml"
          "python3 $DIR/test_versioning_with_objects.py -c $DIR/configs/test_versioning_suspend.yaml"
          "python3 $DIR/test_bucket_lifecycle_config_ops.py -c $DIR/configs/test_bucket_lifecycle_config_disable.yaml"
          "python3 $DIR/test_bucket_lifecycle_config_ops.py -c $DIR/configs/test_bucket_lifecycle_config_modify.yaml"
          "python3 $DIR/test_bucket_lifecycle_config_ops.py -c $DIR/configs/test_bucket_lifecycle_config_read.yaml"
          "python3 $DIR/test_bucket_lifecycle_config_ops.py -c $DIR/configs/test_bucket_lifecycle_config_versioning.yaml"
          "python3 $DIR/test_bucket_policy_ops.py -c $DIR/configs/test_bucket_policy_delete.yaml"
          "python3 $DIR/test_bucket_policy_ops.py -c $DIR/configs/test_bucket_policy_modify.yaml"
          "python3 $DIR/test_bucket_policy_ops.py -c $DIR/configs/test_bucket_policy_replace.yaml"
          "python3 $DIR/test_bucket_request_payer.py -c $DIR/configs/test_bucket_request_payer.yaml"
          "python3 $DIR/test_bucket_request_payer.py -c $DIR/configs/test_bucket_request_payer_download.yaml"
          "python3 $DIR/test_byte_range.py -c $DIR/configs/test_byte_range.yaml"
          "python3 $DIR/test_dynamic_bucket_resharding.py -c $DIR/configs/test_manual_resharding.yaml" # need to check
          "python3 $DIR/test_dynamic_bucket_resharding.py -c $DIR/configs/test_dynamic_resharding.yaml" # need to check
          "python3 $DIR/test_frontends_with_ssl.py -c $DIR/configs/test_ssl_beast.yaml"
          "python3 $DIR/test_frontends_with_ssl.py -c $DIR/configs/test_ssl_civetweb.yaml"
          "python3 $DIR/user_op_using_rest.py -c $DIR/configs/test_user_with_REST.yaml"
          "python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_date.yaml"
          "python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_multiple_rule_prefix_current_days.yaml"
          "python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_rule_prefix_and_tag.yaml"
          "python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_rule_prefix_non_current_days.yaml"
          "python3 $DIR/test_bucket_lifecycle_object_expiration.py -c $DIR/configs/test_lc_rule_delete_marker.yaml"
          "python3 $DIR/test_bucket_listing.py -c $DIR/configs/test_bucket_listing_flat_ordered.yaml"
          "python3 $DIR/test_bucket_listing.py -c $DIR/configs/test_bucket_listing_flat_unordered.yaml"
          "python3 $DIR/test_bucket_listing.py -c $DIR/configs/test_bucket_listing_flat_ordered_versionsing.yaml"
          "python3 $DIR/test_bucket_listing.py -c $DIR/configs/test_bucket_listing_pseudo_ordered.yaml"
          "python3 $DIR/test_bucket_listing.py -c $DIR/configs/test_bucket_listing_pseudo_ordered_dir_only.yaml"
          "python3 $DIR/test_gc_with_resharding.py -c $DIR/configs/test_gc_resharding_bucket.yaml"
          "python3 $DIR/test_gc_with_resharding.py -c $DIR/configs/test_gc_resharding_versioned_bucket.yaml"
        )

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
