# file may need fixing if being used anywhere.
def cmp(val1, val2):
    return (val1 > val2) - (val1 < val2)


def check_object_cmp(k1, k2):
    # compare key names
    cmp(k1.name, k2.name)
    cmp(k1.get_contents_as_string(), k2.get_contents_as_string())
    cmp(k1.metadata, k2.metadata)
    cmp(k1.content_type, k2.content_type)
    cmp(k1.etag, k2.etag)
    cmp(k1.size, k2.size)


def check_bucket_cmp(zone1, zone2, bucket_name):
    b1 = get_bucket(zone1, bucket_name)
    b2 = get_bucket(zone2, bucket_name)
    # compare buckets across zones

    for k1, k2 in zip_longest(b1.get_all_versions(), b2.get_all_versions()):
        if k1 is None:
            return False
        if k2 is None:
            return False

        check_object_cmp(k1, k2)

        # now get the keys through a HEAD operation, verify that the available data is the same
        k1_head = b1.get_key(k1.name)
        k2_head = b2.get_key(k2.name)

        check_object_cmp(k1_head, k2_head)
