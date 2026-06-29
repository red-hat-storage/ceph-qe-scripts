# Apple Multipart Race Condition Bug Test Suite

Automated Python test for verifying two related RGW multipart upload bugs.

## Bugs Covered

### 1. JIRA 13821: Empty ETag Bug
- **Severity:** Medium (cosmetic/API compliance issue)
- **Symptom:** Concurrent CompleteMultipartUpload returns HTTP 200 with empty ETag ("")
- **Impact:** No data loss, but breaks S3 API compatibility

### 2. JIRA IBMCEPH-13341 (Tracker #75375): Ghost Object Bug
- **Severity:** High (DATA LOSS)
- **Symptom:** HEAD returns 200 but GET returns 404 (ghost object)
- **Impact:** Data inaccessible, production-critical

## Prerequisites

1. **Python 3.6+** with boto3:
   ```bash
   pip3 install boto3
   ```

2. **RGW Cluster** with S3 API enabled

3. **S3 Credentials**:
   ```bash
   radosgw-admin user create \
     --uid=test-user \
     --display-name="Test User" \
     --access-key=TEST_ACCESS_KEY \
     --secret=TEST_SECRET_KEY
   ```

4. **radosgw-admin CLI** (for ghost object test only)

5. **(Optional) OSD Latency Configuration** for higher reproduction rate:
   ```bash
   ceph config set osd osd_debug_inject_dispatch_delay_duration 0.06
   ceph config set osd osd_debug_inject_dispatch_delay_probability 1.0
   ceph config set client.rgw rgw_mp_lock_max_time 3
   ceph orch restart <rgw-service-name>
   ```

## Usage

### Show Configuration Help
```bash
python3 test_apple_multipart_race_bugs.py --show-config
```

### Run All Tests
```bash
python3 test_apple_multipart_race_bugs.py \
  --endpoint http://hostname:port \
  --access-key ACCESS_KEY \
  --secret-key SECRET_KEY \
  --iterations 5
```

### Run Only Empty ETag Test (JIRA 13821)
```bash
python3 test_apple_multipart_race_bugs.py \
  --endpoint http://grim019:5000 \
  --access-key ETAG_TEST_KEY \
  --secret-key ETAG_TEST_SECRET \
  --test empty-etag \
  --iterations 10
```

### Run Only Ghost Object Test (JIRA IBMCEPH-13341)
```bash
python3 test_apple_multipart_race_bugs.py \
  --endpoint http://grim019:5000 \
  --access-key ETAG_TEST_KEY \
  --secret-key ETAG_TEST_SECRET \
  --test ghost-object \
  --iterations 5
```

### Custom Configuration
```bash
python3 test_apple_multipart_race_bugs.py \
  --endpoint http://grim019:5000 \
  --access-key ETAG_TEST_KEY \
  --secret-key ETAG_TEST_SECRET \
  --num-parts 50 \
  --part-size 10 \
  --iterations 3
```

## Parameters

- `--endpoint`: RGW S3 endpoint (required)
- `--access-key`: S3 access key (required)
- `--secret-key`: S3 secret key (required)
- `--test`: Which test to run: `all`, `empty-etag`, or `ghost-object` (default: all)
- `--num-parts`: Number of multipart parts (default: 100)
- `--part-size`: Part size in MB (default: 5)
- `--iterations`: Number of iterations per bug (default: 5)
- `--show-config`: Show recommended Ceph configuration

## Expected Output

### If Bug is Present
```
✓✓✓ JIRA 13821 BUG REPRODUCED! Empty ETag detected
✓✓✓ JIRA IBMCEPH-13341 BUG REPRODUCED! Ghost object detected

FINAL TEST SUMMARY
==================================================================
JIRA 13821 - Empty ETag Bug:
  Iterations: 5
  Reproductions: 2
  Success rate: 40.0%
  Status: ✓ BUG REPRODUCED
```

### If Bug is Fixed
```
⚠ Bug not reproduced (timing-dependent)

FINAL TEST SUMMARY
==================================================================
JIRA 13821 - Empty ETag Bug:
  Iterations: 5
  Reproductions: 0
  Success rate: 0.0%
  Status: ⚠ Bug not reproduced (timing-dependent)
```

## Exit Codes

- `0`: No bugs reproduced (tests passed, bugs may be fixed)
- `1`: At least one bug reproduced (bug exists)

## Test Methods

### Empty ETag Test
1. Create multipart upload
2. Upload 100 parts (5MB each)
3. Send 3 concurrent CompleteMultipartUpload requests
4. Check if any response has empty ETag
5. Verify object is accessible (HEAD and GET)

### Ghost Object Test
1. Create multipart upload
2. Upload 100 parts (5MB each)
3. Backup meta object at RADOS level
4. Complete upload (Request 1) - succeeds
5. Restore meta object (simulates lock expiry)
6. Complete upload again (Request 2) - triggers race
7. Wait for GC processing (30 seconds)
8. Verify: HEAD should work, GET should fail if bug exists

## Troubleshooting

### boto3 not installed
```bash
pip3 install boto3
```

### radosgw-admin not found
Ensure you're running on a Ceph node with RGW installed, or the ghost object test will be skipped.

### Low reproduction rate
Apply OSD latency configuration:
```bash
python3 test_apple_multipart_race_bugs.py --show-config
```

### Permission denied
```bash
chmod +x test_apple_multipart_race_bugs.py
```

## Configuration Tuning

For **higher reproduction rate**, use these aggressive settings:
```bash
# Very slow OSDs (100ms latency)
ceph config set osd osd_debug_inject_dispatch_delay_duration 0.1
ceph config set osd osd_debug_inject_dispatch_delay_probability 1.0

# Very short lock timeout (3 seconds)
ceph config set client.rgw rgw_mp_lock_max_time 3

# More parts = longer completion time
--num-parts 200
```

For **realistic testing** (closer to production):
```bash
# Moderate OSD latency (30ms)
ceph config set osd osd_debug_inject_dispatch_delay_duration 0.03
ceph config set osd osd_debug_inject_dispatch_delay_probability 1.0

# Standard lock timeout (10 seconds)
ceph config set client.rgw rgw_mp_lock_max_time 10

# Smaller parts
--num-parts 50 --part-size 10
```

## Cleanup

After testing, revert configuration:
```bash
ceph config set osd osd_debug_inject_dispatch_delay_probability 0.0
ceph config set client.rgw rgw_mp_lock_max_time 600
ceph orch restart <rgw-service-name>
```

## Integration with CI/CD

```yaml
# Example GitLab CI job
test-apple-bugs:
  script:
    - python3 test_apple_multipart_race_bugs.py \
        --endpoint $RGW_ENDPOINT \
        --access-key $RGW_ACCESS_KEY \
        --secret-key $RGW_SECRET_KEY \
        --iterations 10
  allow_failure: true  # Timing-dependent
```

## Author
Vidushi Mishra - RGW QE Team

## References
- JIRA 13821: Empty ETag Bug
- JIRA IBMCEPH-13341: Ghost Object Bug
- GitHub PR #67696: Fix for ghost object bug
- Tracker #75375: Upstream bug tracker
