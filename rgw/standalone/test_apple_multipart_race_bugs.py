#!/usr/bin/env python3
"""
Automated Test Suite for Apple Multipart Race Condition Bugs

This script tests TWO related but distinct bugs in RGW multipart upload handling:

1. JIRA 13821: Empty ETag Bug
   - Empty ETag returned in concurrent CompleteMultipartUpload requests
   - Severity: Medium (cosmetic/API compliance issue, no data loss)
   - Symptom: HTTP 200 with empty ETag ("")

2. JIRA IBMCEPH-13341 / Tracker #75375: Ghost Object Bug (Apple Data Loss)
   - CompleteMultipartUpload retry causes GC to delete tail objects
   - Severity: High (DATA LOSS)
   - Symptom: HEAD returns 200 OK but GET returns 404 NoSuchKey

Both bugs are triggered by concurrent/retry CompleteMultipartUpload operations
but have different root causes and impacts.

PRE-REQUISITES:
    1. RGW cluster with S3 API enabled
    2. boto3 Python library
    3. radosgw-admin CLI access (for ghost object test)
    4. Valid S3 credentials
    5. (Optional) OSD latency injection for higher reproduction rate

RECOMMENDED CONFIGURATION FOR REPRODUCTION:
    # OSD latency (60ms per operation)
    ceph config set osd osd_debug_inject_dispatch_delay_duration 0.06
    ceph config set osd osd_debug_inject_dispatch_delay_probability 1.0

    # Multipart lock timeout (3 seconds)
    ceph config set client.rgw rgw_mp_lock_max_time 3

    # Restart RGW
    ceph orch restart <rgw-service-name>

USAGE:
    # Run both tests
    python3 test_apple_multipart_race_bugs.py \\
        --endpoint http://hostname:port \\
        --access-key ACCESS_KEY \\
        --secret-key SECRET_KEY

    # Run only empty ETag test (JIRA 13821)
    python3 test_apple_multipart_race_bugs.py \\
        --endpoint http://hostname:port \\
        --access-key ACCESS_KEY \\
        --secret-key SECRET_KEY \\
        --test empty-etag

    # Run only ghost object test (JIRA IBMCEPH-13341)
    python3 test_apple_multipart_race_bugs.py \\
        --endpoint http://hostname:port \\
        --access-key ACCESS_KEY \\
        --secret-key SECRET_KEY \\
        --test ghost-object

    # Show configuration commands
    python3 test_apple_multipart_race_bugs.py --show-config

AUTHOR: Vidushi Mishra
DATE: May 2026
JIRA: 13821, IBMCEPH-13341
"""

import argparse
import json
import subprocess
import sys
import threading
import time
from datetime import datetime

import boto3


class AppleMultipartRaceTests:
    def __init__(self, endpoint, access_key, secret_key, num_parts=100, part_size=5):
        self.endpoint = endpoint
        self.access_key = access_key
        self.secret_key = secret_key
        self.num_parts = num_parts
        self.part_size_mb = part_size
        self.part_size_bytes = part_size * 1024 * 1024

        self.s3 = boto3.client(
            "s3",
            endpoint_url=endpoint,
            aws_access_key_id=access_key,
            aws_secret_access_key=secret_key,
        )

        self.results = {
            "empty_etag": {
                "tested": False,
                "reproduced": False,
                "iterations": 0,
                "count": 0,
            },
            "ghost_object": {
                "tested": False,
                "reproduced": False,
                "iterations": 0,
                "count": 0,
            },
        }

    def log(self, message, level="INFO"):
        timestamp = datetime.now().strftime("%Y-%m-%d %H:%M:%S.%f")[:-3]
        colors = {
            "INFO": "\033[0;36m",
            "WARNING": "\033[1;33m",
            "ERROR": "\033[0;31m",
            "SUCCESS": "\033[0;32m",
            "RESET": "\033[0m",
        }
        color = colors.get(level, colors["INFO"])
        reset = colors["RESET"]
        print(f"{color}[{timestamp}] [{level}] {message}{reset}")

    def create_bucket(self, bucket_name):
        try:
            self.s3.create_bucket(Bucket=bucket_name)
            self.log(f"Created bucket: {bucket_name}")
            return True
        except Exception as e:
            self.log(f"Failed to create bucket: {e}", "ERROR")
            return False

    def upload_parts(self, bucket, key, upload_id):
        parts = []
        self.log(f"Uploading {self.num_parts} parts ({self.part_size_mb}MB each)...")

        start_time = time.time()
        for i in range(1, self.num_parts + 1):
            try:
                part = self.s3.upload_part(
                    Bucket=bucket,
                    Key=key,
                    UploadId=upload_id,
                    PartNumber=i,
                    Body=b"x" * self.part_size_bytes,
                )
                parts.append({"PartNumber": i, "ETag": part["ETag"]})

                if i % 10 == 0:
                    self.log(f"  Uploaded part {i}/{self.num_parts}")
            except Exception as e:
                self.log(f"Failed to upload part {i}: {e}", "ERROR")
                return None

        duration = time.time() - start_time
        self.log(f"All parts uploaded in {duration:.1f} seconds")

        return parts

    def complete_upload_thread(self, bucket, key, upload_id, parts, thread_id, results):
        start = time.time()
        try:
            response = self.s3.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
            duration = time.time() - start
            etag = response.get("ETag", "")
            status = response["ResponseMetadata"]["HTTPStatusCode"]

            result = {
                "thread": thread_id,
                "status": status,
                "etag": etag,
                "duration": duration,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            }
            results.append(result)

            self.log(
                f"Thread {thread_id}: HTTP {status}, ETag: '{etag}', Time: {duration:.2f}s"
            )
        except Exception as e:
            duration = time.time() - start
            result = {
                "thread": thread_id,
                "error": str(e),
                "duration": duration,
                "timestamp": datetime.now().strftime("%H:%M:%S.%f")[:-3],
            }
            results.append(result)
            self.log(f"Thread {thread_id}: ERROR - {e}, Time: {duration:.2f}s", "ERROR")

    def test_empty_etag(self, iteration=1):
        """
        JIRA 13821: Test for empty ETag in concurrent CompleteMultipartUpload

        Method: Send 3 concurrent complete requests and check if any return empty ETag
        """
        bucket = f"jira-13821-test-{int(time.time())}"
        key = f"empty-etag-test-object-{iteration}"

        self.log("=" * 70)
        self.log(f"TEST 1: Empty ETag Bug (JIRA 13821) - Iteration {iteration}")
        self.log("=" * 70)

        # Create bucket
        if not self.create_bucket(bucket):
            return False

        # Start multipart upload
        try:
            upload_resp = self.s3.create_multipart_upload(Bucket=bucket, Key=key)
            upload_id = upload_resp["UploadId"]
            self.log(f"Upload ID: {upload_id}")
        except Exception as e:
            self.log(f"Failed to create multipart upload: {e}", "ERROR")
            return False

        # Upload parts
        parts = self.upload_parts(bucket, key, upload_id)
        if not parts:
            return False

        # Concurrent complete requests
        self.log("Launching 3 concurrent CompleteMultipartUpload requests...")

        thread_results = []
        threads = []

        for i in range(1, 4):
            t = threading.Thread(
                target=self.complete_upload_thread,
                args=(bucket, key, upload_id, parts, i, thread_results),
            )
            threads.append(t)
            t.start()
            time.sleep(0.01)  # 10ms stagger

        # Wait for all threads
        for t in threads:
            t.join()

        # Analyze results
        self.log("RESULTS ANALYSIS:")

        empty_etag_found = False
        valid_etags = []

        for r in sorted(thread_results, key=lambda x: x.get("thread", 0)):
            if "etag" in r:
                if r["etag"] == "" or r["etag"] == '""':
                    self.log(f"Thread {r['thread']}: EMPTY ETAG DETECTED!", "WARNING")
                    empty_etag_found = True
                else:
                    valid_etags.append(r["etag"])

        # Verify object integrity
        try:
            head = self.s3.head_object(Bucket=bucket, Key=key)
            get = self.s3.get_object(Bucket=bucket, Key=key)
            self.log(f"✓ Object is accessible (HEAD and GET both work)", "SUCCESS")
        except Exception as e:
            self.log(f"✗ Object verification failed: {e}", "ERROR")

        # Cleanup
        try:
            self.s3.delete_object(Bucket=bucket, Key=key)
            self.s3.delete_bucket(Bucket=bucket)
        except Exception as e:
            self.log(f"Cleanup warning: {e}", "WARNING")

        # Verdict
        if empty_etag_found:
            self.log("✓✓✓ JIRA 13821 BUG REPRODUCED! Empty ETag detected", "WARNING")
            return True
        else:
            self.log("No empty ETag found in this iteration")
            return False

    def test_ghost_object(self, iteration=1):
        """
        JIRA IBMCEPH-13341: Test for ghost object (Apple data loss bug)

        Method: Use meta object restoration to simulate lock expiry and trigger GC deletion
        """
        bucket = f"jira-ibmceph-13341-test-{int(time.time())}"
        key = f"ghost-object-test-{iteration}"

        self.log("=" * 70)
        self.log(
            f"TEST 2: Ghost Object Bug (JIRA IBMCEPH-13341) - Iteration {iteration}"
        )
        self.log("=" * 70)

        # Create bucket
        if not self.create_bucket(bucket):
            return False

        # Get bucket ID for RADOS operations
        try:
            cmd = f"radosgw-admin bucket stats --bucket={bucket}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                self.log(
                    "radosgw-admin not available, skipping ghost object test", "WARNING"
                )
                return False

            bucket_stats = json.loads(result.stdout)
            bucket_id = bucket_stats["id"]
            self.log(f"Bucket ID: {bucket_id}")
        except Exception as e:
            self.log(f"Failed to get bucket ID: {e}", "ERROR")
            return False

        # Start multipart upload
        try:
            upload_resp = self.s3.create_multipart_upload(Bucket=bucket, Key=key)
            upload_id = upload_resp["UploadId"]
            self.log(f"Upload ID: {upload_id}")
        except Exception as e:
            self.log(f"Failed to create multipart upload: {e}", "ERROR")
            return False

        # Upload parts
        parts = self.upload_parts(bucket, key, upload_id)
        if not parts:
            return False

        # Backup meta object before first completion
        meta_oid = f"{bucket_id}_{key}.2~{upload_id.split('~')[1]}"
        backup_file = f"/tmp/meta_backup_{iteration}.bin"

        try:
            cmd = f"rados -p default.rgw.buckets.index get {meta_oid} {backup_file}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                self.log(f"Failed to backup meta object: {result.stderr}", "ERROR")
                return False
            self.log(f"Backed up meta object to {backup_file}")
        except Exception as e:
            self.log(f"Meta backup failed: {e}", "ERROR")
            return False

        # First complete (should succeed)
        try:
            resp1 = self.s3.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
            self.log(f"First complete succeeded: ETag={resp1['ETag']}", "SUCCESS")
        except Exception as e:
            self.log(f"First complete failed: {e}", "ERROR")
            return False

        # Restore meta object (simulates lock expiry)
        try:
            cmd = f"rados -p default.rgw.buckets.index put {meta_oid} {backup_file}"
            result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
            if result.returncode != 0:
                self.log(f"Failed to restore meta object: {result.stderr}", "ERROR")
                return False
            self.log("Restored meta object (simulating lock expiry)")
        except Exception as e:
            self.log(f"Meta restore failed: {e}", "ERROR")
            return False

        # Second complete (triggers the bug)
        try:
            resp2 = self.s3.complete_multipart_upload(
                Bucket=bucket,
                Key=key,
                UploadId=upload_id,
                MultipartUpload={"Parts": parts},
            )
            self.log(f"Second complete succeeded: ETag={resp2['ETag']}")
        except Exception as e:
            self.log(f"Second complete failed: {e}", "WARNING")

        # Wait for GC to process
        self.log("Waiting 30 seconds for GC processing...")
        time.sleep(30)

        # Verify object state (HEAD should work, GET should fail if bug exists)
        ghost_object_detected = False

        try:
            head = self.s3.head_object(Bucket=bucket, Key=key)
            self.log(
                f"✓ HEAD succeeded: ETag={head['ETag']}, Size={head['ContentLength']}",
                "SUCCESS",
            )

            try:
                get = self.s3.get_object(Bucket=bucket, Key=key)
                self.log(
                    f"✓ GET succeeded: Size={get['ContentLength']} bytes", "SUCCESS"
                )
                self.log("Object is normal (no ghost object)")
            except self.s3.exceptions.NoSuchKey:
                self.log("✗ GET failed with NoSuchKey (404)", "ERROR")
                self.log("🚨 GHOST OBJECT DETECTED! HEAD works but GET fails", "WARNING")
                ghost_object_detected = True
            except Exception as e:
                self.log(f"GET failed with unexpected error: {e}", "ERROR")

        except Exception as e:
            self.log(f"HEAD failed: {e}", "ERROR")

        # Cleanup
        try:
            subprocess.run(f"rm -f {backup_file}", shell=True)
            self.s3.delete_object(Bucket=bucket, Key=key)
            self.s3.delete_bucket(Bucket=bucket)
        except Exception as e:
            self.log(f"Cleanup warning: {e}", "WARNING")

        # Verdict
        if ghost_object_detected:
            self.log(
                "✓✓✓ JIRA IBMCEPH-13341 BUG REPRODUCED! Ghost object detected",
                "WARNING",
            )
            return True
        else:
            self.log("No ghost object detected in this iteration")
            return False

    def run_tests(self, test_type="all", iterations=5):
        """Run selected tests"""

        if test_type in ["all", "empty-etag"]:
            self.log("\n" + "=" * 70)
            self.log("STARTING EMPTY ETAG TESTS (JIRA 13821)")
            self.log("=" * 70 + "\n")

            self.results["empty_etag"]["tested"] = True
            self.results["empty_etag"]["iterations"] = iterations

            for i in range(1, iterations + 1):
                if self.test_empty_etag(iteration=i):
                    self.results["empty_etag"]["count"] += 1
                    self.results["empty_etag"]["reproduced"] = True
                time.sleep(2)

        if test_type in ["all", "ghost-object"]:
            self.log("\n" + "=" * 70)
            self.log("STARTING GHOST OBJECT TESTS (JIRA IBMCEPH-13341)")
            self.log("=" * 70 + "\n")

            self.results["ghost_object"]["tested"] = True
            self.results["ghost_object"]["iterations"] = iterations

            for i in range(1, iterations + 1):
                if self.test_ghost_object(iteration=i):
                    self.results["ghost_object"]["count"] += 1
                    self.results["ghost_object"]["reproduced"] = True
                time.sleep(2)

    def print_summary(self):
        """Print final test summary"""
        print("\n" + "=" * 70)
        print("FINAL TEST SUMMARY")
        print("=" * 70)

        for test_name, result in self.results.items():
            if result["tested"]:
                test_title = {
                    "empty_etag": "JIRA 13821 - Empty ETag Bug",
                    "ghost_object": "JIRA IBMCEPH-13341 - Ghost Object Bug",
                }[test_name]

                print(f"\n{test_title}:")
                print(f"  Iterations: {result['iterations']}")
                print(f"  Reproductions: {result['count']}")
                print(
                    f"  Success rate: {result['count']/result['iterations']*100:.1f}%"
                )

                if result["reproduced"]:
                    print(f"  Status: ✓ BUG REPRODUCED")
                else:
                    print(f"  Status: ⚠ Bug not reproduced (timing-dependent)")

        print("=" * 70 + "\n")


def show_configuration():
    """Show recommended Ceph configuration"""
    print("\n" + "=" * 70)
    print("RECOMMENDED CEPH CONFIGURATION FOR BUG REPRODUCTION")
    print("=" * 70)
    print(
        "\nThese settings increase the likelihood of reproducing the race conditions:"
    )
    print("\n1. Enable OSD latency injection (60ms per operation):")
    print("   ceph config set osd osd_debug_inject_dispatch_delay_duration 0.06")
    print("   ceph config set osd osd_debug_inject_dispatch_delay_probability 1.0")
    print("\n2. Reduce multipart lock timeout (3 seconds):")
    print("   ceph config set client.rgw rgw_mp_lock_max_time 3")
    print("\n3. Restart RGW daemons:")
    print("   ceph orch restart <rgw-service-name>")
    print("\n4. To revert configuration after testing:")
    print("   ceph config set osd osd_debug_inject_dispatch_delay_probability 0.0")
    print("   ceph config set client.rgw rgw_mp_lock_max_time 600")
    print("   ceph orch restart <rgw-service-name>")
    print("\n" + "=" * 70 + "\n")


def main():
    parser = argparse.ArgumentParser(
        description="Automated test suite for Apple multipart race condition bugs",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=__doc__,
    )

    parser.add_argument("--endpoint", help="RGW endpoint (e.g., http://hostname:8080)")
    parser.add_argument("--access-key", help="S3 access key")
    parser.add_argument("--secret-key", help="S3 secret key")
    parser.add_argument(
        "--test",
        choices=["all", "empty-etag", "ghost-object"],
        default="all",
        help="Which test to run (default: all)",
    )
    parser.add_argument(
        "--num-parts",
        type=int,
        default=100,
        help="Number of parts to upload (default: 100)",
    )
    parser.add_argument(
        "--part-size", type=int, default=5, help="Part size in MB (default: 5)"
    )
    parser.add_argument(
        "--iterations",
        type=int,
        default=5,
        help="Number of test iterations per bug (default: 5)",
    )
    parser.add_argument(
        "--show-config",
        action="store_true",
        help="Show recommended Ceph configuration and exit",
    )

    args = parser.parse_args()

    if args.show_config:
        show_configuration()
        return 0

    if not args.endpoint or not args.access_key or not args.secret_key:
        parser.error("--endpoint, --access-key, and --secret-key are required")

    # Run tests
    print(f"\n{'='*70}")
    print(f"APPLE MULTIPART RACE CONDITION BUG TEST SUITE")
    print(f"{'='*70}")
    print(f"Endpoint: {args.endpoint}")
    print(f"Test type: {args.test}")
    print(f"Parts: {args.num_parts} × {args.part_size}MB")
    print(f"Iterations: {args.iterations} per bug")
    print(f"{'='*70}\n")

    tester = AppleMultipartRaceTests(
        endpoint=args.endpoint,
        access_key=args.access_key,
        secret_key=args.secret_key,
        num_parts=args.num_parts,
        part_size=args.part_size,
    )

    tester.run_tests(test_type=args.test, iterations=args.iterations)
    tester.print_summary()

    # Return exit code based on results
    if any(r["reproduced"] for r in tester.results.values() if r["tested"]):
        return 1  # Bug(s) reproduced
    else:
        return 0  # No bugs reproduced


if __name__ == "__main__":
    sys.exit(main())
