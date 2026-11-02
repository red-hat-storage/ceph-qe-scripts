# RGW QE v3

A standalone pytest suite for an existing Ceph RGW cluster. It provides reusable
boto3 operations, class-based feature tests, isolated resource ownership, and a
subprocess runner for standalone execution or cephCI. It has no v2 imports and
does not deploy or reconfigure the cluster.

## Install and verify offline

Use Python 3.10 or later. From this directory:

```bash
python3 -m venv .venv
source .venv/bin/activate
.venv/bin/python -m pip install -e .
.venv/bin/python -m pytest unit -q
.venv/bin/python -m pytest -q
```

Without `--rgw-config`, integration tests skip without creating clients or
contacting RGW. Unit tests use botocore stubs and fault injection. The package
includes the integration suites, so the installed runner also works outside the
source checkout. Do not run pytest against the entire legacy repository; target
this directory or use `rgw-v3`.

## Run CRUD sanity

Edit `configs/sanity.yaml` to set the endpoint and admin command for your cluster:

```bash
rgw-v3 --config configs/sanity.yaml --collect-only
rgw-v3 --config configs/sanity.yaml --artifacts artifacts/sanity
rgw-v3 --config configs/sanity.yaml -k test_copy
```

The default marker expression is `sanity`. Each scenario gets a fresh identity
and bucket. The P0 matrix includes normal, tenanted, account root, and IAM account
users against unversioned, versioning-enabled, and versioning-suspended buckets.
Each workload uses one bucket and 20 objects by default; counts are configurable.

Scenarios independently report PUT/GET/LIST with SHA-256 verification, COPY,
DELETE, multipart upload/download/copy/delete, incomplete upload listing/part
listing/abort, version history, and suspended null-version replacement. History
and null-version cases skip for bucket states where they do not apply.

Normal object PUT, GET, COPY, and DELETE use bounded boto3 threads. Multipart
operations currently run sequentially to bound payload memory. Tests themselves
run serially. The supported runner disables third-party pytest plugin autoload
and ignores inherited `PYTEST_ADDOPTS`; xdist is not part of this release.

## Cluster prerequisites and identities

The cluster must already have RGW and its backing OSD/monitor services available.
No particular node count is imposed. `radosgw-admin` needs cluster configuration
and credentials on the execution node. A command prefix such as
`[sudo, radosgw-admin]` or `[sudo, cephadm, shell, --, radosgw-admin]` is supported.
Commands are argv lists and are never run through a local shell. For a remote
admin node, prefer a fixed wrapper executable that accepts these arguments.

Account cases require a Ceph release supporting RGW accounts and an enabled IAM
API. New accounts/root users are created with the admin CLI; child account users,
policies, and access keys are created through IAM. Provisioning failures are test
errors, not capability skips. Narrow `user_types` for clusters lacking accounts.

To run without provisioning users, use `configs/existing-identity.yaml`. Set
`RGW_TEST_ACCESS_KEY_ID` and `RGW_TEST_SECRET_ACCESS_KEY` in the environment;
`RGW_TEST_SESSION_TOKEN` is optional. For a supplied tenanted identity, also set
`RGW_TEST_TENANT` so admin feature operations use the correct namespace. The identity needs bucket CRUD, versioning,
lifecycle, notification configuration, and multipart permissions. The suite only
removes buckets it created, and does not remove supplied users or their keys.

An `identities` mapping associates a user type with an environment variable
prefix. It must describe the identity's actual type; v3 does not infer that type
from a key. `configs/external-auth.yaml` covers supplied LDAP and STS credentials.
Provision the LDAP service and issue the LDAP/STS credentials externally. Sessions
must remain valid through cleanup; automatic credential refresh is not implemented.
LDAP/STS types without an identity mapping skip with an explicit prerequisite.

TLS verification defaults to true. `verify_tls` also accepts a CA bundle path.
Secrets are not accepted in YAML or endpoint URLs. Avoid pytest `--showlocals` and
SDK debug logging when handling real credentials.

## Feature suites

Features are enabled explicitly through `features` and selected with markers:

```bash
rgw-v3 --config configs/regression.yaml -m 'sanity or lifecycle or gc or resharding'
rgw-v3 --config configs/notifications.yaml -m notifications
rgw-v3 --config configs/optional-tools.yaml -m 'awscli or elbencho'
```

Feature tests use the first configured identity; lifecycle noncurrent tests create
a versioned bucket. Other feature tests use unversioned buckets.

| Feature | Behavior and prerequisites |
| --- | --- |
| Lifecycle | Policy set/get/delete, current expiration, noncurrent expiration, and incomplete multipart expiration; cluster background lifecycle processing must be enabled |
| GC | Delete a multipart object, observe bucket-specific GC tags, then wait for those tags to disappear; requires admin access and background GC |
| Resharding | Explicitly reshard an owned bucket, verify target shard count, listing, content, ACLs, and subsequent CRUD; requires admin access |
| Notifications | Create an owned SNS topic and HTTP receiver, validate creation/removal events for the exact bucket/key, then remove the subscription/topic/receiver |
| AWS CLI | Optional PUT/COPY/GET/LIST/DELETE with downloaded content verification; requires an installed `aws` executable |
| Elbencho | Optional write/read/delete with `--verify` integrity checking in an owned bucket; requires a recent Elbencho build with S3 support; boto3 handles listing and cleanup |

`timeout` bounds each polling stage and admin/tool subprocess; it is not an entire
suite deadline. SDK requests have separate connect/read timeouts and bounded
retries. A slow request can finish after the polling deadline. Timeout failures
identify the awaited condition; API permission and operation errors propagate.

Lifecycle days are real policy days. A default 300-second timeout cannot prove a
one-day expiration. Use an appropriately configured disposable cluster and/or a
long timeout; `regression.yaml` uses 48 hours per polling stage. The suite never
changes cluster-wide debug intervals or invokes global `gc process`. A GC timeout
before observation can mean the entry drained too quickly or the object did not
produce a deferred GC entry. Queue disappearance verifies queue processing, not
physical storage reclamation. Dynamic resharding and physical reclamation checks
are follow-up coverage.

For notifications, enable the RGW notifications API and persistent topics. Set
`notification.advertise_host` to the runner address reachable from every RGW;
`bind_host` is the local listener interface. The receiver uses an ephemeral TCP
port. Allow RGW to reach that port. Notification records can arrive in any order
and can be duplicated. No Kafka, AMQP, or external HTTP service is required.

Optional tools are opt-in via `optional_tools`; missing executables produce
capability skips. Once present, tool execution errors fail the test. Credentials
are passed through subprocess environments, not command arguments. Elbencho's
adapter uses one thread and exactly `objects` objects, supports its default TLS
verification, and is restricted to CRUD. boto3 remains the primary implementation.

## Cleanup and reports

Names contain a per-resource UUID. Fixtures register cleanup as soon as creation
succeeds. Teardown removes bucket notifications/policies, incomplete uploads,
versions, delete markers, current objects, and the bucket before removing owned
IAM keys, policies, users, and accounts. All registered finalizers are attempted;
cleanup failures are reported as teardown errors even when a test already failed.
A killed process or unavailable cluster can leave resources; use the reported
`rgwv3-*` names to inspect and remove only that run's resources.

The runner creates `junit.xml` and `pytest.log` under `--artifacts`, streams pytest
output, and returns pytest's exit code unchanged (including collection errors and
no tests selected). Use a distinct artifact directory for each concurrent run.
Logs intentionally omit admin stdout/stderr, which can contain generated keys.

## cephCI integration

`rgw_tests.cephci.run(ceph_cluster, **kwargs)` uses the existing cephCI node API.
Install v3 in the controller's environment for importing the adapter and on the
selected execution node. Supply an existing node-side YAML and artifact directory:

```yaml
config:
  node-role: client
  v3-python: /opt/rgw-v3/bin/python
  v3-config: /opt/rgw-v3/configs/sanity.yaml
  v3-artifacts: /tmp/rgw-v3-run-001
  markers: sanity
  timeout: 3600
```

Register a cephCI test module that imports `run` from `rgw_tests.cephci`, or invoke
`python -m rgw_tests.runner` directly through the harness. The adapter quotes
remote shell arguments and returns the node's execution status. Cluster access,
credential environment provisioning, dependency installation, and artifact
retrieval remain the harness's responsibility. The existing cephCI
`sanity_rgw.py` wrapper uses v1/v2 path mappings; setting `test-version: v3` there
alone does not enable v3. This repository does not modify that external checkout.

## Development and next coverage

`rgw_tests/operations` holds reusable behavior; `rgw_tests/suites` holds feature
classes and assertions; `unit` holds offline failure-path checks. Add new feature
cases using the shared resource registry, paginated operations, and bounded polls.
A feature must pass on a live cluster before treating it as migrated from v2.
Broader v2 parity, dynamic resharding, automatic LDAP/STS provisioning, distributed
pytest workers, and multisite tests remain future extensions.

Validation and formatting from the repository root:

```bash
python3 -m pytest rgw/v3 -q
python3 -m black --check rgw/v3
python3 -m isort --check-only rgw/v3
python3 -m yamllint rgw/v3/configs
```

Protocol references: [Ceph accounts](https://docs.ceph.com/en/latest/radosgw/account/),
[Ceph notifications](https://docs.ceph.com/en/latest/radosgw/notifications/),
[admin CLI](https://docs.ceph.com/en/latest/man/8/radosgw-admin/), and
[Elbencho S3 options](https://github.com/breuner/elbencho/blob/master/docs/usage/help-s3.md).
