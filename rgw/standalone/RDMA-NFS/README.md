# NFS-RDMA Automated Test Suite

Automated test suite for IBM Ceph NFS over RDMA (NFS-Ganesha + RoCEv2).

## Structure

```
RDMA-NFS/
  nfs_rdma_tests.py       ← single main script — run this
  config/
    cluster.yaml          ← hosts, SSH, NFS, RDMA settings  (required)
    scale.yaml            ← scale test parameters            (optional)
    performance.yaml      ← performance test parameters      (optional)
  results/                ← auto-created, JSON results per run
  README.md
```

## Design

| Category | Where defined | How to customise |
|---|---|---|
| **Sanity** | hardcoded in `nfs_rdma_tests.py` | not needed |
| **Functional** | hardcoded in `nfs_rdma_tests.py` | not needed |
| **Regression** | hardcoded in `nfs_rdma_tests.py` | not needed |
| **Negative** | hardcoded in `nfs_rdma_tests.py` | not needed |
| **Performance** | driven by `config/performance.yaml` | edit file sizes, enable/disable tests |
| **Scale** | driven by `config/scale.yaml` | edit file counts, depth, workers |

## Requirements

```bash
pip install pyyaml
# sshpass must be installed on the machine running the script
brew install sshpass        # macOS
dnf install sshpass         # RHEL/CentOS
```

## Quick Start

```bash
cd RDMA-NFS

# 1. Edit cluster settings
vi config/cluster.yaml

# 2. Run sanity + functional + regression + negative (default)
python3 nfs_rdma_tests.py

# 3. Run everything including scale and performance
python3 nfs_rdma_tests.py --run all

# 4. Run only scale tests
python3 nfs_rdma_tests.py --run scale

# 5. Run only performance tests
python3 nfs_rdma_tests.py --run performance

# 6. Run against a specific client
python3 nfs_rdma_tests.py --client grim020

# 7. Custom config paths
python3 nfs_rdma_tests.py \
  --config config/cluster.yaml \
  --scale  config/scale.yaml \
  --perf   config/performance.yaml \
  --run    sanity,functional,scale
```

## Test Coverage

### Sanity (always run by default)
| ID | Test |
|---|---|
| SETUP-01..06 | SSH reachability, kernel modules, RDMA device, Ganesha, Ceph health, stale handles |
| T-01 | RDMA hardware validation |
| T-02 | NFS RDMA sync mount verification |
| T-04 | No TCP fallback confirmation |
| T-05 | Protocol verification via RDMA counter delta |

### Functional (always run by default)
| ID | Test |
|---|---|
| T-03 | Basic file ops: write / read / rename / delete |
| T-08 | Dual mount: RDMA + TCP same export simultaneously |
| T-09 | Directory depth-20 + 1000 files per level |
| T-10 | File permissions 644 / 755 / 400 |
| T-25 | File locking with concurrent writers |

### Performance (opt-in via `--run performance`, tunable in `performance.yaml`)
| ID | Test |
|---|---|
| T-06 | 1 GB write throughput |
| T-07 | 1 GB read + MD5 integrity |
| T-11 | Mixed file sizes 4 KB – 100 MB |
| T-12 | 10 GB write throughput |
| T-13 | 10 GB read throughput |
| T-14 | CPU utilisation during RDMA write (mpstat) |
| T-15 | N concurrent RDMA clients |
| T-16 | N RDMA + TCP mixed concurrent clients |

### Scale (opt-in via `--run scale`, tunable in `scale.yaml`)
| ID | Test |
|---|---|
| T-17 | 100 K files flat |
| T-18 | 2 M files, depth-20 tree, 100 K files/level, 4 KB each |
| T-19 | 10 M files (disabled by default — enable in `scale.yaml`) |

### Regression (always run by default)
| ID | Test |
|---|---|
| T-20 | I/O stability — sustained writes, no errors |
| T-21 | Ganesha restart with active RDMA mount |
| T-22 | RGW restart with active RDMA connections |

### Negative (always run by default)
| ID | Test |
|---|---|
| T-23 | No silent TCP fallback under RDMA mount |
| T-24 | Incompatible NIC types (auto-skipped if all nodes are same NIC) |

## Changing Scale / Performance Parameters

### Example: Run 10M files instead of 2M

Edit `config/scale.yaml`:
```yaml
scale:
  file_counts:
    - name: "10M files"
      count: 10000000
      enabled: true    # change from false to true
  dir_depth:
    total_files: 10000000
```

### Example: Add a 25 GB write test

Edit `config/performance.yaml`:
```yaml
performance:
  write_tests:
    - name: "25GB write"
      size_mb: 25600
      enabled: true
```

## Results

Each run produces a JSON file in `results/`:
```json
{
  "results": [
    {"id": "T-01", "name": "RDMA hardware validation", "verdict": "PASS",
     "notes": "device=mlx5_bond_0 fw=26.43.2026", "metrics": {...}},
    ...
  ],
  "summary": {"total": 22, "pass": 20, "fail": 0, "partial": 1, "skip": 1}
}
```

Exit code is `0` on all-pass, `1` if any test fails.

## Cluster Requirements

- IBM Ceph 9.2+ with NFS-Ganesha and RGW
- Mellanox ConnectX-5 or equivalent RoCEv2 NIC on all nodes
- `rpcrdma`, `ib_core`, `mlx5_ib` kernel modules loaded on NFS clients
- `sshpass` on the machine running the script
- `python3`, `pyyaml` on the machine running the script
- `ibv_devinfo`, `mpstat`, `dd`, `python3` on all remote nodes
