# This is RAW script which dumps bucket stats into file for every  5 seconds until bucket syncs completely on both sites
# Please change bucket name with actual bucket name

import json
import subprocess
import time

cmd = "netstat -nltp | egrep 'ceph-osd|radosgw|haproxy' | awk '{print $7}'"
p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
out, err = p.communicate()
# convert bytes -> str
out = out.decode().strip()
lines = out.split("\n")

result = {}
for line in lines:
    pid, proc = line.split("/")
    result[pid] = proc  # duplicates automatically removed

print(result)

while True:
    for pid, comp in result.items():
        p = subprocess.Popen("date", stdout=subprocess.PIPE, shell=True)
        dt, err = p.communicate()
        cmd = f"ps -u -p {pid} | awk '{{print $13, $2, $3, $6/1024}}' | tail -n 1"
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
        out, err = p.communicate()
        # convert bytes -> str and split into columns
        out = out.decode().strip().split()

        name = out[0]  # process name
        pid = out[1]  # PID
        cpu = out[2]  # %CPU
        memMB = out[3]  # memory in MB
        current_data = (
            "DATE: "
            + str(dt)
            + "\t"
            + " Daemon: "
            + str(name)
            + "\t"
            + " pid: "
            + str(pid)
            + "\t"
            + " cpu utilisation: "
            + str(cpu)
            + "\t"
            + " Memory: "
            + str(memMB)
            + "\t"
        )

        cmd = f"echo {current_data} >> upgrade-bkt-1_cpu_util_folio11"
        p = subprocess.Popen(cmd, stdout=subprocess.PIPE, shell=True)
    time.sleep(600)
