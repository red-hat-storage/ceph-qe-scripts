from time import sleep
import subprocess
import json


def check_free_space(current_raw_middles):
    output = subprocess.check_output(['sudo', 'ceph', 'df', '--cluster', cluster_name, '--format', 'json'])
    json_output = json.loads(output)
    total_bytes = float(json_output['stats']['total_bytes'])
    total_used_bytes = float(json_output['stats']['total_used_bytes'])
    last_raw_used = format(((total_used_bytes / total_bytes) * 100), '.2f')
    if(last_raw_used>current_raw_middles):
        print "##############################--RESULT--######################################"
        print "After Creating pool", current_raw_used
        print "After Benchmark", current_raw_middles
        print "After Script Execution ", last_raw_used
        print "##############################################################################"

        subprocess.Popen(
            ["sudo", "ceph", "osd", "pool", "delete", pool_name, pool_name, "--yes-i-really-really-mean-it",
             "--cluster", cluster_name]).wait()
        print "Passed"
        exit(0)
    else:
        check_free_space(current_raw_middles)


pool_name="spacereleasepool"
img_name= "spaceimage"
snap_name= "spacesnap"
cluster_name="ceph"
percent_to_fill=10.0
image_size="20480"
iterator_deletion=0
iterator_creation=0

subprocess.Popen(["sudo","ceph","osd","pool","create",pool_name,"128","128","--cluster",cluster_name]).wait()


output = subprocess.check_output(['sudo', 'ceph', 'df', '--cluster', cluster_name, '--format', 'json'])
json_output = json.loads(output)
total_bytes = float(json_output['stats']['total_bytes'])
total_used_bytes = float(json_output['stats']['total_used_bytes'])
current_raw_used = float(format(((total_used_bytes / total_bytes) * 100), '.2f'))
throughput=float(current_raw_used+percent_to_fill)

print throughput
print ("Current Raw Used",current_raw_used,throughput)


while(current_raw_used<=throughput):
    img_name_new=img_name+str(iterator_creation)
    snap_name_new=snap_name+str(iterator_creation)
    subprocess.Popen(["sudo","rbd", "create",img_name_new,"--size",image_size,"--pool",pool_name,"--cluster",cluster_name]).wait()
    subprocess.Popen(["sudo","rbd","snap","create",img_name_new+"@"+snap_name_new,"--pool",pool_name,"--cluster",cluster_name]).wait()
    subprocess.Popen(["sudo","rbd", "bench-write", img_name_new,"--pool", pool_name,"--cluster",cluster_name]).wait()
    output = subprocess.check_output(['sudo', 'ceph', 'df', '--cluster', cluster_name, '--format', 'json'])
    json_output = json.loads(output)
    total_bytes = float(json_output['stats']['total_bytes'])
    total_used_bytes = float(json_output['stats']['total_used_bytes'])
    current_raw_middle = float(format(((total_used_bytes / total_bytes) * 100), '.2f'))
    current_raw_used=current_raw_middle;
    iterator_creation=iterator_creation+1
    print "******************************************************************************"
    print ("Iteration count ", iterator_creation)
    print ("Throughtput     " , throughput)
    print ("Current Raw Used" , current_raw_used)
    print "******************************************************************************"



while(iterator_deletion<iterator_creation):
    img_name_new = img_name + str(iterator_deletion)
    snap_name_new = snap_name + str(iterator_deletion)
    subprocess.Popen(["sudo", "rbd", "snap", "rm", img_name_new + "@" + snap_name_new, "--pool", pool_name,"--cluster",cluster_name]).wait()
    sleep(2)
    iterator_deletion=iterator_deletion+1

check_free_space(current_raw_middle)