
from time import sleep
import subprocess


pool_name="spacereleasepool"
img_name= "spaceimage"
snap_name= "spacesnap"
cluster_name="ceph"
percent_to_fill=0.15
image_size="20480"
iterator_deletion=0
iterator_creation=0

subprocess.Popen(["sudo","ceph","osd","pool","create",pool_name,"128","128","--cluster",cluster_name]).wait()


output = subprocess.check_output(['sudo','ceph', 'df','--cluster',cluster_name])
for i in range(1,len(output)):
    output_list=output.split()
    current_raw_used = float(output_list[10])
    current_raw_used=float(current_raw_used)
throughput=current_raw_used+percent_to_fill
print ("Current Raw Used",current_raw_used)


while(current_raw_used<=throughput):
    img_name_new=img_name+str(iterator_creation)
    snap_name_new=snap_name+str(iterator_creation)
    subprocess.Popen(["sudo","rbd", "create",img_name_new,"--size",image_size,"--pool",pool_name,"--cluster",cluster_name]).wait()
    subprocess.Popen(["sudo","rbd","snap","create",img_name_new+"@"+snap_name_new,"--pool",pool_name,"--cluster",cluster_name]).wait()
    subprocess.Popen(["sudo","rbd", "bench-write", img_name_new,"--pool", pool_name,"--cluster",cluster_name]).wait()
    output = subprocess.check_output(['sudo','ceph', 'df','--cluster',cluster_name])
    for i in range(1, len(output)):
        output_list = output.split()
        current_raw_middle = float(output_list[10])
        current_raw_middle=float(current_raw_middle)
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
    sleep(5)
    iterator_deletion=iterator_deletion+1

print "10 Min to Go"
for i in range(1,10):
    sleep(60)
    print 10-i," Min to Go"
    output = subprocess.check_output(['sudo','ceph', 'df','--cluster',cluster_name])
    for i in range(1, len(output)):
        output_list = output.split()
        last_raw_used = float(output_list[10])
        last_raw_used = float(last_raw_used)


print "##############################--RESULT--######################################"
print "After Creating pool",current_raw_used
print "After Benchmark" , current_raw_middle
print "After Script Execution " , last_raw_used
print "##############################################################################"


if(last_raw_used<current_raw_middle):
    print "Passed"
    exit(0)
else:
    print "failed"
    exit(1)
