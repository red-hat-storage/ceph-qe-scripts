Procedure to configure COSBench and submitting workload

1. Install netcat and java on all driver and controller node
    # yum install nc
    # yum install java-1.8.0-openjdk.x86_64

2. Disable firewalld service or open respective ports on drivers and controller node
3. Download COSBench on controller as well as on driver node
    # wget https://github.com/intel-cloud/cosbench/releases/download/v0.4.2.c4/0.4.2.c4.zip
    # unzip 0.4.2.c4.zip
    # cd 0.4.2.c4
    # chmod 755 *.sh

4. Configure 0.4.2.c4/conf/controller.conf file on only controller node (Refer controller.conf file)
5. Configure HAproxy on all drivers (Refer haproxy.cfg file)
6. Start HAproxy service
7. Check HAproxy stats on web browser
    # http://<Driver Hostname>:1936/haproxy?stats

8. Start drivers from all driver node
    # cd 0.4.2.c4
    # ./stop-driver.sh

9. Start controller from controler node
    # cd 0.4.2.c4
    # ./start-controller.sh

10. Access controller UI using port 19088
    # http://<Controller Hostname>:19088/controller/index.html

11. Initiate IOs on cluster using controller UI
    # Perform write operation on cluster by submitting fill.xml workload on controller UI
    # Perform read/write/list/delete operation on cluster by submitting measure.xml workload on controller UI
