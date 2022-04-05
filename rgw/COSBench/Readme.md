# Procedure to configure COSBench and submit workloads

1. Install netcat and java on controller and all driver nodes
    - yum install nc
    - yum install java-1.8.0-openjdk.x86_64
 
2. Disable firewalld service or open respective ports on controller and all driver nodes

3. Download COSBench on controller and all driver nodes
    - wget https://github.com/intel-cloud/cosbench/releases/download/v0.4.2.c4/0.4.2.c4.zip
    - unzip 0.4.2.c4.zip
    - cd 0.4.2.c4
    - chmod 755 *.sh
   
4. Configure controller configuration file (0.4.2.c4/conf/controller.conf) only on controller node (Refer controller.conf file)

5. Configure HAproxy configuration file (/etc/haproxy/haproxy.cfg) on all driver nodes (Refer haproxy.cfg file)

6. If you have selinux turned on, you will need to ensure setsebool haproxy_connect_any on is allowed in order for stats to bind to port 1936 with this config. Execute following command on all driver nodes. 
    - setsebool -P haproxy_connect_any=1
    
7. Start HAproxy service

8. Check HAproxy stats on web browser
    - http://<driver-hostname>:1936/haproxy?stats
    
9. Start drivers on all driver node
    - cd 0.4.2.c4
    - ./start-driver.sh
    
10. Start controller on controller node
    - cd 0.4.2.c4
    - ./start-controller.sh
    
11. Access controller UI using port 19088
    - http://<controller-hostname>:19088/controller/index.html
    
12. Initiate IOs on cluster using controller UI
    - Perform write operation on cluster by submitting fill.xml workload on controller UI
    - Perform read/write/list/delete operation on cluster by submitting measure.xml workload on controller UI
