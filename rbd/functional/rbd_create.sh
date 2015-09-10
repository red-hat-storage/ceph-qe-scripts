#!/bin/bash
for i in {1..10}
do
        rbd create Tanay-RBD/testing$i --size 10240 --image-format 2 --image-features 13 --order 22
        rbd snap create Tanay-RBD/testing$i@testingsnap$i
        rbd snap protect Tanay-RBD/testing$i@testingsnap$i
        rbd clone Tanay-RBD/testing$i@testingsnap$i Tanay-RBD/testingClone_new$i --image-features 13
        i=`expr $i+1`
done
