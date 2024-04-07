#!/bin/bash

NFS_IP='54.83.99.90'

cd /root/IOT_DDoS/MEC-topo/
mount $NFS_IP:/var/nfs/general ./MECa
mount $NFS_IP:/var/nfs/general2 ./MECb
echo 'Mount successful"