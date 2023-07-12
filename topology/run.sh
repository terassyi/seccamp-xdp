#!/bin/bash

set -x

ip netns exec host3 ./app/app > ./run/app1.log &
echo $! > ./run/app1.pid

ip netns exec host4 ./app/app > ./run/app2.log &
echo $! > ./run/app2.pid

ip netns exec host2 nginx -p ./nginx -c nginx.conf &
echo $! > ./run/nginx.pid
