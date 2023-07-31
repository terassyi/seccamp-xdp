#!/bin/bash

set -x

ip netns exec host5 ./app/app > ./run/app1.log &
echo $! > ./run/app1.pid

ip netns exec host6 ./app/app > ./run/app2.log &
echo $! > ./run/app2.pid
