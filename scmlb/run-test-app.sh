#!/bin/bash

set -x


ip netns exec host5 ../app/app &
echo $! > ./run/app1.pid

ip netns exec host6 ../app/app &
echo $! > ./run/app2.pid


ip netns exec host7 ../app/app &
echo $! > ./run/app3.pid
