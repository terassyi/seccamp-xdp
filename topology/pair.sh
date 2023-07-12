#!/bin/bash

ip netns add host0
ip netns add host1


ip link add h0 type veth peer name h1 netns host1
ip link set netns host0 dev h0

ip netns exec host0 ip link set up dev lo
ip netns exec host1 ip link set up dev lo

ip netns exec host0 ip link set up dev h0
ip netns exec host1 ip link set up dev h1

ip netns exec host0 ip addr add 10.0.0.1/24 dev h0
ip netns exec host1 ip addr add 10.0.0.2/24 dev h1

