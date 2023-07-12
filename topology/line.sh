#!/bin/bash

ip netns add host0
ip netns add host1
ip netns add host2

ip link add h0-h1 type veth peer name h1-h0 netns host1
ip link add h0-h2 type veth peer name h2-h0 netns host2
ip link set netns host0 dev h0-h1
ip link set netns host0 dev h0-h2

ip netns exec host0 ip link set up dev lo
ip netns exec host1 ip link set up dev lo
ip netns exec host2 ip link set up dev lo

ip netns exec host0 ip link set up dev h0-h1
ip netns exec host0 ip link set up dev h0-h2
ip netns exec host1 ip link set up dev h1-h0
ip netns exec host2 ip link set up dev h2-h0

ip netns exec host0 ip addr add 10.0.0.1/24 dev h0-h1
ip netns exec host0 ip addr add 10.0.1.1/24 dev h0-h2
ip netns exec host1 ip addr add 10.0.0.2/24 dev h1-h0
ip netns exec host2 ip addr add 10.0.1.2/24 dev h2-h0

ip netns exec host1 ip route add 10.0.1.0/24 via 10.0.0.1 dev h1-h0
ip netns exec host2 ip route add 10.0.0.0/24 via 10.0.1.1 dev h2-h0
