#!/bin/bash
set -x

ip netns add host0
ip netns add host1
ip netns add host2
ip netns add host3
ip netns add host4
ip netns add host5
ip netns add host6
ip netns add host7

ip link add h0-h1 type veth peer name h1-h0 netns host1
ip link add h0-h2 type veth peer name h2-h0 netns host2
ip link add h1-h3 type veth peer name h3-h1 netns host3
ip link add h1-h4 type veth peer name h4-h1 netns host4
ip link add h2-h5 type veth peer name h5-h2 netns host5
ip link add h2-h6 type veth peer name h6-h2 netns host6
ip link add h2-h7 type veth peer name h7-h2 netns host7

ip link set netns host0 dev h0-h1
ip link set netns host0 dev h0-h2
ip link set netns host1 dev h1-h3
ip link set netns host1 dev h1-h4
ip link set netns host2 dev h2-h5
ip link set netns host2 dev h2-h6
ip link set netns host2 dev h2-h7

ip netns exec host0 ip link set up dev lo
ip netns exec host1 ip link set up dev lo
ip netns exec host2 ip link set up dev lo
ip netns exec host3 ip link set up dev lo
ip netns exec host4 ip link set up dev lo
ip netns exec host5 ip link set up dev lo
ip netns exec host6 ip link set up dev lo
ip netns exec host7 ip link set up dev lo

ip netns exec host0 ip link set up dev h0-h1
ip netns exec host0 ip link set up dev h0-h2
ip netns exec host1 ip link set up dev h1-h0
ip netns exec host1 ip link set up dev h1-h3
ip netns exec host1 ip link set up dev h1-h4
ip netns exec host2 ip link set up dev h2-h0
ip netns exec host2 ip link set up dev h2-h5
ip netns exec host2 ip link set up dev h2-h6
ip netns exec host2 ip link set up dev h2-h7
ip netns exec host3 ip link set up dev h3-h1
ip netns exec host4 ip link set up dev h4-h1
ip netns exec host5 ip link set up dev h5-h2
ip netns exec host6 ip link set up dev h6-h2
ip netns exec host7 ip link set up dev h7-h2

ip netns exec host0 ip addr add 10.0.0.1/24 dev h0-h1
ip netns exec host0 ip addr add 10.0.1.1/24 dev h0-h2
ip netns exec host1 ip addr add 10.0.0.2/24 dev h1-h0
ip netns exec host2 ip addr add 10.0.1.2/24 dev h2-h0
ip netns exec host1 ip addr add 10.0.2.1/24 dev h1-h3
ip netns exec host1 ip addr add 10.0.3.1/24 dev h1-h4
ip netns exec host3 ip addr add 10.0.2.2/24 dev h3-h1
ip netns exec host4 ip addr add 10.0.3.2/24 dev h4-h1
ip netns exec host2 ip addr add 10.0.4.1/24 dev h2-h5
ip netns exec host2 ip addr add 10.0.5.1/24 dev h2-h6
ip netns exec host5 ip addr add 10.0.4.2/24 dev h5-h2
ip netns exec host6 ip addr add 10.0.5.2/24 dev h6-h2
ip netns exec host7 ip addr add 10.0.6.2/24 dev h7-h2
ip netns exec host2 ip addr add 10.0.6.1/24 dev h2-h7

ip netns exec host2 ip link add vipdev type dummy
ip netns exec host2 ip addr add 203.0.113.11/24 dev vipdev # テスト用のグローバルアドレス
ip netns exec host2 ip link set up dev vipdev

ip netns exec host0 ip route add 10.0.2.0/24 via 10.0.0.2 dev h0-h1
ip netns exec host0 ip route add 10.0.3.0/24 via 10.0.0.2 dev h0-h1
ip netns exec host0 ip route add 10.0.4.0/24 via 10.0.1.2 dev h0-h2
ip netns exec host0 ip route add 10.0.5.0/24 via 10.0.1.2 dev h0-h2
ip netns exec host0 ip route add 10.0.6.0/24 via 10.0.1.2 dev h0-h2

ip netns exec host0 ip route add 203.0.113.0/24 dev h0-h2 # テスト用のグローバルアドレスへの経路を割り当てます


ip netns exec host1 ip route add default via 10.0.0.1 dev h1-h0
ip netns exec host2 ip route add default via 10.0.1.1 dev h2-h0
ip netns exec host3 ip route add default via 10.0.2.1 dev h3-h1
ip netns exec host4 ip route add default via 10.0.3.1 dev h4-h1
ip netns exec host5 ip route add default via 10.0.4.1 dev h5-h2
ip netns exec host6 ip route add default via 10.0.5.1 dev h6-h2
ip netns exec host7 ip route add default via 10.0.6.1 dev h7-h2

ip netns exec host0 ping -c 1 10.0.0.2
ip netns exec host0 ping -c 1 10.0.1.2
ip netns exec host0 ping -c 1 10.0.2.2
ip netns exec host0 ping -c 1 10.0.3.2
ip netns exec host0 ping -c 1 10.0.4.2
ip netns exec host0 ping -c 1 10.0.5.2
ip netns exec host0 ping -c 1 10.0.6.2

ip netns exec host1 ping -c 1 10.0.0.1
ip netns exec host1 ping -c 1 10.0.1.2
ip netns exec host1 ping -c 1 10.0.2.2
ip netns exec host1 ping -c 1 10.0.3.2
ip netns exec host1 ping -c 1 10.0.4.2
ip netns exec host1 ping -c 1 10.0.5.2
ip netns exec host1 ping -c 1 10.0.6.2

ip netns exec host2 ping -c 1 10.0.0.2
ip netns exec host2 ping -c 1 10.0.1.1
ip netns exec host2 ping -c 1 10.0.2.2
ip netns exec host2 ping -c 1 10.0.3.2
ip netns exec host2 ping -c 1 10.0.4.2
ip netns exec host2 ping -c 1 10.0.5.2
ip netns exec host2 ping -c 1 10.0.6.2

ip netns exec host3 ping -c 1 10.0.0.2
ip netns exec host3 ping -c 1 10.0.1.2
ip netns exec host3 ping -c 1 10.0.2.1
ip netns exec host3 ping -c 1 10.0.3.2
ip netns exec host3 ping -c 1 10.0.4.2
ip netns exec host3 ping -c 1 10.0.5.2
ip netns exec host3 ping -c 1 10.0.6.2

ip netns exec host4 ping -c 1 10.0.0.2
ip netns exec host4 ping -c 1 10.0.1.2
ip netns exec host4 ping -c 1 10.0.2.2
ip netns exec host4 ping -c 1 10.0.3.1
ip netns exec host4 ping -c 1 10.0.4.2
ip netns exec host4 ping -c 1 10.0.5.2
ip netns exec host4 ping -c 1 10.0.6.2

ip netns exec host5 ping -c 1 10.0.0.1
ip netns exec host5 ping -c 1 10.0.1.2
ip netns exec host5 ping -c 1 10.0.2.2
ip netns exec host5 ping -c 1 10.0.3.2
ip netns exec host5 ping -c 1 10.0.4.1
ip netns exec host5 ping -c 1 10.0.5.2
ip netns exec host5 ping -c 1 10.0.6.2

ip netns exec host6 ping -c 1 10.0.0.1
ip netns exec host6 ping -c 1 10.0.1.2
ip netns exec host6 ping -c 1 10.0.2.2
ip netns exec host6 ping -c 1 10.0.3.2
ip netns exec host6 ping -c 1 10.0.4.2
ip netns exec host6 ping -c 1 10.0.5.1
ip netns exec host6 ping -c 1 10.0.6.2

ip netns exec host7 ping -c 1 10.0.0.1
ip netns exec host7 ping -c 1 10.0.1.2
ip netns exec host7 ping -c 1 10.0.2.2
ip netns exec host7 ping -c 1 10.0.3.2
ip netns exec host7 ping -c 1 10.0.4.2
ip netns exec host7 ping -c 1 10.0.5.2
ip netns exec host7 ping -c 1 10.0.6.1

ip netns exec host0 ping -c 1 203.0.113.11
ip netns exec host1 ping -c 1 203.0.113.11
ip netns exec host2 ping -c 1 203.0.113.11
ip netns exec host3 ping -c 1 203.0.113.11
