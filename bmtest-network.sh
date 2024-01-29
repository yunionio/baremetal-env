#!/bin/bash

BOND=vbmbond0
VETH0=vbmeth0
VETH1=vbmeth1
BMBR=bmbr0
MBR=$2
BRIP=$3

if [ -z "$BRIP" ]; then
    echo "$0 <start|stop> <master_br> <bm_br_ip>"
    exit 1
fi

MASKLEN=24

PREFIX="$(echo $BRIP | cut -d '.' -f 1,2,3).0/${MASKLEN}"

function requires_root {
    if [[ $EUID -ne 0 ]]; then
        echo "ERROR: You need sudo to run the program" 2>&1
        exit
    fi
}

requires_root

function start() {
    ip link add dev $BOND type bond
    ip link add dev $VETH0 type veth peer name $VETH1
    ip link set $VETH1 master $BOND
    ovs-vsctl add-port $MBR $BOND
    ovs-vsctl add-br $BMBR
    ovs-vsctl add-port $BMBR $VETH0
    ip addr add "${BRIP}/${MASKLEN}" dev $BMBR
    ip link set $BOND up
    ip link set $VETH0 up
    ip link set $VETH1 up
    ip link set $BMBR up
    iptables -t filter -P FORWARD ACCEPT
    echo 1 > /proc/sys/net/ipv4/ip_forward
    while iptables -t nat -D POSTROUTING -s $PREFIX -j MASQUERADE &>/dev/null; do :; done
    iptables -t nat -A POSTROUTING -s $PREFIX -j MASQUERADE
}

function stop() {
    while iptables -t nat -D POSTROUTING -o $MBR -s $PREFIX -j MASQUERADE &>/dev/null; do :; done
    ovs-vsctl del-port $BMBR $VETH0
    ovs-vsctl del-br $BMBR
    ip link delete dev $VETH0
    ovs-vsctl del-port $MBR $BOND
    ip link delete dev $BOND
}

case $1 in
    start )
        stop
        start
        ;;
    stop )
        stop ;;
esac
