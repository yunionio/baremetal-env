#!/bin/bash

set -e

REGISTRY=${REGISTRY:-registry.cn-beijing.aliyuncs.com/zexi}
VERSION=${VERSION:-20240129.0}
OCBOOT_IMAGE="$REGISTRY/dhcprelay:$VERSION"

CUR_DIR="$(pwd)"
CONTAINER_NAME="buildah-dhcprelay"

buildah_from_image() {
    if buildah ps | grep $CONTAINER_NAME; then
        buildah rm $CONTAINER_NAME
    fi
    local img="$1"
    echo "Using buildah pull $img"
    buildah from --name $CONTAINER_NAME "$img"
}

buildah_from_image "$OCBOOT_IMAGE"

CMD="/opt/yunion/bin/dhcprelay"

# --interface bmbr0 --ip 10.18.10.1 --relay $BR0_IP

buildah run -t --network host --cap-add=cap_sys_admin \
    "$CONTAINER_NAME" $CMD $@
