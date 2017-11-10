#!/bin/bash
# Copyright (c) 2017 IBM Corp.
#
# Licensed under the Apache License, Version 2.0 (the "License");
# you may not use this file except in compliance with the License.
# You may obtain a copy of the License at
#
#    http://www.apache.org/licenses/LICENSE-2.0
#
# Unless required by applicable law or agreed to in writing, software
# distributed under the License is distributed on an "AS IS" BASIS,
# WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or
# implied.
# See the License for the specific language governing permissions and
# limitations under the License.

# Configuration
DIR_DEVSTACK=/opt/devstack
SWIFT_IP=192.168.50.12
SERVICES_IP=192.168.50.11
OS_BRANCH=stable/pike

# Dependencies
sudo apt -y update
sudo apt -y dist-upgrade
sudo apt -y install git python-pbr

# Configure devstack with keystone and barbican
if [ -d $DIR_DEVSTACK ]
then
  sudo rm -rf $DIR_DEVSTACK
fi
sudo mkdir -p $DIR_DEVSTACK
sudo mkdir -p /opt/stack
sudo git clone -b ${OS_BRANCH} https://git.openstack.org/openstack-dev/devstack $DIR_DEVSTACK
sudo tee $DIR_DEVSTACK/local.conf << EOF
[[local|localrc]]
enable_plugin barbican https://git.openstack.org/openstack/barbican ${OS_BRANCH}
ADMIN_PASSWORD=admin
DATABASE_PASSWORD=admin
RABBIT_PASSWORD=admin
SERVICE_PASSWORD=\$ADMIN_PASSWORD
SERVICE_TOKEN=\$ADMIN_PASSWORD
KEYSTONE_BRANCH=${OS_BRANCH}
REQUIREMENTS_BRANCH=${OS_BRANCH}
LOGFILE=/opt/stack/logs/stack.sh.log
LOGDAYS=2
ENABLED_SERVICES=rabbit,mysql,key
VERBOSE=True
HOST_IP=$SERVICES_IP
EOF
sudo chown -R "$USER:$GROUPS" $DIR_DEVSTACK
sudo chown -R "$USER:$GROUPS" /opt/stack
$DIR_DEVSTACK/stack.sh

sudo apt clean

# Set up user and endpoints for swift in service project
. $DIR_DEVSTACK/openrc admin admin
SWIFT_PROXY_USER=swift
SWIFT_PROXY_PASS=swift
openstack service create --name=object-store --description="Swift Service" object-store
openstack user create $SWIFT_PROXY_USER --password $SWIFT_PROXY_PASS --project service
openstack role add admin --project service --user $SWIFT_PROXY_USER
openstack endpoint create --region RegionOne object-store public "http://${SWIFT_IP}:8080/v1/AUTH_%(tenant_id)s"
openstack endpoint create --region RegionOne object-store internal "http://${SWIFT_IP}:8080/v1/AUTH_%(tenant_id)s"
openstack endpoint create --region RegionOne object-store admin "http://${SWIFT_IP}:8080"

# Set up project and user for swift proxy to manage secrets in barbican
SWIFT_PROXY_ENC_USER=swiftenc
SWIFT_PROXY_ENC_PASS=swiftencpass
SWIFT_PROXY_ENC_PROJECT=swiftencproj
openstack project create --enable "${SWIFT_PROXY_ENC_PROJECT}"
openstack user create --password ${SWIFT_PROXY_ENC_PASS} --project ${SWIFT_PROXY_ENC_PROJECT} --enable ${SWIFT_PROXY_ENC_USER}
openstack role add --project ${SWIFT_PROXY_ENC_PROJECT} --user ${SWIFT_PROXY_ENC_USER} admin

# Create Swift end user for storing objects
SWIFT_USER_USER=swiftuser
SWIFT_USER_PASS=swiftuserpass
SWIFT_USER_PROJECT=swiftuserproject
openstack project create --enable "${SWIFT_USER_PROJECT}"
openstack user create --password ${SWIFT_USER_PASS} --project ${SWIFT_USER_PROJECT} --enable ${SWIFT_USER_USER}
openstack role add --project ${SWIFT_USER_PROJECT} --user ${SWIFT_USER_USER} admin
