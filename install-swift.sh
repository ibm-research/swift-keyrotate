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
SWIFT=/vagrant/swift
SWIFTCLIENT=/vagrant/python-swiftclient
DISK=/dev/sdc
SERVICES_IP=192.168.50.11
LC_ALL=en_US.UTF-8
SWIFT_PROXY_USER=swift
SWIFT_PROXY_PASS=swift
SWIFT_PROXY_ENC_USER=swiftenc
SWIFT_PROXY_ENC_PASS=swiftencpass
SWIFT_PROXY_ENC_PROJECT=swiftencproj
SWIFT_USER_USER=swiftuser
SWIFT_USER_PASS=swiftuserpass
SWIFT_USER_PROJECT=swiftuserproject

if [ ! -d "$SWIFT" ]
then
  echo "Error, $SWIFT does not exist."
  exit 1
else
  echo "$SWIFT exists, continuing"
fi

# Enable multiverse repository
sudo sed -i '/multiverse$/s/^#//' /etc/apt/sources.list

# Add Openstack repositories
sudo apt -y update
sudo apt -y dist-upgrade

sudo apt -y install software-properties-common
sudo add-apt-repository -y cloud-archive:newton
sudo apt -y update
sudo apt -y dist-upgrade

# Swift AIO
sudo apt -y install curl gcc memcached rsync sqlite3 xfsprogs \
                    git-core libffi-dev python-setuptools \
                    libssl-dev
sudo apt -y install python-coverage python-dev python-nose \
                    python-xattr python-eventlet \
                    python-greenlet python-pastedeploy \
                    python-netifaces python-pip python-dnspython \
                    python-mock
sudo apt -y install python-keystonemiddleware python-keystoneclient \
                    python-barbicanclient python-openstackclient

# Development tools
sudo apt -y install git git-review gitk git-gui mc htop tmux

# Tools for building liberasurecode
sudo apt -y install build-essential autoconf automake libtool
# Tool for running tests
sudo apt -y install tox

# Build and install liberasurecode ourselves
cd ~
if [ ! -d liberasurecode ]
then
  git clone https://github.com/openstack/liberasurecode.git
fi
cd liberasurecode
git pull
./autogen.sh
./configure
make
sudo make install
if ! grep "/usr/local/lib" /etc/ld.so.conf ;
then
  echo "/usr/local/lib" | sudo tee -a /etc/ld.so.conf
fi
sudo ldconfig

sudo parted -s "$DISK" mklabel msdos
sudo parted -s "$DISK" mkpart primary ext4 0 "100%"
sudo mkdir -p /mnt/sdb1/{1..4}
echo "${DISK}1 /mnt/sdb1 xfs noatime,nodiratime,nobarrier,logbufs=8 0 0" | sudo tee -a /etc/fstab
sudo mkfs.xfs -m crc=0,finobt=0 "${DISK}"1
sudo mount /mnt/sdb1

sudo mkdir -p /srv
for x in {1..4}; do
    sudo ln -s /mnt/sdb1/$x /srv/$x;
done
sudo chown -R "$USER:$GROUPS" /srv/{1..4}

sudo mkdir -p /var/run/swift
sudo chown -R "$USER:$GROUPS" /var/run/swift

sudo sed -i '/^exit 0$/s/.*//' /etc/rc.local
echo "
mkdir -p /var/cache/swift /var/cache/swift2 /var/cache/swift3 /var/cache/swift4
chown $USER:$GROUPS /var/cache/swift*
mkdir -p /var/run/swift
chown $USER:$GROUPS /var/run/swift
sudo mount -t vboxsf -o uid=$UID,gid=$(id -g) vagrant /vagrant

exit 0
" | sudo tee -a /etc/rc.local
# Run the script to create the directories without having to reboot
sudo /etc/rc.local

# Upgrade pip
sudo pip install --upgrade pip
sudo apt autoremove -y --purge python-pip

# Clone swift repo
cd ~
git clone -b stable/pike https://github.com/openstack/swift.git
cd -

# Install requirements
cd ~/swift/
sudo pip install -r requirements.txt
sudo python setup.py develop
sudo pip install -r test-requirements.txt
cd -

# Install swift key rotation middleware
cd ${SWIFT}
sudo pip install -r requirements.txt
sudo python setup.py develop
cd -

# Set up rsync
sudo cp ~/swift/doc/saio/rsyncd.conf /etc/
sudo sed -i "s/<your-user-name>/$USER/" /etc/rsyncd.conf

sudo sed -i '/RSYNC_ENABLE/s/false/true/' /etc/default/rsync
sudo service rsync restart

# Configure swift
sudo rm -rf /etc/swift
sudo cp -r ~/swift/doc/saio/swift /etc/swift
sudo chown -R "$USER:$GROUPS" /etc/swift
find /etc/swift/ -name '*.conf' -exec sed -i "s/<your-user-name>/$USER/" {} \;

mkdir -p ~/bin
cp ~/swift/doc/saio/bin/* ~/bin
chmod +x ~/bin/*

cp ~/swift/test/sample.conf /etc/swift/test.conf
echo "export SWIFT_TEST_CONFIG_FILE=/etc/swift/test.conf" >> ~/.bashrc
echo "export PATH=$PATH:\~/bin" >> ~/.bashrc

# Set up keystone auth and remove tempauth
sed -i '/^bind_ip/s/127.0.0.1/0.0.0.0/' /etc/swift/proxy-server.conf
sed -i '/^pipeline/s/\(proxy-logging\)/authtoken keystoneauth \1/2' /etc/swift/proxy-server.conf
sed -i '/^pipeline/s/tempauth //g' /etc/swift/proxy-server.conf

cat >> /etc/swift/proxy-server.conf << EOF

[filter:authtoken]
auth_plugin = password
paste.filter_factory = keystonemiddleware.auth_token:filter_factory
password = swift
username = swift
project_name = service
auth_uri = http://$SERVICES_IP/identity
auth_url = http://$SERVICES_IP/identity
cache = swift.cache
include_service_catalog = False
delay_auth_decision = True
auth_version = v3.0

[filter:keystoneauth]
use = egg:swift#keystoneauth
operator_roles = admin, swiftoperator

EOF

# Set up crypto
sed -i '/^pipeline/s/\(proxy-logging\)/rotating_keymaster rotating_encryption \1/2' /etc/swift/proxy-server.conf

cat >> /etc/swift/proxy-server.conf << EOF

[filter:rotating_keymaster]
use = egg:swiftkeyrotate#rotating_keymaster
keymaster_config_path = /etc/swift/rotating_keymaster.conf

[filter:rotating_encryption]
use = egg:swiftkeyrotate#rotating_encryption
EOF

cat >> /etc/swift/rotating_keymaster.conf << EOF
[rotating_keymaster]
auth_endpoint = http://$SERVICES_IP/identity/v3
api_class = swiftkeyrotate.keyrotate_key_manager.KeyrotateKeyManager
EOF

# Set up logging
sudo cp ~/swift/doc/saio/rsyslog.d/10-swift.conf /etc/rsyslog.d/
sudo sed -i "/^\(\$PrivDropToGroup\).*$/s//\1 adm/" /etc/rsyslog.conf
sudo mkdir /var/log/swift
sudo chown -R "syslog:adm" /var/log/swift
sudo chmod -R g+w /var/log/swift
sudo service rsyslog restart

# Create openrcs.
rm -f ~/openrc.admin
cat >> ~/openrc.admin << EOF
export OS_AUTH_TYPE=password
export OS_AUTH_URL=http://$SERVICES_IP/identity/v3
export OS_IDENTITY_API_VERSION=3
export OS_PROJECT_DOMAIN_ID=default
export OS_REGION_NAME=RegionOne
export OS_USER_DOMAIN_ID=default
export OS_VOLUME_API_VERSION=2
export OS_NO_CACHE="1"
export OS_USERNAME=admin
export OS_PASSWORD=admin
export OS_PROJECT_NAME=admin
EOF

rm -f ~/openrc.proxy
cat >> ~/openrc.proxy << EOF
export OS_AUTH_TYPE=password
export OS_AUTH_URL=http://$SERVICES_IP/identity/v3
export OS_IDENTITY_API_VERSION=3
export OS_PROJECT_DOMAIN_ID=default
export OS_REGION_NAME=RegionOne
export OS_USER_DOMAIN_ID=default
export OS_VOLUME_API_VERSION=2
export OS_NO_CACHE="1"
export OS_PASSWORD="$SWIFT_PROXY_ENC_PASS"
export OS_PROJECT_NAME="$SWIFT_PROXY_ENC_PROJECT"
export OS_USERNAME="$SWIFT_PROXY_ENC_USER"
EOF

rm -f ~/openrc.swiftuser
cat >> ~/openrc.swiftuser << EOF
export OS_AUTH_TYPE=password
export OS_AUTH_URL=http://$SERVICES_IP/identity/v3
export OS_IDENTITY_API_VERSION=3
export OS_PROJECT_DOMAIN_ID=default
export OS_REGION_NAME=RegionOne
export OS_USER_DOMAIN_ID=default
export OS_VOLUME_API_VERSION=2
export OS_NO_CACHE="1"
export OS_PASSWORD="$SWIFT_USER_PASS"
export OS_PROJECT_NAME="$SWIFT_USER_PROJECT"
export OS_USERNAME="$SWIFT_USER_USER"
EOF

sudo apt clean

# Set up python-swiftclient
ln -s "$SWIFTCLIENT" ~/python-swiftclient
cd ~/python-swiftclient
sudo pip install -r requirements.txt; sudo python setup.py develop
sudo pip install -r test-requirements.txt
cd -

# The device is now /dev/sdc, but mounted on /mnt/sdb since this is hardcoded
# in lots of places.
sed -i "/^sudo mkfs/s/sdb/sdc/" ~/bin/resetswift

# Create key in barbican using proxy user (for kms_keymaster)
#source ~/openrc.proxy
#ORDER_HREF=`openstack secret order create --name swift_root_secret --payload-content-type="application/octet-stream" --algorithm aes --bit-length 256 key -f value -c 'Order href'`
#SECRET_HREF=`openstack secret order get -f value -c 'Secret href' "${ORDER_HREF}"`
#KEY_ID="${SECRET_HREF##*/}"
#echo "key_id = ${KEY_ID}" >> /etc/swift/kms_keymaster.conf

# Create key in barbican using swift end user (for rotating_keymaster)
source ~/openrc.swiftuser
ORDER_HREF=`openstack secret order create --name swift_root_secret --payload-content-type="application/octet-stream" --algorithm aes --bit-length 256 key -f value -c 'Order href'`
SECRET_HREF=`openstack secret order get -f value -c 'Secret href' "${ORDER_HREF}"`
KEY_ID="${SECRET_HREF##*/}"
echo "Created key for swift end user, ID: ${KEY_ID}"

~/bin/resetswift
~/bin/remakerings
~/bin/startmain
~/bin/startrest
