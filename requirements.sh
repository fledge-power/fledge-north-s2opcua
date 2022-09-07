#!/usr/bin/env bash

##---------------------------------------------------------------------------
## Copyright (c) 2022 Dianomic Systems Inc.
##
## Licensed under the Apache License, Version 2.0 (the "License");
## you may not use this file except in compliance with the License.
## You may obtain a copy of the License at
##
##     http://www.apache.org/licenses/LICENSE-2.0
##
## Unless required by applicable law or agreed to in writing, software
## distributed under the License is distributed on an "AS IS" BASIS,
## WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
## See the License for the specific language governing permissions and
## limitations under the License.
##---------------------------------------------------------------------------

##
## Author: Amandeep Singh Arora, Mark Riddoch, Jeremie Chabod
##

function fail() {
    CODE=$1
    shift
    echo "[EE] (code $CODE) $*"
    exit $CODE
}

os_name=`(grep -o '^NAME=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')`
os_version=`(grep -o '^VERSION_ID=.*' /etc/os-release | cut -f2 -d\" | sed 's/"//g')`
echo "Platform is ${os_name}, Version: ${os_version}"

export DEV_ROOT=`cd .. && pwd`
[ "$1" != "" ] && DEV_ROOT="$1"

echo "Using development folder ${DEV_ROOT}"
[ -d ${DEV_ROOT} ] || (mkdir -p $1 && echo "${DEV_ROOT} created!") || fail 1 "Cannnot create ${DEV_ROOT}"

# Before building, check that environment is clean
! [ -d ${DEV_ROOT} ] && fail 2 "${DEV_ROOT} does not exist!"
cd "${DEV_ROOT}" || fail 2
for f in libexpat S2OPC check-0.15.2; do
    [ -e ${f} ] && fail 3 "${f} already exist in ${DEV_ROOT}/ . Cleanup ${DEV_ROOT} before continuing"
done
! [ -e fledge-north-s2opcua  ] && fail 4 "fledge-north-s2opcua not found in ${DEV_ROOT} "

# Check sudo
[ `whoami` != "root" ] && echo "Elevation will be required for installation" && sudo echo || fail 5 "Failed to get elevation"

# Download all
cd ${DEV_ROOT}
# git clone https://github.com/fledge-power/fledge-north-s2opcua.git || fail 6
git clone https://github.com/libexpat/libexpat.git || fail 6
wget https://github.com/libcheck/check/releases/download/0.15.2/check-0.15.2.tar.gz || fail 6
git clone https://gitlab.com/systerel/S2OPC.git || fail 6


# mbedtls-dev:
if [[  $os_name == *"Red Hat"* || $os_name == *"CentOS"* ]]; then
	echo RHEL/CentOS not currently supported by this plugin
	exit 1
else
	sudo apt-get install -y libmbedtls-dev
fi

# libexpat:
cd ${DEV_ROOT}
cd libexpat/expat || fail 10 "Enter libexpat"
rm -f CMakeCache.txt ; mkdir -p build && cd build && cmake -D CMAKE_INSTALL_PREFIX=/usr/local -D EXPAT_BUILD_PKGCONFIG=ON -D EXPAT_ENABLE_INSTALL=ON -D EXPAT_SHARED_LIBS=ON .. && make -j4 || fail 10 "Build libexpat"
sudo make install || fail 10 "Install libexpat"


# libcheck:
cd ${DEV_ROOT} && tar xf check-0.15.2.tar.gz 
cd check-0.15.2 || fail 11 "Enter check"
patch CMakeLists.txt ${DEV_ROOT}/fledge-north-s2opcua/patches/check-0.15.2.patch || fail 11 "Patch check"
rm -f CMakeCache.txt ; mkdir -p build && cd build&& cmake .. && make -j4  || fail 11 "Build check"
sudo make install  || fail 11 "Install check"



# S2OPC
(
    cd ${DEV_ROOT}/S2OPC || fail 20 "Enter S2OPC folder"
    git apply ${DEV_ROOT}/fledge-north-s2opcua/patches/S2OPC.patch || fail 20 "Apply patch for S2OPC"

    WITH_USER_ASSERT=ON USE_STATIC_EXT_LIBS=ON BUILD_SHARED_LIBS=OFF CMAKE_INSTALL_PREFIX=/usr/local ./build.sh  || fail 20 "Build S2OPC"
    echo; echo "BUILD done, INSTALLING..."; echo
    sudo make install -C build || fail 20 "Install S2OPC"
) || exit

echo "All requirement installed properly"

