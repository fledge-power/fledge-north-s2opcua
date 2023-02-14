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

export S2OPC_COMMIT=S2OPC_Toolkit_1.3.0
export MBEDTLS_VERSION=2.28.1

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
for f in S2OPC check-0.15.2 ; do
    [ -e "${DEV_ROOT}/${f}" ] && fail 3 "${f} already exist in ${DEV_ROOT}/ . Cleanup ${DEV_ROOT} before continuing"
done
! [ -e fledge-north-s2opcua  ] && fail 4 "fledge-north-s2opcua not found in ${DEV_ROOT} "

# Check sudo
[ `whoami` != "root" ] && echo "Elevation will be required for installation" && sudo echo || fail 5 "Failed to get elevation"

# Download all
cd ${DEV_ROOT}
# git clone https://github.com/fledge-power/fledge-north-s2opcua.git || fail 6
wget https://github.com/libcheck/check/releases/download/0.15.2/check-0.15.2.tar.gz || fail 6
git clone --branch $S2OPC_COMMIT --single-branch https://gitlab.com/systerel/S2OPC.git || fail 6


if [[  $os_name == *"Red Hat"* || $os_name == *"CentOS"* ]]; then
	echo RHEL/CentOS not currently supported by this plugin
	exit 1
fi

# mbedtls-dev:
wget https://github.com/ARMmbed/mbedtls/archive/refs/tags/v${MBEDTLS_VERSION}.tar.gz
tar xf v${MBEDTLS_VERSION}.tar.gz
cd mbedtls-${MBEDTLS_VERSION}
mkdir build
cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_TESTS=NO -DBUILD_EXAMPLES=NO -DCMAKE_BUILD_TYPE=Release ..
make -j4
sudo make install -j4

# libcheck:
cd ${DEV_ROOT} && tar xf check-0.15.2.tar.gz 
cd check-0.15.2 || fail 11 "Enter check"
patch CMakeLists.txt ${DEV_ROOT}/fledge-north-s2opcua/patches/check-0.15.2.patch || fail 11 "Patch check"
rm -f CMakeCache.txt ; mkdir -p build && cd build&& cmake .. && make -j4  || fail 11 "Build check"
sudo make install  || fail 11 "Install check"



# S2OPC
(
    cd ${DEV_ROOT}/S2OPC || fail 20 "Enter S2OPC folder"
    git checkout "$S2OPC_COMMIT" || fail 20 "Could not find S2OPC commit $S2OPC_COMMIT"
    git apply ${DEV_ROOT}/fledge-north-s2opcua/patches/S2OPC.patch || fail 20 "Apply patch for S2OPC"

    WITH_USER_ASSERT=1 S2OPC_CLIENTSERVER_ONLY=1 WITH_NANO_EXTENDED=1 USE_STATIC_EXT_LIBS=1 BUILD_SHARED_LIBS=0 CMAKE_INSTALL_PREFIX=/usr/local ./build.sh  || fail 20 "Build S2OPC"
    echo; echo "BUILD done, INSTALLING..."; echo
    sudo make install -C build || fail 20 "Install S2OPC"
) || exit

# cpplint
pip install -I cpplint==1.6.1

echo "All requirement installed properly"

