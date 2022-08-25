# OPC UA S2OPC North plugin 

A simple OPC UA plugin that provides an OPC UA server based on S2OPC stack.
This plugin supports several OPC UA Security Policies and Message Security Modes.
It supports both anonymous access and authentication using username and password.


## Configuration

This configuration of this plugin requires following parameters to be set:

TODO

## Building

Building this plugin requires that dependancies are available in a specified relative location in the file system. The `DEV_ROOT` variable may be set to any local folder. For example:

```sh
export DEV_ROOT=~/dev
mkdir -p ${DEV_ROOT}
```

### Automated dependancies build

All commands shown below are automated in the script `requirements.sh`.

```sh
cd ${DEV_ROOT}
./requirements.sh
```

### Manual dependancies build
As there are some hard dependancies between `fledge-north-s2opc` and other components (patch, inclusion...), it is mandatory to retreive `fledge-north-s2opc` in this specific folder :

- Download dependancies

```sh
cd ${DEV_ROOT}
git clone https://github.com/fledge-power/fledge-north-s2opcua.git
git clone https://github.com/libexpat/libexpat.git
wget https://github.com/libcheck/check/releases/download/0.15.2/check-0.15.2.tar.gz
git clone https://gitlab.com/systerel/S2OPC.git
```

- libmbedtls

```sh
sudo apt-get install -y libmbedtls-dev
```

- libexpat

```sh
cd ${DEV_ROOT}
cd libexpat/expat
rm -f CMakeCache.txt ; mkdir -p build ; cd build; cmake -D CMAKE_INSTALL_PREFIX=/usr/local -D EXPAT_BUILD_PKGCONFIG=ON -D EXPAT_ENABLE_INSTALL=ON -D EXPAT_SHARED_LIBS=ON .. && make -j4 && sudo make install; cd -
```

- libcheck

```sh
cd ${DEV_ROOT}
tar xf check-0.15.2.tar.gz
cd check-0.15.2
patch CMakeLists.txt ${DEV_ROOT}/fledge-north-s2opcua/patches/check-0.15.2.patch
rm -f CMakeCache.txt ; mkdir -p build ; cd build; cmake .. && make -j4 && sudo make install; cd -
```
  
- S2OPC

```sh
cd ${DEV_ROOT}/S2OPC
git apply ${DEV_ROOT}/fledge-north-s2opcua/patches/S2OPC.patch

USE_STATIC_EXT_LIBS=OFF BUILD_SHARED_LIBS=OFF CMAKE_INSTALL_PREFIX=/usr/local ./build.sh; echo; echo "BUILD done, INSTALLING..."; echo; cd build; sudo make install; cd -
```

### Build plugin
Now all dependancies are installed, the plugin itself an be built.

To build the OPC UA S2OPC South plugin run the commands:

```
cd ${DEV_ROOT}/fledge-north-s2opcua
make
```
