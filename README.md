# OPC UA S2OPC North plugin 

A simple OPC UA plugin that provides an OPC UA server based on S2OPC stack.
This plugin supports several OPC UA Security Policies and Message Security Modes.
It supports both anonymous access and authentication using username and password.


## Configuration

See an example in `include/default_config.json`

## Building

Building this plugin requires that dependencies are available in a specified relative location in the file system. The `DEV_ROOT` variable may be set to any local folder. For example:

```sh
export DEV_ROOT=~/dev
mkdir -p ${DEV_ROOT}
```

### Automated dependencies build

All commands shown below are automated in the script `requirements.sh`.

```sh
cd ${DEV_ROOT}
./requirements.sh
```

### Manual dependencies build
As there are some hard dependencies between `fledge-north-s2opc` and other components (patch, inclusion...), it is mandatory to retrieve `fledge-north-s2opc` in this specific folder :

- Download dependencies

```sh
cd ${DEV_ROOT}
git clone https://github.com/fledge-power/fledge-north-s2opcua.git
wget https://github.com/libcheck/check/releases/download/0.15.2/check-0.15.2.tar.gz
git clone --branch master --single-branch https://gitlab.com/systerel/S2OPC.git
```

- libmbedtls

```sh
cd ${DEV_ROOT}
wget https://github.com/ARMmbed/mbedtls/archive/refs/tags/v2.28.1.tar.gz
tar xf v2.28.1.tar.gz
cd mbedtls-2.28.1
mkdir build
cd build
cmake -DCMAKE_POSITION_INDEPENDENT_CODE=ON -DBUILD_TESTS=NO -DBUILD_EXAMPLES=NO -DCMAKE_BUILD_TYPE=Release ..
make -j4
sudo make install -j4
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
git checkout 073040628
git apply ${DEV_ROOT}/fledge-north-s2opcua/patches/S2OPC.patch

WITH_USER_ASSERT=1 S2OPC_CLIENTSERVER_ONLY=1 WITH_NANO_EXTENDED=1 USE_STATIC_EXT_LIBS=1 BUILD_SHARED_LIBS=0 CMAKE_INSTALL_PREFIX=/usr/local ./build.sh; echo; echo "BUILD done, INSTALLING..."; echo; sudo make install -C build
```

- cpplint

```sh
pip install -I cpplint==1.6.1
```


### Build plugin
Now all dependencies are installed, the plugin itself can be built.

To build the OPC UA S2OPC South plugin run the commands:

```
cd ${DEV_ROOT}/fledge-north-s2opcua
make
```

### Test plugin

Plugin can be tested locally using the command line. A `Makefile` is provided in the root project to execute basic commands:

- `make build` : compile (Debug)
- `make unit_tests` : Execute unit tests
- `make clean` : Clean the project
- `make log` : Show logs from FLEDGE for the plugin
- `make check` : Check the plugin interface using FLEDGE `get_plugin_info` tool
- `make install_plugin` : Install the North plugin into FLEDGE (requires `FLEDGE_INSTALL` to be set)
- `make insert_task` : Start the plugin as a FLEDGE task
- `make insert_service` : Start the plugin as a FLEDGE service
- `make del_plugin` : Stop the plugin (Either service or task)
- `make cpplint` : Launch coding rules checker

Once the service is started (with default configuration), a simple OPCUA read can be performed for example with the command:

``` bash
(cd ${DEV_ROOT}/fledge-north-s2opcua/samples/cert/ && ../bin/s2opc_read --none -e "opc.tcp://localhost:4841" -n "i=84" -a 3)
```

Which should return something like 

```
S2OPC read demo.
# Info: Session activated.
# Info: Sending ReadRequest.
# Info: Response received.
Read node "i=84", attribute 3:
StatusCode: 0x00000000
Variant @0x7f3988001bc0:
  TypeId 20 [dim=0]: QualifiedName = 0:Root
```

