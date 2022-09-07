cmake_minimum_required(VERSION 2.6.0)

# Set the plugin name to build
project(s2opcua)

# Supported options:
# -DFLEDGE_INCLUDE
# -DFLEDGE_LIB
# -DFLEDGE_SRC
# -DFLEDGE_INSTALL
#
# If no -D options are given and FLEDGE_ROOT environment variable is set
# then Fledge libraries and header files are pulled from FLEDGE_ROOT path.

set(CMAKE_CXX_FLAGS "-std=c++11 -O3")

# Generation of JSON default file
set_source_files_properties(default_config.inc PROPERTIES GENERATED TRUE)
add_custom_command(
  OUTPUT default_config.inc
  DEPENDS ${CMAKE_SOURCE_DIR}/include/default_config.json ${CMAKE_SOURCE_DIR}/mkjson
  COMMAND ${CMAKE_SOURCE_DIR}/mkjson plugin_default_config ${CMAKE_SOURCE_DIR}/include/default_config.json default_config.inc 
  COMMENT "Generating JSON default configuration file"
  VERBATIM
)

# Generation version header file
set_source_files_properties(version.h PROPERTIES GENERATED TRUE)
add_custom_command(
  OUTPUT version.h
  DEPENDS ${CMAKE_SOURCE_DIR}/VERSION
  COMMAND ${CMAKE_SOURCE_DIR}/mkversion ${CMAKE_SOURCE_DIR}
  COMMENT "Generating version header"
  VERBATIM
)
include_directories(${CMAKE_BINARY_DIR})

# Set plugin type (south, north, filter)
set(PLUGIN_TYPE "north")

# Add here all needed Fledge libraries as list
set(NEEDED_FLEDGE_LIBS common-lib)

# Find source files
file(GLOB SOURCES src/*.cpp src/*.c)

# Find Fledge includes and libs, by including FindFledge.cmake file
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR})
find_package(Fledge)
# If errors: make clean and remove Makefile
if (NOT FLEDGE_FOUND)
	if (EXISTS "${CMAKE_BINARY_DIR}/Makefile")
		execute_process(COMMAND make clean WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
		file(REMOVE "${CMAKE_BINARY_DIR}/Makefile")
	endif()
	# Stop the build process
	message(FATAL_ERROR "Fledge plugin '${PROJECT_NAME}' build error.")
endif()
# On success, FLEDGE_INCLUDE_DIRS and FLEDGE_LIB_DIRS variables are set 

# if(NOT S2OPC_COMMON_DEFS_SET)
#   include(../../CommonDefs.cmake)
# endif()

# Find the S2OPC library source tree
if (NOT "$ENV{S2OPC}" STREQUAL "")
	set(OPCUADIR $ENV{S2OPC})
else()
	set(OPCUADIR "../S2OPC")
endif()
message("OPCUADIR: ${OPCUADIR}")

# Add ./include
include_directories(include)
# Add Fledge include dir(s)
include_directories(${FLEDGE_INCLUDE_DIRS})

include_directories(/usr/local/include/s2opc/common)
include_directories(/usr/local/include/s2opc/clientserver) # TODO
include_directories(/usr/local/include/s2opc/clientserver/frontend) # TODO

# Add Fledge lib path
link_directories(${FLEDGE_LIB_DIRS})

# Add additional link directories
# We assume the 'S2OPC' libraries are available here: 
link_directories(/usr/local/lib)

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} -Wl,--no-as-needed")

# Create shared library
add_library(${PROJECT_NAME} SHARED ${SOURCES} version.h default_config.inc)

# Add Fledge library names
target_link_libraries(${PROJECT_NAME} ${NEEDED_FLEDGE_LIBS})

# Add additional libraries
target_link_libraries(${PROJECT_NAME} -lpthread -ldl)

# Add S2OPC libraries
find_library(S2OPC_COMMON s2opc_common ${OPCUADIR}/build/lib)
if (NOT S2OPC_COMMON)
        message(FATAL_ERROR "S2OPC library s2opc_common not found.\n"
                        "Please build S2OPC library and set the environment variable S2OPC to library source tree root")
        return()
endif()

find_library(S2OPC_CLIENTSERVER s2opc_clientserver ${OPCUADIR}/build/lib)
if (NOT S2OPC_CLIENTSERVER)
        message(FATAL_ERROR "S2OPC library s2opc_clientserver not found.\n"
                        "Please build S2OPC library and set the environment variable S2OPC to library source tree root")
        return()
endif()

find_library(S2OPC_SERVERWRAPPER s2opc_serverwrapper ${OPCUADIR}/build/lib)
if (NOT S2OPC_SERVERWRAPPER)
        message(FATAL_ERROR "S2OPC library s2opc_serverwrapper not found.\n"
                        "Please build S2OPC library and set the environment variable S2OPC to library source tree root")
        return()
endif()

find_library(S2OPC_COMMONWRAPPER s2opc_commonwrapper ${OPCUADIR}/build/lib)
if (NOT S2OPC_COMMONWRAPPER)
        message(FATAL_ERROR "S2OPC library s2opc_commonwrapper not found.\n"
                        "Please build S2OPC library and set the environment variable S2OPC to library source tree root")
        return()
endif()

# Report S2OPC build options
add_definitions( -DWITH_USER_ASSERT=1)

# Manage libraries
message("S2OPC_COMMON: ${S2OPC_COMMON}")
message("S2OPC_CLIENTSERVER: ${S2OPC_CLIENTSERVER}")
message("S2OPC_SERVERWRAPPER: ${S2OPC_SERVERWRAPPER}")
message("S2OPC_COMMONWRAPPER: ${S2OPC_COMMONWRAPPER}")
target_link_libraries(${PROJECT_NAME} ${S2OPC_COMMON} ${S2OPC_CLIENTSERVER} ${S2OPC_SERVERWRAPPER} ${S2OPC_COMMONWRAPPER} -lmbedtls -lmbedcrypto)

target_compile_options(${PROJECT_NAME} PRIVATE ${S2OPC_COMPILER_FLAGS})
target_compile_definitions(${PROJECT_NAME} PRIVATE ${S2OPC_DEFINITIONS})


# Set the build version 
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION 1)

set(FLEDGE_INSTALL "" CACHE INTERNAL "")
# Install library
if (FLEDGE_INSTALL)
	message(STATUS "Installing ${PROJECT_NAME} in ${FLEDGE_INSTALL}/plugins/${PLUGIN_TYPE}/${PROJECT_NAME}")
	install(TARGETS ${PROJECT_NAME} DESTINATION ${FLEDGE_INSTALL}/plugins/${PLUGIN_TYPE}/${PROJECT_NAME})
endif()
