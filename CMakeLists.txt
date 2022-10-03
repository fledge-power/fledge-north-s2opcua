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

list(APPEND CMAKE_MODULE_PATH "${PROJECT_SOURCE_DIR}/cmake")

# Generation of JSON default file
set_source_files_properties(default_config.inc PROPERTIES GENERATED TRUE)
add_custom_command(
  OUTPUT default_config.inc
  DEPENDS ${CMAKE_SOURCE_DIR}/include/default_config.json ${CMAKE_SOURCE_DIR}/mkjson
  COMMAND ${CMAKE_SOURCE_DIR}/mkjson plugin_default_config ${CMAKE_SOURCE_DIR}/include/default_config.json default_config.inc 
  COMMENT "Generating JSON default configuration file"
  VERBATIM
)

# Generation of AddressSpace NS0 file
set_source_files_properties(base_addrspace.c PROPERTIES GENERATED TRUE)
add_custom_command(
  OUTPUT base_addrspace.c
  DEPENDS ${CMAKE_SOURCE_DIR}/include/s2opc_base_nodeset_origin.xml ${CMAKE_SOURCE_DIR}/mkaddrspace
  COMMAND ${CMAKE_SOURCE_DIR}/mkaddrspace ${CMAKE_SOURCE_DIR}/include/s2opc_base_nodeset_origin.xml base_addrspace.c 
  COMMENT "Generating NS0 AddressSpace initialization file"
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

# Add ./include
include_directories(include)
# Add Fledge include dir(s)
include_directories(${FLEDGE_INCLUDE_DIRS})

find_package(S2OPC 1.2.0)

# Add Fledge lib path
link_directories(${FLEDGE_LIB_DIRS})

set(CMAKE_SHARED_LINKER_FLAGS "${CMAKE_STATIC_LINKER_FLAGS} -Wl,--no-as-needed")

# Create shared library
add_library(${PROJECT_NAME} SHARED ${SOURCES} version.h default_config.inc base_addrspace.c)

# Add Fledge library names
target_link_libraries(${PROJECT_NAME} PRIVATE ${NEEDED_FLEDGE_LIBS})

# Add additional libraries
target_link_libraries(${PROJECT_NAME} PRIVATE -ldl)

# Report S2OPC build options
add_definitions( -DWITH_USER_ASSERT=1)
target_link_libraries(${PROJECT_NAME} PRIVATE s2opc_serverwrapper)

# Set the build version 
set_target_properties(${PROJECT_NAME} PROPERTIES SOVERSION 1)

set(FLEDGE_INSTALL "" CACHE INTERNAL "")
# Install library
if (FLEDGE_INSTALL)
	message(STATUS "Installing ${PROJECT_NAME} in ${FLEDGE_INSTALL}/plugins/${PLUGIN_TYPE}/${PROJECT_NAME}")
	install(TARGETS ${PROJECT_NAME} DESTINATION ${FLEDGE_INSTALL}/plugins/${PLUGIN_TYPE}/${PROJECT_NAME})
endif()

if ("${CMAKE_BUILD_TYPE}" STREQUAL "Coverage")
  add_subdirectory(tests)
elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Debug")
  set(CMAKE_CXX_FLAGS "-std=c++11 -O0")
elseif("${CMAKE_BUILD_TYPE}" STREQUAL "Release")
  set(CMAKE_CXX_FLAGS "-std=c++11 -O3")
endif()

