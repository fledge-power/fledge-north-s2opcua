cmake_minimum_required(VERSION 2.8)

project(RunTests)

# Supported options:
# -DFLEDGE_INCLUDE
# -DFLEDGE_LIB
# -DFLEDGE_SRC
# -DFLEDGE_INSTALL
#
# If no -D options are given and FLEDGE_ROOT environment variable is set
# then Fledge libraries and header files are pulled from FLEDGE_ROOT path.

  message("Coverage is going to be generated")
  enable_testing()
  include(CodeCoverage)
  append_coverage_compiler_flags()

  set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} --coverage")
  set(CMAKE_C_FLAGS "${CMAKE_C_FLAGS} --coverage")
  set(GCOVR_ADDITIONAL_ARGS "--exclude-unreachable-branches" "--exclude-throw-branches" )
  
  setup_target_for_coverage_gcovr_sonar(NAME "${PROJECT_NAME}_coverage_sonar"
                                      EXECUTABLE RunTests
                                      DEPENDENCIES RunTests
                                      BASE_DIRECTORY "${PROJECT_SOURCE_DIR}/.."
                                      EXCLUDE "tests/*" "build/*"
  )    

  setup_target_for_coverage_gcovr_html(NAME "${PROJECT_NAME}_coverage_html"
                                       EXECUTABLE RunTests
                                       DEPENDENCIES RunTests
                                       BASE_DIRECTORY "${PROJECT_SOURCE_DIR}/../src"
                                       EXCLUDE "tests/*"
  )

# Generation version header file

if (${CMAKE_BUILD_TYPE} STREQUAL Coverage OR ${CMAKE_BUILD_TYPE} STREQUAL Debug)
  set(GEN_SRC_DIR "${CMAKE_SOURCE_DIR}")
else()
  set(GEN_SRC_DIR "${CMAKE_SOURCE_DIR}/..")
endif()

# Patch the ASSERT and logging features to avoid branch false detection.
if (${CMAKE_BUILD_TYPE} STREQUAL Coverage)
  set(CMAKE_CXX_FLAGS  "${CMAKE_CXX_FLAGS} -DUNIT_TESTING")
endif()

set_source_files_properties(version.h PROPERTIES GENERATED TRUE)
add_custom_command(
  OUTPUT version.h
  DEPENDS ${GEN_SRC_DIR}/VERSION
  COMMAND ${GEN_SRC_DIR}/mkversion ${GEN_SRC_DIR}
  COMMENT "Generating tests version header"
  VERBATIM
)
	
# Generation of JSON default file
set_source_files_properties(default_config.inc PROPERTIES GENERATED TRUE)
add_custom_command(
  OUTPUT default_config.inc
  DEPENDS ${GEN_SRC_DIR}/include/default_config.json ${GEN_SRC_DIR}/mkjson
  COMMAND ${GEN_SRC_DIR}/mkjson plugin_default_config ${GEN_SRC_DIR}/include/default_config.json default_config.inc 
  COMMENT "Generating JSON default configuration file"
  VERBATIM
)
	
# Generation of AddressSpace NS0 file
set_source_files_properties(base_addrspace.c PROPERTIES GENERATED TRUE)
add_custom_command(
  OUTPUT base_addrspace.c
  DEPENDS ${GEN_SRC_DIR}/include/s2opc_base_nodeset_origin.xml ${GEN_SRC_DIR}/mkaddrspace
  COMMAND ${GEN_SRC_DIR}/mkaddrspace ${GEN_SRC_DIR}/include/s2opc_base_nodeset_origin.xml base_addrspace.c 
  COMMENT "Generating tests NS0 AddressSpace initialization file"
  VERBATIM
)
	
file(COPY ${CMAKE_SOURCE_DIR}/samples/bin/s2opc_write
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_SOURCE_DIR}/samples/bin/s2opc_read
     DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
file(COPY ${CMAKE_SOURCE_DIR}/samples/cert DESTINATION ${CMAKE_CURRENT_BINARY_DIR})
     
include_directories(${CMAKE_BINARY_DIR} "${CMAKE_CURRENT_BINARY_DIR}")

# Set plugin type (south, north, filter)
set(PLUGIN_TYPE "north")

# Add here all needed Fledge libraries as list
set(NEEDED_FLEDGE_LIBS common-lib services-common-lib)

# Find source files
#file(GLOB SOURCES ../src/*.cpp)
file(GLOB unittests "*.cpp")

# Find Fledge includes and libs, by including FindFledge.cmak file
set(CMAKE_MODULE_PATH ${CMAKE_MODULE_PATH} ${CMAKE_CURRENT_SOURCE_DIR}/..)
find_package(Fledge)
# If errors: make clean and remove Makefile
if (NOT FLEDGE_FOUND)
	if (EXISTS "${CMAKE_BINARY_DIR}/Makefile")
		execute_process(COMMAND make clean WORKING_DIRECTORY ${CMAKE_BINARY_DIR})
		file(REMOVE "${CMAKE_BINARY_DIR}/Makefile")
	endif()
	message(FATAL_ERROR "Fledge plugin '${PROJECT_NAME}' build error.")
endif()
# On success, FLEDGE_INCLUDE_DIRS and FLEDGE_LIB_DIRS variables are set 

# Locate GTest
find_package(GTest REQUIRED)
include_directories(${GTEST_INCLUDE_DIRS})

# Add ../include
include_directories(../include)
include_directories(${GEN_SRC_DIR})

# Add Fledge include dir(s)
include_directories(${FLEDGE_INCLUDE_DIRS})

# Add Fledge lib path
link_directories(${FLEDGE_LIB_DIRS})

# Link runTests with what we want to test and the GTest and pthread library
add_executable(RunTests ${unittests} ${SOURCES} version.h base_addrspace.c default_config.inc)

set(FLEDGE_INSTALL "" CACHE INTERNAL "")
# Install library
if (FLEDGE_INSTALL)
	message(STATUS "Installing ${PROJECT_NAME} in ${FLEDGE_INSTALL}/plugins/${PLUGIN_TYPE}/${PROJECT_NAME}")
	install(TARGETS ${PROJECT_NAME} DESTINATION ${FLEDGE_INSTALL}/plugins/${PLUGIN_TYPE}/${PROJECT_NAME})
endif()

target_link_libraries(${PROJECT_NAME} ${GTEST_LIBRARIES})
target_link_libraries(${PROJECT_NAME} ${NEEDED_FLEDGE_LIBS})
#target_link_libraries(${PROJECT_NAME}  ${Boost_LIBRARIES})
target_link_libraries(${PROJECT_NAME} -ldl)
add_definitions( -DWITH_USER_ASSERT=1)
target_link_libraries(${PROJECT_NAME} s2opc_serverwrapper s2opc_common)
