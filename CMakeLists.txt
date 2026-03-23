cmake_minimum_required(VERSION  3.10.0)

if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif(POLICY CMP0048)

project(kmip C CXX)

enable_testing()

set(KMIP_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")
option(WITH_ASAN "Enable AddressSanitizer for project build" OFF)
option(BUILD_KMIP_TESTS "Build and register libkmip/src/tests.c with CTest" OFF)

if(BUILD_KMIP_TESTS)
  enable_testing()
endif()

if(WITH_ASAN)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU" AND CMAKE_CXX_COMPILER_ID MATCHES "Clang|GNU")
    set(_asan_compile_flags "-fsanitize=address -fno-omit-frame-pointer")
    set(_asan_link_flags "-fsanitize=address")

    string(APPEND CMAKE_C_FLAGS " ${_asan_compile_flags}")
    string(APPEND CMAKE_CXX_FLAGS " ${_asan_compile_flags}")
    string(APPEND CMAKE_EXE_LINKER_FLAGS " ${_asan_link_flags}")
    string(APPEND CMAKE_SHARED_LINKER_FLAGS " ${_asan_link_flags}")
  else()
    message(FATAL_ERROR "WITH_ASAN=ON is supported only with Clang or GCC compilers")
  endif()
endif()


add_subdirectory(libkmip/src)
add_subdirectory(kmippp)
add_subdirectory(kmipcore)
add_subdirectory(kmipclient)

find_package(Doxygen)

option(BUILD_DOCS "Build API documentation with Doxygen" ${DOXYGEN_FOUND})

if(BUILD_DOCS)
  if(NOT DOXYGEN_FOUND)
    message(FATAL_ERROR "BUILD_DOCS is ON but Doxygen was not found.")
  endif()

  configure_file(Doxyfile ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile COPYONLY)

  add_custom_target(doc
    COMMAND ${DOXYGEN_EXECUTABLE} ${CMAKE_CURRENT_BINARY_DIR}/Doxyfile
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    COMMENT "Generating API documentation with Doxygen"
    VERBATIM
  )

  # Make the 'doc' target depend on your build targets if necessary
  # add_dependencies(doc your_library your_executable)
else()
  message(STATUS "Doxygen not found or BUILD_DOCS=OFF, skipping documentation generation.")
endif()
