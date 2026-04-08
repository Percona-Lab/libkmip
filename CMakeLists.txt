cmake_minimum_required(VERSION  3.10.0)

if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif(POLICY CMP0048)

project(kmip C CXX)

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

# Keep Clang-20+ builds quiet even when user environments inject strict warning flags.
if(CMAKE_C_COMPILER_ID MATCHES "Clang" AND CMAKE_C_COMPILER_VERSION VERSION_GREATER_EQUAL 20)
  add_compile_options(
    $<$<COMPILE_LANGUAGE:C>:-Wno-c23-extensions>
    $<$<COMPILE_LANGUAGE:C>:-Wno-invalid-utf8>
    $<$<COMPILE_LANGUAGE:C>:-Wno-newline-eof>
    $<$<COMPILE_LANGUAGE:C>:-Wno-sign-compare>
    $<$<COMPILE_LANGUAGE:C>:-Wno-unused-parameter>
    $<$<COMPILE_LANGUAGE:C>:-Wno-unused-variable>
  )
endif()

if(CMAKE_CXX_COMPILER_ID MATCHES "Clang" AND CMAKE_CXX_COMPILER_VERSION VERSION_GREATER_EQUAL 20)
  add_compile_options(
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-invalid-utf8>
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-missing-field-initializers>
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-sign-compare>
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-unused-parameter>
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-unused-private-field>
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-unused-variable>
    $<$<COMPILE_LANGUAGE:CXX>:-Wno-vla-cxx-extension>
  )
endif()

add_subdirectory(libkmip/src)
add_subdirectory(kmippp)

