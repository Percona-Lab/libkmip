cmake_minimum_required(VERSION 3.16)
project(kmipclient)

#Have to put these 2 lines here to compile

set(CMAKE_CXX_STANDARD 20)
include_directories(${CMAKE_CURRENT_SOURCE_DIR}/include)

add_library(
  kmipclient
  STATIC
        include/KmipClient.hpp
        src/KmipClient.cpp
        include/NetClient.hpp
        src/NetClientOpenSSL.cpp
        include/NetClientOpenSSL.hpp
        include/kmip_data_types.hpp
        src/RequestFactory.cpp
        src/RequestFactory.hpp
        src/KmipCtx.hpp
        src/KmipRequest.hpp
        src/IOUtils.cpp
        src/IOUtils.hpp
        include/Kmip.hpp
        src/ResponseResult.cpp
        src/ResponseResult.hpp
        include/kmip_exceptions.hpp
        src/AttributesFactory.cpp
        src/AttributesFactory.hpp
        src/KeyFactory.cpp
        src/KeyFactory.hpp
        src/Key.cpp
        include/Key.hpp
        src/StringUtils.cpp
        src/StringUtils.hpp
        include/Logger.hpp
)

target_include_directories(
        kmipclient PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)

target_link_libraries(kmipclient kmip)

set_property(TARGET kmipclient PROPERTY POSITION_INDEPENDENT_CODE ON)


target_compile_features(kmipclient INTERFACE cxx_std_20)

set_target_properties(kmipclient PROPERTIES
  CXX_STANDARD_REQUIRED YES
  CXX_EXTENSIONS NO
)

option(WITH_ASAN "Enable Address Sanitizer" OFF)
if(WITH_ASAN)
  target_compile_options(kmipclient INTERFACE "-fsanitize=address")
  target_link_options(kmipclient INTERFACE "-fsanitize=address")
endif()

export(TARGETS kmip kmipclient FILE "kmipclient.cmake")

install(
  TARGETS kmipclient
  EXPORT kmipclient
  DESTINATION cmake
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include/
  LIBRARY DESTINATION lib)

macro(add_example name)
  add_executable(example_${name} examples/example_${name}.cpp)
  target_link_libraries(example_${name} PRIVATE kmipclient)
endmacro()

add_example(create_aes)
add_example(register_secret)
add_example(activate)
add_example(get)
add_example(get_name)
add_example(get_secret)
add_example(revoke)
add_example(destroy)
add_example(register_key)
add_example(locate)
add_example(locate_by_group)
add_example(get_all_ids)
add_example(get_attributes)


# Google Test integration
option(BUILD_TESTS "Build the tests" OFF)

if(BUILD_TESTS)
  if (NOT (TARGET gtest OR TARGET gmock))
    include(FetchContent)
    FetchContent_Declare(
            googletest
            GIT_REPOSITORY https://github.com/google/googletest.git
            GIT_TAG v1.14.0
    )

    # For Windows: Prevent overriding the parent project's compiler/linker settings
    set(gtest_force_shared_crt ON CACHE BOOL "" FORCE)
    FetchContent_MakeAvailable(googletest)
  endif ()

  enable_testing()

  add_executable(
          kmipclient_test
          tests/KmipClientIntegrationTest.cpp
  )

  target_link_libraries(
          kmipclient_test
          PRIVATE
          GTest::gtest_main
          kmipclient
  )

  include(GoogleTest)
  gtest_discover_tests(kmipclient_test)
endif()
