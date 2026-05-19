cmake_minimum_required(VERSION 3.10.0)

project(kmipcore LANGUAGES CXX)

set(CMAKE_CXX_STANDARD 20)
set(CMAKE_CXX_STANDARD_REQUIRED ON)

option(KMIP_MAINTAINER_MODE "Enable strict compiler warnings for kmipcore targets" OFF)
option(WARNINGS_AS_ERRORS "Treat compiler warnings as errors" OFF)

function(kmip_enable_maintainer_warnings target_name)
  if(NOT KMIP_MAINTAINER_MODE)
    return()
  endif()

  if(MSVC)
    target_compile_options(${target_name} PRIVATE /W4)
    if(WARNINGS_AS_ERRORS)
      target_compile_options(${target_name} PRIVATE /WX)
    endif()
    return()
  endif()

  if(CMAKE_CXX_COMPILER_ID STREQUAL "Clang")
    target_compile_options(
      ${target_name}
      PRIVATE
      -Weverything
      -Wno-c++98-compat
      -Wno-c++98-compat-pedantic
      -Wno-pre-c++20-compat
      -Wno-c++20-compat
      -Wno-padded
      -Wno-switch-enum
      -Wno-unsafe-buffer-usage
      -Wno-covered-switch-default
      -Wno-documentation
      -Wno-exit-time-destructors
      -Wno-global-constructors
      -Wno-missing-prototypes
      -Wno-newline-eof
      -Wno-nrvo
      -Wno-weak-vtables
    )
  elseif(CMAKE_CXX_COMPILER_ID STREQUAL "GNU")
    target_compile_options(
      ${target_name}
      PRIVATE
      -Wall
      -Wextra
      -Wpedantic
      -Wcast-qual
      -Wconversion
      -Wdouble-promotion
      -Wformat=2
      -Wnull-dereference
      -Woverloaded-virtual
      -Wshadow
      -Wsign-conversion
      -Wundef
      -Wuseless-cast
    )
  endif()

  if(WARNINGS_AS_ERRORS)
    target_compile_options(${target_name} PRIVATE -Werror)
  endif()
endfunction()


file(GLOB_RECURSE SOURCES CONFIGURE_DEPENDS "src/*.cpp")
file(GLOB_RECURSE HEADERS CONFIGURE_DEPENDS "include/kmipcore/*.hpp")

add_library(kmipcore STATIC ${SOURCES} ${HEADERS})
kmip_enable_maintainer_warnings(kmipcore)

target_include_directories(kmipcore PUBLIC
    $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
    $<INSTALL_INTERFACE:include>
)

set_property(TARGET kmipcore PROPERTY POSITION_INDEPENDENT_CODE ON)

install(
  TARGETS kmipcore
  EXPORT kmipclient
  DESTINATION cmake
  ARCHIVE DESTINATION lib
  LIBRARY DESTINATION lib)

add_executable(kmip_core_test tests/test_core.cpp)
target_link_libraries(kmip_core_test PRIVATE kmipcore)
kmip_enable_maintainer_warnings(kmip_core_test)
add_test(NAME kmip_core_test COMMAND kmip_core_test)

add_executable(kmip_parser_test tests/test_parsers.cpp)
target_link_libraries(kmip_parser_test PRIVATE kmipcore)
kmip_enable_maintainer_warnings(kmip_parser_test)
add_test(NAME kmip_parser_test COMMAND kmip_parser_test)

add_executable(kmip_serialization_buffer_test tests/test_serialization_buffer.cpp)
target_link_libraries(kmip_serialization_buffer_test PRIVATE kmipcore)
kmip_enable_maintainer_warnings(kmip_serialization_buffer_test)
add_test(NAME kmip_serialization_buffer_test COMMAND kmip_serialization_buffer_test)
