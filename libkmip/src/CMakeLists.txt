
find_package(OpenSSL REQUIRED)

# Keep legacy libkmip C sources quiet on Clang-20+ even when user environments
# inject strict warning flags.
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

add_library(
  kmip
  STATIC
  kmip_bio.c
  kmip.c
  kmip_locate.c
  kmip_memset.c
  )

target_link_libraries(kmip OpenSSL::SSL OpenSSL::Crypto)
set_property(TARGET kmip PROPERTY POSITION_INDEPENDENT_CODE ON)


target_include_directories(
  kmip PUBLIC
  $<BUILD_INTERFACE:${KMIP_SOURCE_DIR}/libkmip/include/>
  $<INSTALL_INTERFACE:include>
  )
set_target_properties(
  kmip PROPERTIES PUBLIC_HEADER
  "../include/kmip.h"
  )


export(TARGETS kmip FILE "kmip.cmake")
install(
  TARGETS kmip
  EXPORT kmip
  DESTINATION cmake
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include/
  LIBRARY DESTINATION lib)

macro(add_demo name)
  add_executable(demo_${name} demo_${name}.c)
  target_link_libraries(demo_${name} kmip)
endmacro()

add_demo(create)
add_demo(destroy)
add_demo(get)
add_demo(locate)
add_demo(register)
add_demo(query)

if(BUILD_KMIP_TESTS)
  add_executable(kmip_tests tests.c)
  target_link_libraries(kmip_tests kmip)
  if(CMAKE_C_COMPILER_ID MATCHES "Clang|GNU")
    # tests.c includes kmip.h before stdio.h; inject stdio for this target only.
    target_compile_options(kmip_tests PRIVATE -include stdio.h)
  endif()
  add_test(NAME kmip_tests COMMAND kmip_tests)
endif()

