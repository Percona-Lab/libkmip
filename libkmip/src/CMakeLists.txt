
find_package(OpenSSL REQUIRED)

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

# ASAN-enabled test runner for libkmip/src/tests.c.
add_executable(
  kmip_tests_asan
  tests.c
  kmip_bio.c
  kmip.c
  kmip_locate.c
  kmip_memset.c
)

target_include_directories(
  kmip_tests_asan PRIVATE
  ${KMIP_SOURCE_DIR}/libkmip/include/
)

target_link_libraries(kmip_tests_asan OpenSSL::SSL OpenSSL::Crypto)

target_compile_options(
  kmip_tests_asan PRIVATE
  -fsanitize=address
  -fno-omit-frame-pointer
  -include
  stdio.h
)

target_link_options(
  kmip_tests_asan PRIVATE
  -fsanitize=address
)

add_custom_target(
  run_tests_asan
  COMMAND ${CMAKE_COMMAND} -E env ASAN_OPTIONS=detect_leaks=1:abort_on_error=1:halt_on_error=1 $<TARGET_FILE:kmip_tests_asan>
  DEPENDS kmip_tests_asan
  USES_TERMINAL
)

