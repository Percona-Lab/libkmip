
add_library(
  kmippp
  STATIC
  kmippp.cpp
  )

target_link_libraries(kmippp kmip)

target_include_directories(
  kmip PUBLIC
  $<BUILD_INTERFACE:${KMIP_SOURCE_DIR}/kmippp//>
  $<INSTALL_INTERFACE:include>
  )
set_target_properties(
  kmip PROPERTIES PUBLIC_HEADER
  "kmippp.h"
  )


export(TARGETS kmippp FILE "kmippp.cmake")
install(
  TARGETS kmippp
  EXPORT kmippp
  ARCHIVE DESTINATION lib
  PUBLIC_HEADER DESTINATION include/
  LIBRARY DESTINATION lib)
install(EXPORT kmippp DESTINATION cmake)

macro(add_demo name)
  add_executable(demo_pp_${name} demo_${name}.cpp)
  target_link_libraries(demo_pp_${name} kmippp)
endmacro()

add_demo(create)
add_demo(get)
add_demo(get_name)
add_demo(register)
add_demo(locate)
add_demo(all)

