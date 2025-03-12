
set(CMAKE_CXX_STANDARD 23)
set(CMAKE_CXX_STANDARD_REQUIRED ON)
set(CMAKE_CXX_EXTENSIONS OFF) # Optional, but recommended for standard compliance

add_library(
  kmipclient
  STATIC
        include/KmipClient.hpp
        src/KmipClient.cpp
        include/NetClient.hpp
        src/NetClientOpenSSL.cpp
        include/NetClientOpenSSL.hpp
        include/v_expected.hpp
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
        src/kmip_exceptions.hpp
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

target_link_libraries(kmipclient kmip)
set_property(TARGET kmipclient PROPERTY POSITION_INDEPENDENT_CODE ON)

target_include_directories(
  kmipclient PUBLIC
  $<BUILD_INTERFACE:${KMIP_SOURCE_DIR}/kmipclient/>
  $<INSTALL_INTERFACE:include>
  )

set_target_properties(
  kmipclient PROPERTIES PUBLIC_HEADER "Kmip.hpp"
)

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
  target_link_libraries(example_${name} kmipclient)
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
