cmake_minimum_required(VERSION  3.5.0)

if (POLICY CMP0048)
  cmake_policy(SET CMP0048 NEW)
endif(POLICY CMP0048)

project(kmip C CXX)

set(KMIP_SOURCE_DIR "${CMAKE_CURRENT_SOURCE_DIR}")

add_subdirectory(libkmip/src)
add_subdirectory(kmippp)
add_subdirectory(kmipclient)

find_package(Doxygen REQUIRED)

if(DOXYGEN_FOUND)
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
  message(STATUS "Doxygen not found, skipping documentation generation.")
endif()
