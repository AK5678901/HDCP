cmake_minimum_required(VERSION 3.20)
project(hdcp LANGUAGES CXX)

if(MSVC)
  add_compile_options(/utf-8)
endif()

add_library(hdcp_cipher STATIC hdcp_cipher.cpp)
target_compile_features(hdcp_cipher PUBLIC cxx_std_17)
target_include_directories(hdcp_cipher PUBLIC ${CMAKE_CURRENT_SOURCE_DIR})

add_executable(hdcp hdcp.cpp)
target_link_libraries(hdcp PRIVATE hdcp_cipher)

add_executable(bitslice-gen bitslice-gen.cpp)
target_compile_features(bitslice-gen PRIVATE cxx_std_17)

include(CTest)
if(BUILD_TESTING)
  add_test(NAME hdcp_vectors COMMAND hdcp -t)
endif()
