cmake_minimum_required(VERSION 3.31)

find_package(cmake-bare REQUIRED PATHS node_modules/cmake-bare)
find_package(cmake-fetch REQUIRED PATHS node_modules/cmake-fetch)

project(bare_hc C CXX)

fetch_package("github:holepunchto/libhc")

add_bare_module(bare_hc)

target_sources(
  ${bare_hc}
  PRIVATE
    binding.c
)

target_link_libraries(
  ${bare_hc}
  PUBLIC
    hc_static
)
