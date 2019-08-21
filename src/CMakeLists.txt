project(keyprotector)

set(EOSIO_WASM_OLD_BEHAVIOR "Off")
find_package(eosio.cdt)

add_contract( keyprotector keyprotector keyprotector.cpp )
target_include_directories( keyprotector PUBLIC ${CMAKE_SOURCE_DIR}/../include )
target_ricardian_directory( keyprotector ${CMAKE_SOURCE_DIR}/../ricardian )