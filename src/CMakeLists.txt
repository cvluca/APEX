file(GLOB_RECURSE SOURCE_FILES *.cpp)

add_library(apex STATIC ${SOURCE_FILES})

target_include_directories(apex PUBLIC
    ${CMAKE_CURRENT_SOURCE_DIR}/../third-party/openfhe-development/src/core/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../third-party/openfhe-development/src/binfhe/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../third-party/openfhe-development/src/pke/include
    ${CMAKE_BINARY_DIR}/third-party/openfhe-development/src/core
    ${CMAKE_CURRENT_SOURCE_DIR}/../third-party/openfhe-development/third-party/cereal/include
    ${CMAKE_CURRENT_SOURCE_DIR}/../include
)

target_link_libraries(apex OPENFHEcore_static OPENFHEpke_static OPENFHEbinfhe_static)
