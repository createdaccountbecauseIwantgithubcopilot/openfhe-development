find_package(GLScheme CONFIG REQUIRED)

add_library(GLRProductionAdapter STATIC
    src/glr-production-adapter.cpp
)
add_library(OpenFHE::GLRProductionAdapter ALIAS GLRProductionAdapter)

target_compile_features(GLRProductionAdapter PUBLIC cxx_std_20)
target_include_directories(GLRProductionAdapter
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(GLRProductionAdapter PUBLIC GLScheme::glscheme)
set_target_properties(GLRProductionAdapter PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    PUBLIC_HEADER
        "${CMAKE_CURRENT_SOURCE_DIR}/include/openfhe/pke/glr-production-adapter.h"
)

install(TARGETS GLRProductionAdapter
    EXPORT OpenFHETargets
    ARCHIVE DESTINATION lib
    LIBRARY DESTINATION lib
    RUNTIME DESTINATION bin
    PUBLIC_HEADER DESTINATION include/openfhe/pke
)

# Kept independent of the monolithic pke_tests binary: this provider smoke
# test stays fast and can be built/run without compiling OpenFHE itself.
add_executable(glr_production_adapter_metadata_test
    tests/glr-production-adapter-metadata-test.cpp
)
target_compile_features(glr_production_adapter_metadata_test PRIVATE cxx_std_20)
target_link_libraries(glr_production_adapter_metadata_test
    PRIVATE GLRProductionAdapter
)

if(BUILD_UNITTESTS)
    add_test(
        NAME glr_production_adapter_metadata
        COMMAND glr_production_adapter_metadata_test
    )
    set_tests_properties(glr_production_adapter_metadata PROPERTIES
        LABELS "pke;glr;production-adapter"
    )
endif()

add_custom_target(testglrproductionadapter
    COMMAND $<TARGET_FILE:glr_production_adapter_metadata_test>
    DEPENDS glr_production_adapter_metadata_test
    COMMENT "Running native GLR production-adapter metadata smoke test"
)
