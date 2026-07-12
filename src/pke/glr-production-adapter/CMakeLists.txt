find_package(GLScheme CONFIG REQUIRED)

add_library(GLRProductionAdapter STATIC
    src/glr-production-adapter.cpp
    src/gl-int-production-glr-bridge.cpp
)
add_library(OpenFHE::GLRProductionAdapter ALIAS GLRProductionAdapter)

target_compile_features(GLRProductionAdapter PUBLIC cxx_std_20)
target_include_directories(GLRProductionAdapter
    PUBLIC
        $<BUILD_INTERFACE:${CMAKE_CURRENT_SOURCE_DIR}/include>
        $<INSTALL_INTERFACE:include>
)
target_link_libraries(GLRProductionAdapter PUBLIC GLScheme::glscheme)
if(BUILD_SHARED)
    target_link_libraries(GLRProductionAdapter PUBLIC OPENFHEpke)
elseif(BUILD_STATIC)
    target_link_libraries(GLRProductionAdapter PUBLIC OPENFHEpke_static)
endif()
set_target_properties(GLRProductionAdapter PROPERTIES
    POSITION_INDEPENDENT_CODE ON
    PUBLIC_HEADER
        "${CMAKE_CURRENT_SOURCE_DIR}/include/openfhe/pke/glr-production-adapter.h;${CMAKE_CURRENT_SOURCE_DIR}/include/openfhe/pke/gl-int-production-glr-bridge.h"
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

add_executable(glr_production_adapter_resumable_pack_test
    tests/glr-production-adapter-resumable-pack-test.cpp
)

add_executable(glr_production_adapter_h64_all_y_compile_test
    tests/glr-production-adapter-h64-all-y-compile-test.cpp
)
target_compile_features(glr_production_adapter_h64_all_y_compile_test
    PRIVATE cxx_std_20
)
target_link_libraries(glr_production_adapter_h64_all_y_compile_test
    PRIVATE GLRProductionAdapter
)

add_executable(glr_production_adapter_h64_all_y_metadata_test
    tests/glr-production-adapter-h64-all-y-metadata-test.cpp
)
target_compile_features(glr_production_adapter_h64_all_y_metadata_test
    PRIVATE cxx_std_20
)
target_link_libraries(glr_production_adapter_h64_all_y_metadata_test
    PRIVATE GLRProductionAdapter
)

add_executable(gl_int_production_glr_bridge_link_test
    tests/gl-int-production-glr-bridge-link-test.cpp
)
target_compile_features(gl_int_production_glr_bridge_link_test PRIVATE cxx_std_20)
target_link_libraries(gl_int_production_glr_bridge_link_test
    PRIVATE GLRProductionAdapter
)
target_compile_features(glr_production_adapter_resumable_pack_test
    PRIVATE cxx_std_20
)
target_link_libraries(glr_production_adapter_resumable_pack_test
    PRIVATE GLRProductionAdapter
)

if(BUILD_UNITTESTS)
    add_test(
        NAME glr_production_adapter_metadata
        COMMAND glr_production_adapter_metadata_test
    )
    add_test(
        NAME glr_production_adapter_resumable_pack
        COMMAND glr_production_adapter_resumable_pack_test
    )
    add_test(
        NAME glr_production_adapter_h64_all_y_compile
        COMMAND glr_production_adapter_h64_all_y_compile_test
    )
    add_test(
        NAME glr_production_adapter_h64_all_y_metadata
        COMMAND glr_production_adapter_h64_all_y_metadata_test
    )
    set_tests_properties(glr_production_adapter_metadata PROPERTIES
        LABELS "pke;glr;production-adapter"
    )
    set_tests_properties(glr_production_adapter_resumable_pack PROPERTIES
        LABELS "pke;glr;production-adapter;resumable"
    )
    set_tests_properties(
        glr_production_adapter_h64_all_y_compile
        glr_production_adapter_h64_all_y_metadata
        PROPERTIES LABELS "pke;glr;production-adapter;h64;research"
    )
endif()

add_custom_target(testglrproductionadapter
    COMMAND $<TARGET_FILE:glr_production_adapter_metadata_test>
    COMMAND $<TARGET_FILE:glr_production_adapter_resumable_pack_test>
    COMMAND $<TARGET_FILE:glr_production_adapter_h64_all_y_compile_test>
    COMMAND $<TARGET_FILE:glr_production_adapter_h64_all_y_metadata_test>
    DEPENDS glr_production_adapter_metadata_test
            glr_production_adapter_resumable_pack_test
            glr_production_adapter_h64_all_y_compile_test
            glr_production_adapter_h64_all_y_metadata_test
    COMMENT "Running native GLR production-adapter focused tests"
)
