cmake_minimum_required(VERSION 3.20)
project(sys-cert-store VERSION 0.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CTest)
find_package(SQLite3 3.31 REQUIRED)
find_package(Threads REQUIRED)

option(SYS_CERT_STORE_SANITIZERS "Enable address and undefined behavior sanitizers" OFF)
include(cmake/bundled-crypto.cmake)

find_program(CARGO_EXECUTABLE cargo REQUIRED)
set(CARGO_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/cargo-target")
if(CMAKE_BUILD_TYPE STREQUAL "Debug")
    set(RUST_PROFILE debug)
    set(RUST_PROFILE_FLAG)
else()
    set(RUST_PROFILE release)
    set(RUST_PROFILE_FLAG --release)
endif()

set(SCS_CARGO_ENV
    "MAKEFLAGS="
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}"
    "OPENSSL_DIR=${openssl_install}"
    "OPENSSL_STATIC=1"
    "SCS_BUNDLED_CRYPTO=1"
    "SCS_CRYPTO_ARCHIVE=$<TARGET_FILE:scs-crypto>"
    "SCS_SCOSSL_ARCHIVE=$<TARGET_FILE:scs-scossl>"
    "SCS_SYMCRYPT_RUNTIME_ARCHIVE=$<TARGET_FILE:scs-symcrypt-runtime>"
    "SCS_SYMCRYPT_POSIX_ARCHIVE=$<TARGET_FILE:scs-symcrypt-posixusermode>"
    "SCS_SYMCRYPT_COMMON_ARCHIVE=$<TARGET_FILE:scs-symcrypt-common>"
    "SCS_SYMCRYPT_MLKEM_ARCHIVE=$<TARGET_FILE:scs-symcrypt-mlkem>"
    "SCS_JITTER_ARCHIVE=$<TARGET_FILE:scs-jitter>"
    "SCS_OPENSSL_ARCHIVE=$<TARGET_FILE:scs-openssl>")

add_custom_target(sys-cert-store-rust ALL
    COMMAND ${CMAKE_COMMAND} -E env ${SCS_CARGO_ENV}
        ${CARGO_EXECUTABLE} build ${RUST_PROFILE_FLAG}
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    VERBATIM)
add_dependencies(sys-cert-store-rust scs-crypto)

add_library(sys-cert-store SHARED IMPORTED GLOBAL)
add_dependencies(sys-cert-store sys-cert-store-rust)
set_target_properties(sys-cert-store PROPERTIES
    IMPORTED_LOCATION "${CARGO_TARGET_DIR}/${RUST_PROFILE}/libsys_cert_store.so"
    INTERFACE_INCLUDE_DIRECTORIES "${CMAKE_CURRENT_SOURCE_DIR}/include")
add_library(sys-cert-store::sys-cert-store ALIAS sys-cert-store)

add_executable(list-certificates examples/list-certificates.cpp)
target_link_libraries(list-certificates PRIVATE sys-cert-store)
set_target_properties(list-certificates PROPERTIES BUILD_RPATH "${CARGO_TARGET_DIR}/${RUST_PROFILE}")

add_executable(certutil IMPORTED GLOBAL)
add_dependencies(certutil sys-cert-store-rust)
set_target_properties(certutil PROPERTIES
    IMPORTED_LOCATION "${CARGO_TARGET_DIR}/${RUST_PROFILE}/certutil")

if(BUILD_TESTING)
    add_test(NAME rust-tests COMMAND ${CMAKE_COMMAND} -E env ${SCS_CARGO_ENV}
        ${CARGO_EXECUTABLE} test ${RUST_PROFILE_FLAG})
    set_tests_properties(rust-tests PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

    add_executable(compat-store-tests tests/compat-store-tests.cpp)
    target_compile_features(compat-store-tests PRIVATE cxx_std_20)
    target_include_directories(compat-store-tests PRIVATE "${CMAKE_CURRENT_SOURCE_DIR}/src")
    target_link_libraries(compat-store-tests PRIVATE
        sys-cert-store scs-crypto SQLite::SQLite3 Threads::Threads)
    target_link_options(compat-store-tests PRIVATE "LINKER:--exclude-libs,ALL")
    set_target_properties(compat-store-tests PROPERTIES
        BUILD_RPATH "${CARGO_TARGET_DIR}/${RUST_PROFILE}")

    add_test(NAME compatibility-tests COMMAND compat-store-tests)
    add_test(NAME certutil-tests COMMAND compat-store-tests
        --certutil "${CARGO_TARGET_DIR}/${RUST_PROFILE}/certutil")
    add_test(NAME pqc-tests COMMAND compat-store-tests --pqc)
    foreach(algorithm ML-DSA-44 ML-DSA-65 ML-DSA-87
            MLDSA44-ECDSA-P256-SHA256 MLDSA65-ECDSA-P256-SHA512
            MLDSA65-ECDSA-P384-SHA512 MLDSA87-ECDSA-P384-SHA512)
        add_test(NAME certutil-${algorithm} COMMAND compat-store-tests
            --certutil "${CARGO_TARGET_DIR}/${RUST_PROFILE}/certutil" ${algorithm})
    endforeach()

    find_program(SCS_READELF NAMES readelf llvm-readelf REQUIRED)
    add_test(NAME static-crypto-linkage COMMAND ${CMAKE_COMMAND}
        "-DREADELF=${SCS_READELF}" "-DLIBRARY=$<TARGET_FILE:sys-cert-store>"
        "-DTOOL=${CARGO_TARGET_DIR}/${RUST_PROFILE}/certutil"
        "-DTESTS=$<TARGET_FILE:compat-store-tests>"
        -P "${PROJECT_SOURCE_DIR}/cmake/check-static-crypto.cmake")
endif()

install(FILES "${CARGO_TARGET_DIR}/${RUST_PROFILE}/libsys_cert_store.so"
    DESTINATION ${CMAKE_INSTALL_LIBDIR} RENAME libsys-cert-store.so)
install(PROGRAMS "${CARGO_TARGET_DIR}/${RUST_PROFILE}/certutil"
    DESTINATION ${CMAKE_INSTALL_BINDIR})
install(DIRECTORY include/ DESTINATION ${CMAKE_INSTALL_INCLUDEDIR})

include(CMakePackageConfigHelpers)
configure_package_config_file(cmake/sys-cert-store-config.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-config.cmake
    INSTALL_DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sys-cert-store)
write_basic_package_version_file(
    ${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-config-version.cmake
    COMPATIBILITY SameMajorVersion)
configure_file(cmake/sys-cert-store-targets.cmake.in
    ${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-targets.cmake @ONLY)
install(FILES
    ${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-config.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-config-version.cmake
    ${CMAKE_CURRENT_BINARY_DIR}/sys-cert-store-targets.cmake
    DESTINATION ${CMAKE_INSTALL_LIBDIR}/cmake/sys-cert-store)
