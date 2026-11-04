cmake_minimum_required(VERSION 3.20)
project(sys-cert-store VERSION 0.1.0 LANGUAGES C CXX)

include(GNUInstallDirs)
include(CTest)
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

set(SCS_CARGO_ENV_COMMON
    "MAKEFLAGS="
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
set(SCS_CARGO_ENV
    ${SCS_CARGO_ENV_COMMON}
    "CARGO_TARGET_DIR=${CARGO_TARGET_DIR}")

add_custom_target(sys-cert-store-rust ALL
    COMMAND ${CMAKE_COMMAND} -E env ${SCS_CARGO_ENV}
        ${CARGO_EXECUTABLE} build ${RUST_PROFILE_FLAG} --all-targets
    WORKING_DIRECTORY ${CMAKE_CURRENT_SOURCE_DIR}
    VERBATIM)
add_dependencies(sys-cert-store-rust scs-crypto)

if(BUILD_TESTING)
    add_test(NAME rust-tests COMMAND ${CMAKE_COMMAND} -E env ${SCS_CARGO_ENV}
        ${CARGO_EXECUTABLE} test ${RUST_PROFILE_FLAG})
    set_tests_properties(rust-tests PROPERTIES WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

    set(SCS_CONSUMER_TARGET_DIR "${CMAKE_CURRENT_BINARY_DIR}/bundled-consumer-target")
    add_test(NAME bundled-rlib-consumer COMMAND ${CMAKE_COMMAND} -E env
        ${SCS_CARGO_ENV_COMMON}
        "CARGO_TARGET_DIR=${SCS_CONSUMER_TARGET_DIR}"
        ${CARGO_EXECUTABLE} run ${RUST_PROFILE_FLAG} --locked
        --manifest-path "${PROJECT_SOURCE_DIR}/tests/bundled-consumer/Cargo.toml")
    set_tests_properties(bundled-rlib-consumer PROPERTIES
        WORKING_DIRECTORY "${CMAKE_CURRENT_SOURCE_DIR}")

    find_program(SCS_READELF NAMES readelf llvm-readelf REQUIRED)
    add_test(NAME static-crypto-linkage COMMAND ${CMAKE_COMMAND}
        "-DREADELF=${SCS_READELF}"
        "-DTOOL=${CARGO_TARGET_DIR}/${RUST_PROFILE}/certutil"
        "-DEXAMPLE=${CARGO_TARGET_DIR}/${RUST_PROFILE}/examples/list_certificates"
        "-DCONSUMER=${SCS_CONSUMER_TARGET_DIR}/${RUST_PROFILE}/bundled-consumer"
        -P "${PROJECT_SOURCE_DIR}/cmake/check-static-crypto.cmake")
    set_tests_properties(static-crypto-linkage PROPERTIES DEPENDS bundled-rlib-consumer)
endif()

install(PROGRAMS "${CARGO_TARGET_DIR}/${RUST_PROFILE}/certutil"
    DESTINATION ${CMAKE_INSTALL_BINDIR})
