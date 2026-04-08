# libkmip

libkmip is an ISO C11 implementation of the Key Management Interoperability
Protocol (KMIP), an [OASIS][oasis] communication standard for the management
of objects stored and maintained by key management systems. KMIP defines how
key management operations and operation data should be encoded and
communicated, between client and server applications. Supported operations
include creating, retrieving, and destroying keys. Supported object types
include:

* symmetric and asymmetric encryption keys

For more information on KMIP, check out the
[OASIS KMIP Technical Committee][kmip] and the
[OASIS KMIP Documentation][spec].

For more information on libkmip, check out the project [Documentation][docs].

## Build

Configure and build with CMake:

```bash
cmake -S . -B cmake-build-debug -DCMAKE_BUILD_TYPE=Debug
cmake --build cmake-build-debug -j
```

By default, `BUILD_KMIP_TESTS` is `OFF`.

## Run Demos

Demo binaries are created in `cmake-build-debug/libkmip/src/`.
For example:

```bash
./cmake-build-debug/libkmip/src/demo_query
```

## Run Tests

Enable tests at configure time, then run them with CTest:

```bash
cmake -S . -B cmake-build-tests -DCMAKE_BUILD_TYPE=Debug -DBUILD_KMIP_TESTS=ON
cmake --build cmake-build-tests -j
ctest --test-dir cmake-build-tests --output-on-failure
```

`BUILD_KMIP_TESTS=ON` builds `libkmip/src/tests.c` into the `kmip_tests` target
and registers it with CTest.

## Build with ASAN

AddressSanitizer can be enabled with `WITH_ASAN=ON` (Clang/GCC):

```bash
cmake -S . -B cmake-build-asan -DCMAKE_BUILD_TYPE=Debug -DWITH_ASAN=ON -DBUILD_KMIP_TESTS=ON
cmake --build cmake-build-asan -j
ctest --test-dir cmake-build-asan --output-on-failure
```

## Installation

Install using CMake:

```bash
cmake -S . -B cmake-build-release -DCMAKE_BUILD_TYPE=Release
cmake --build cmake-build-release -j
cmake --install cmake-build-release
```

To install to a custom prefix, add
`-DCMAKE_INSTALL_PREFIX=/your/prefix/path` when configuring.

See [Installation][install] for more information.

[docs]: https://libkmip.readthedocs.io/en/latest/index.html
[install]: https://libkmip.readthedocs.io/en/latest/installation.html
[kmip]: https://www.oasis-open.org/committees/tc_home.php?wg_abbrev=kmip
[oasis]: https://www.oasis-open.org
[spec]: https://docs.oasis-open.org/kmip/spec
