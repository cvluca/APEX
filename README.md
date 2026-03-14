# APEX: Accurate Parallel Expressive Homomorphic Execution for Encrypted Databases

> [!NOTE]
> For reproducing the experimental results from the paper (IEEE S&P 2026), see [ARTIFACT.md](ARTIFACT.md).

## Project Structure

```
APEX/
├── include/                  # Public header files
├── src/                      # Source implementation
│   ├── coeffs/               # Polynomial coefficient utilities
│   ├── radix/                # Radix arithmetic operations
│   └── string/               # String encoding and pattern matching
├── examples/                 # Example programs
├── benchmark/                # Performance benchmarks
├── tests/                    # Test suite
└── third-party/              # External dependencies
    └── openfhe-development/  # OpenFHE library (submodule)
```

## Dependencies

- **OpenFHE**: Homomorphic encryption library v1.3.0 (included as submodule)
- **CMake**: Build system (version 3.13 or higher)
- **C++17**: Standard C++ compiler with C++17 support

## Building the Project

### Clone with Submodules

```bash
git clone --recursive https://github.com/cvluca/APEX.git
cd APEX
```

If you already cloned without `--recursive`:

```bash
git submodule update --init --recursive
```

### Build Steps

```bash
mkdir build
cd build
cmake ..
make -j$(nproc)
```

### Build Options

Control what gets built using CMake options:

- `APEX_BUILD_EXAMPLES`: Build example programs (default: ON)
- `APEX_BUILD_BENCHMARKS`: Build benchmark suite (default: ON)
- `APEX_BUILD_TESTS`: Build test suite (default: ON)
- `WITH_OPENMP`: Enable OpenMP in OpenFHE (default: OFF)

To disable examples:

```bash
cmake -DAPEX_BUILD_EXAMPLES=OFF ..
```

## Running Examples

After building, executables are located in:

- Examples: `build/examples/`
- Benchmarks: `build/benchmark/`
- Tests: `build/tests/`

Example execution:

```bash
./build/examples/rahc
./build/benchmark/tpch
```

## Benchmarks

- **comparison.cpp**: Encrypted integer comparison operations
- **hybrid_queries.cpp**: Hybrid encrypted database queries
- **tpch.cpp**: TPC-H database query operations on encrypted data
- **lazy_carry.cpp**: Performance evaluation of lazy carry propagation strategies
- **pattern_match.cpp**: String pattern matching with wildcard support
- **ciphertext-size.cpp**: Analysis of encrypted string and integer storage requirements

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.
