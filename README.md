# APEX: Accurate Parallel Expressive Homomorphic Execution for Encrypted Databases

[![DOI](https://zenodo.org/badge/1095803914.svg)](https://doi.org/10.5281/zenodo.19015208)
[![Build](https://github.com/cvluca/APEX/actions/workflows/build.yml/badge.svg)](https://github.com/cvluca/APEX/actions/workflows/build.yml)
[![Artifact Build](https://github.com/cvluca/APEX/actions/workflows/artifact.yml/badge.svg)](https://github.com/cvluca/APEX/actions/workflows/artifact.yml)

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

## Citation

If you use APEX in your research, please cite our paper:

> W. Chen, Q. Hu, S.-M. Yiu, and H. Cui, "APEX: Accurate Parallel Expressive Homomorphic Execution for Encrypted Databases," in *2026 IEEE Symposium on Security and Privacy (SP)*, 2026, pp. 3111–3129. doi: 10.1109/SP63933.2026.00173.

```bibtex
@inproceedings{chen2026apex,
  title     = {{APEX}: Accurate Parallel Expressive Homomorphic Execution for Encrypted Databases},
  author    = {Chen, Wei and Hu, Qi and Yiu, Siu-Ming and Cui, Heming},
  booktitle = {2026 IEEE Symposium on Security and Privacy (SP)},
  year      = {2026},
  pages     = {3111--3129},
  doi       = {10.1109/SP63933.2026.00173},
}
```

## License

BSD 2-Clause License. See [LICENSE](LICENSE) for details.
