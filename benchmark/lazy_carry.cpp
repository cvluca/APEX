#include <libapex.h>
#include <cryptocontextfactory.h>
#include <ring-params.h>
#include <fstream>
#include <ctime>
#include <iomanip>
#include <algorithm>
#include <string>

using namespace lbcrypto;
using namespace apex;

// Release OpenFHE global state (context registry + cached keys) to free memory.
// Without this, each GenCryptoContext accumulates in a global static map.
static void release_crypto_context() {
  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

// Helper function to write results to CSV
void write_to_csv(const std::string& test_type, uint64_t ring_dim,
                  uint32_t radix, bool use_balance,
                  uint32_t operation_count,
                  double operation_time, double balance_time, double carry_time,
                  uint32_t remaining_depth)
{
  const std::string filename = "lazy_carry_results.csv";
  bool file_exists = false;

  // Check if file exists
  std::ifstream check_file(filename);
  if (check_file.good()) {
    file_exists = true;
  }
  check_file.close();

  // Open file in append mode
  std::ofstream csv_file(filename, std::ios::app);

  // Write header if file doesn't exist
  if (!file_exists) {
    csv_file << "test_type,ring_dim,radix,use_balance,operation_count,"
             << "operation_time_ms,balance_time_ms,carry_time_ms,"
             << "total_time_ms,per_op_operation_time_ms,per_op_balance_time_ms,per_op_carry_time_ms,"
             << "per_op_total_time_ms,remaining_depth,timestamp\n";
  }

  // Get current timestamp
  std::time_t now = std::time(nullptr);
  char timestamp[100];
  std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

  // Calculate per-op times (in milliseconds)
  double total_time = operation_time + balance_time + carry_time;
  double per_op_operation_time_ms = operation_time / operation_count;
  double per_op_balance_time_ms = balance_time / operation_count;
  double per_op_carry_time_ms = carry_time / operation_count;
  double per_op_total_time_ms = total_time / operation_count;

  // Write data
  csv_file << test_type << ","
           << ring_dim << ","
           << radix << ","
           << (use_balance ? "yes" : "no") << ","
           << operation_count << ","
           << std::fixed << std::setprecision(3) << operation_time << ","
           << std::fixed << std::setprecision(3) << balance_time << ","
           << std::fixed << std::setprecision(3) << carry_time << ","
           << std::fixed << std::setprecision(3) << total_time << ","
           << std::fixed << std::setprecision(6) << per_op_operation_time_ms << ","
           << std::fixed << std::setprecision(6) << per_op_balance_time_ms << ","
           << std::fixed << std::setprecision(6) << per_op_carry_time_ms << ","
           << std::fixed << std::setprecision(6) << per_op_total_time_ms << ","
           << remaining_depth << ","
           << timestamp << "\n";

  csv_file.close();
}

// Test consecutive addition operations (lazy carry strategy)
void test_addition(uint64_t ring_dim, uint32_t radix, bool use_balance, uint32_t num_operations, uint32_t mdepth)
{
  uint64_t p = RingParams::GetPlaintextModulus(ring_dim);
  const usint SLOT_COUNT = ring_dim;

  std::cout << "\n========== Addition Test ==========\n";
  std::cout << "RingDim: " << ring_dim << ", Radix: " << radix << ", UseBalance: " << (use_balance ? "yes" : "no")
            << ", Operations: " << num_operations << ", Depth: " << mdepth << std::endl;

  // Setup BGV CryptoContext
  CCParams<CryptoContextBGVRNS> parameters;
  SecretKeyDist secretKeyDist = SPARSE_TERNARY;
  parameters.SetSecretKeyDist(secretKeyDist);
  parameters.SetPlaintextModulus(p);
  parameters.SetMultiplicativeDepth(mdepth);
  parameters.SetRingDim(ring_dim);
  if (ring_dim <= (1 << 17))
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);

  KeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  ApexParams fparams;
  fparams.SetRadix(radix);
  fparams.SetSegmentCount(16 / radix);  // 16 bits total

  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);

  // Generate random inputs
  std::default_random_engine engine(42); // Fixed seed for reproducibility
  int64_t max_value = 100;
  std::uniform_int_distribution<int64_t> message(1, max_value);

  std::vector<int64_t> vec1(SLOT_COUNT), vec2(SLOT_COUNT);
  for (uint i = 0; i < SLOT_COUNT; i++) {
    vec1[i] = message(engine);
    vec2[i] = message(engine);
  }

  RadixPlaintext radix1 = ctx->MakePackedRadixPlaintext(vec1);
  RadixPlaintext radix2 = ctx->MakePackedRadixPlaintext(vec2);
  auto ct1 = ctx->Encrypt(radix1);
  auto ct2 = ctx->Encrypt(radix2);

  // Perform operations with timing
  double operation_time = 0, balance_time = 0, carry_time = 0;
  std::chrono::system_clock::time_point start, end;

  auto result = ct1;

  std::cout << "Initial state:\n";

  // All operations first, then carry once (lazy strategy)
  for (uint32_t i = 0; i < num_operations; i++) {
    result = ctx->EvalAdd(result, ct2);
  }

  start = std::chrono::system_clock::now();

  if (use_balance) {
    auto balance_start = std::chrono::system_clock::now();
    ctx->EvalBalanceInPlace(result);
    auto balance_end = std::chrono::system_clock::now();
    balance_time = std::chrono::duration_cast<std::chrono::microseconds>(balance_end - balance_start).count() / 1000.0;
    std::cout << "After balance:\n";
  }

  auto carry_start = std::chrono::system_clock::now();
  ctx->EvalCarryInPlace(result, true);
  auto carry_end = std::chrono::system_clock::now();
  carry_time = std::chrono::duration_cast<std::chrono::microseconds>(carry_end - carry_start).count() / 1000.0;
  std::cout << "After carry:\n";

  end = std::chrono::system_clock::now();
  operation_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0 - balance_time - carry_time;

  // Get remaining depth (use highest segment)
  uint32_t remaining_depth = mdepth - result->GetLevels().back();

  double total_time = operation_time + balance_time + carry_time;
  double per_op_operation_time_ms = operation_time / num_operations;
  double per_op_balance_time_ms = balance_time / num_operations;
  double per_op_carry_time_ms = carry_time / num_operations;
  double per_op_total_time_ms = total_time / num_operations;

  std::cout << "\nOperation time: " << operation_time << " ms\n";
  std::cout << "Balance time: " << balance_time << " ms\n";
  std::cout << "Carry time: " << carry_time << " ms\n";
  std::cout << "Total time: " << total_time << " ms\n";
  std::cout << "Per-op operation time: " << per_op_operation_time_ms << " ms\n";
  std::cout << "Per-op balance time: " << per_op_balance_time_ms << " ms\n";
  std::cout << "Per-op carry time: " << per_op_carry_time_ms << " ms\n";
  std::cout << "Per-op total time: " << per_op_total_time_ms << " ms\n";
  std::cout << "Min remaining depth: " << remaining_depth << "\n";

  // Write to CSV
  write_to_csv("addition", ring_dim, radix, use_balance, num_operations, operation_time, balance_time, carry_time, remaining_depth);
  release_crypto_context();
}

struct MultResult {
  uint32_t radix;
  uint32_t num_ops;
  double balance_time;
  double carry_time;
  double total_time;
  uint32_t remaining_depth;
};

// Test consecutive multiplication operations (lazy carry strategy)
MultResult test_multiplication(uint64_t ring_dim, uint32_t radix, bool use_balance, uint32_t num_operations, uint32_t mdepth)
{
  uint64_t p = RingParams::GetPlaintextModulus(ring_dim);
  const usint SLOT_COUNT = ring_dim;

  std::cout << "\n========== Multiplication Test ==========\n";
  std::cout << "RingDim: " << ring_dim << ", Radix: " << radix << ", UseBalance: " << (use_balance ? "yes" : "no")
            << ", Operations: " << num_operations << ", Depth: " << mdepth << std::endl;

  // Setup BGV CryptoContext
  CCParams<CryptoContextBGVRNS> parameters;
  SecretKeyDist secretKeyDist = SPARSE_TERNARY;
  parameters.SetSecretKeyDist(secretKeyDist);
  parameters.SetPlaintextModulus(p);
  parameters.SetMultiplicativeDepth(mdepth);
  parameters.SetRingDim(ring_dim);
  if (ring_dim <= (1 << 17))
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  KeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  ApexParams fparams;
  fparams.SetRadix(radix);
  fparams.SetSegmentCount(16 / radix);  // 16 bits total

  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);

  // Generate random inputs
  std::default_random_engine engine(42);
  int64_t max_value = 10; // Smaller values for multiplication
  std::uniform_int_distribution<int64_t> message(2, max_value);

  std::vector<int64_t> vec1(SLOT_COUNT), vec2(SLOT_COUNT);
  for (uint i = 0; i < SLOT_COUNT; i++) {
    vec1[i] = message(engine);
    vec2[i] = message(engine);
  }

  RadixPlaintext radix1 = ctx->MakePackedRadixPlaintext(vec1);
  RadixPlaintext radix2 = ctx->MakePackedRadixPlaintext(vec2);
  auto ct1 = ctx->Encrypt(radix1);
  auto ct2 = ctx->Encrypt(radix2);

  // Perform operations with timing
  double operation_time = 0, balance_time = 0, carry_time = 0;
  std::chrono::system_clock::time_point start, end;

  auto result = ct1;

  std::cout << "Initial state:\n";

  // All operations first, then carry once (lazy strategy)
  for (uint32_t i = 0; i < num_operations; i++) {
    result = ctx->EvalMult(result, ct2);
    std::cout << "After operation " << (i+1) << " (Mult):\n";
    ctx->ReduceSegmentInPlace(result, fparams);
  }

  start = std::chrono::system_clock::now();

  if (use_balance) {
    auto balance_start = std::chrono::system_clock::now();
    ctx->EvalBalanceInPlace(result);
    auto balance_end = std::chrono::system_clock::now();
    balance_time = std::chrono::duration_cast<std::chrono::microseconds>(balance_end - balance_start).count() / 1000.0;
    std::cout << "After balance:\n";
  }

  auto carry_start = std::chrono::system_clock::now();
  ctx->EvalCarryInPlace(result, true);
  auto carry_end = std::chrono::system_clock::now();
  carry_time = std::chrono::duration_cast<std::chrono::microseconds>(carry_end - carry_start).count() / 1000.0;
  std::cout << "After carry:\n";

  end = std::chrono::system_clock::now();
  operation_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0 - balance_time - carry_time;

  // Get remaining depth (use highest segment)
  uint32_t remaining_depth = mdepth - result->GetLevels().back();

  double total_time = operation_time + balance_time + carry_time;
  double per_op_operation_time_ms = operation_time / num_operations;
  double per_op_balance_time_ms = balance_time / num_operations;
  double per_op_carry_time_ms = carry_time / num_operations;
  double per_op_total_time_ms = total_time / num_operations;

  std::cout << "\nOperation time: " << operation_time << " ms\n";
  std::cout << "Balance time: " << balance_time << " ms\n";
  std::cout << "Carry time: " << carry_time << " ms\n";
  std::cout << "Total time: " << total_time << " ms\n";
  std::cout << "Per-op operation time: " << per_op_operation_time_ms << " ms\n";
  std::cout << "Per-op balance time: " << per_op_balance_time_ms << " ms\n";
  std::cout << "Per-op carry time: " << per_op_carry_time_ms << " ms\n";
  std::cout << "Per-op total time: " << per_op_total_time_ms << " ms\n";
  std::cout << "Min remaining depth: " << remaining_depth << "\n";

  // Write to CSV
  write_to_csv("multiplication", ring_dim, radix, use_balance, num_operations, operation_time, balance_time, carry_time, remaining_depth);
  release_crypto_context();
  return {radix, num_operations, balance_time, carry_time, total_time, remaining_depth};
}


// Configuration for each radix
struct RadixTestConfig {
  uint32_t radix;
  uint32_t addition_depth;
  uint32_t multiplication_depth;
  std::vector<uint32_t> addition_ops;
  std::vector<uint32_t> multiplication_ops;
};

int main(int argc, char* argv[])
{
  std::cout << "========================================\n";
  std::cout << "Lazy Carry Cost and Convergence Experiment\n";
  std::cout << "========================================\n";

  // Parse command-line arguments
  uint64_t cli_ring_dim = 1 << 16;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--ring-dim" && i + 1 < argc) {
      cli_ring_dim = std::stoull(argv[++i]);
    } else if (arg == "--quick") {
      cli_ring_dim = 1 << 7;
    }
  }

  // Configuration for different radix values
  std::vector<RadixTestConfig> radix_configs = {
    {
      .radix = 2,
      .addition_depth = 43,
      .multiplication_depth = 38,
      .addition_ops = {1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50},
      .multiplication_ops = {1, 2}
    },
    {
      .radix = 4,
      .addition_depth = 36,
      .multiplication_depth = 32,
      .addition_ops = {1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50},
      .multiplication_ops = {1, 2}
    },
    {
      .radix = 8,
      .addition_depth = 28,
      .multiplication_depth = 20,
      .addition_ops = {1, 5, 10, 15, 20, 25, 30, 35, 40, 45, 50},
      .multiplication_ops = {1}
    },
  };

  // Define test parameters
  std::vector<uint64_t> ring_dims = {cli_ring_dim};
  std::vector<bool> balance_options = {false, true};  // Test with and without EvalBalance

  // Run all tests
  std::vector<MultResult> mult_results;

  for (auto ring_dim : ring_dims) {
    std::cout << "\n\n========================================\n";
    std::cout << "Testing with RingDim = " << ring_dim << "\n";
    std::cout << "========================================\n";

    for (const auto& config : radix_configs) {
      // Test addition operations with all balance options
      for (auto use_balance : balance_options) {
        std::cout << "\n--- Addition Tests: Radix = " << config.radix
                  << ", UseBalance = " << (use_balance ? "yes" : "no") << " ---\n";
        for (auto num_ops : config.addition_ops) {
          test_addition(ring_dim, config.radix, use_balance, num_ops, config.addition_depth);
        }
      }

      // Test multiplication operations with balance=true only
      std::cout << "\n--- Multiplication Tests: Radix = " << config.radix
                << ", UseBalance = yes ---\n";
      for (auto num_ops : config.multiplication_ops) {
        mult_results.push_back(
          test_multiplication(ring_dim, config.radix, true, num_ops, config.multiplication_depth));
      }
    }
  }

  // Print multiplication summary table
  // Find results by radix and ops
  auto find_mult = [&](uint32_t radix, uint32_t ops) -> const MultResult* {
    for (const auto& r : mult_results)
      if (r.radix == radix && r.num_ops == ops) return &r;
    return nullptr;
  };

  std::cout << "\n" << std::string(60, '=') << "\n";
  std::cout << "Multiplication Carry Cost\n";
  std::cout << std::string(60, '=') << "\n";
  std::cout << std::left << std::setw(24) << ""
            << std::setw(12) << "2-bit"
            << std::setw(12) << "4-bit"
            << std::setw(12) << "8-bit" << "\n";
  std::cout << std::string(60, '-') << "\n";

  // Row: 1 Mult
  std::cout << std::left << std::setw(24) << "1 Mult (ms)";
  for (uint32_t r : {2u, 4u, 8u}) {
    auto* p = find_mult(r, 1);
    if (p) std::cout << std::setw(12) << std::fixed << std::setprecision(1) << p->total_time;
    else   std::cout << std::setw(12) << "-";
  }
  std::cout << "\n";

  // Row: 2 Mult (total)
  std::cout << std::left << std::setw(24) << "2 Mult total (ms)";
  for (uint32_t r : {2u, 4u, 8u}) {
    auto* p = find_mult(r, 2);
    if (p) std::cout << std::setw(12) << std::fixed << std::setprecision(1) << p->total_time;
    else   std::cout << std::setw(12) << "-";
  }
  std::cout << "\n";

  // Row: 2 Mult (amortized = total / 2)
  std::cout << std::left << std::setw(24) << "2 Mult amortized (ms)";
  for (uint32_t r : {2u, 4u, 8u}) {
    auto* p = find_mult(r, 2);
    if (p) std::cout << std::setw(12) << std::fixed << std::setprecision(1) << p->total_time / 2.0;
    else   std::cout << std::setw(12) << "-";
  }
  std::cout << "\n";
  std::cout << std::string(60, '=') << "\n";

  std::cout << "\n========================================\n";
  std::cout << "All tests completed!\n";
  std::cout << "Results written to lazy_carry_results.csv\n";
  std::cout << "========================================\n";

  return 0;
}
