#include <libapex.h>
#include <cryptocontextfactory.h>
#include "openfhe.h"
#include "ciphertext-ser.h"
#include "cryptocontext-ser.h"
#include "key/key-ser.h"
#include "scheme/bgvrns/bgvrns-ser.h"
#include "ring-params.h"
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <sstream>
#include <string>
#include <vector>

using namespace lbcrypto;
using namespace apex;

// Release OpenFHE global state (context registry + cached keys) to free memory.
// Without this, each GenCryptoContext accumulates in a global static map.
static void release_crypto_context() {
  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

// ─────────────────────────────────────────────────────────────────────────────
// Utility: calculate ciphertext size in bytes from segments
// ─────────────────────────────────────────────────────────────────────────────

template <typename T>
uint64_t calculate_ciphertext_size_bytes(const T& segments)
{
  uint64_t total = 0;
  for (const auto& segment : segments) {
    const auto& elements = segment->GetElements();
    for (const auto& elem : elements) {
      total += elem.GetNumOfElements() * elem.GetLength() * sizeof(uint64_t);
    }
  }
  return total;
}

uint64_t calculate_serialized_size(const StringCiphertext& ct)
{
  std::ostringstream os;
  const auto& segments = ct->GetSegments();
  for (const auto& segment : segments) {
    Serial::Serialize(segment, os, SerType::BINARY);
  }
  return os.str().size();
}

// ─────────────────────────────────────────────────────────────────────────────
// Part 1: String Ciphertext Size (Table 5)
// ─────────────────────────────────────────────────────────────────────────────

struct StringSizeConfig {
  uint64_t ring_dim;
  uint32_t string_length;
  uint32_t mdepth;
  uint32_t radix;
};

struct StringSizeResult {
  uint32_t radix;
  uint32_t num_segments;
  uint32_t num_rns_towers;
  double calc_total_mb;
  double serial_total_mb;
  double calc_kb_per_string;
  double serial_kb_per_string;
  double overhead_pct;
};

StringSizeResult run_string_size_test(const StringSizeConfig& config)
{
  const uint64_t RingDim = config.ring_dim;
  const uint64_t PlaintextModulus = RingParams::GetPlaintextModulus(RingDim);
  const uint32_t string_length = config.string_length;
  const uint32_t mdepth = config.mdepth;
  const uint32_t radix = config.radix;

  std::cout << "\n" << std::string(80, '=') << "\n";
  std::cout << "String Ciphertext Size Test:\n";
  std::cout << "  RingDim:          " << RingDim << "\n";
  std::cout << "  PlaintextModulus: " << PlaintextModulus << "\n";
  std::cout << "  String Length:    " << string_length << "\n";
  std::cout << "  Mult Depth:       " << mdepth << "\n";
  std::cout << "  Radix:            " << radix << "\n";
  std::cout << std::string(80, '=') << "\n\n";

  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetPlaintextModulus(PlaintextModulus);
  parameters.SetMultiplicativeDepth(mdepth);
  parameters.SetRingDim(RingDim);
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
  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);

  std::vector<std::string> test_strings(RingDim);
  std::string test_str = "helloworldabcdef";
  for (size_t i = 0; i < RingDim; i++) {
    if (test_str.length() >= string_length) {
      test_strings[i] = test_str.substr(0, string_length);
    } else {
      test_strings[i] = test_str + std::string(string_length - test_str.length(), 'a');
    }
  }

  std::cout << "Encrypting " << RingDim << " strings of length " << string_length << "...\n";

  StringPlaintext string_ptxt = ctx->MakePackedStringPlaintext(test_strings, string_length);
  auto string_ctxt = ctx->Encrypt(string_ptxt);

  std::cout << "Encryption complete.\n\n";

  uint64_t calc_total_bytes = calculate_ciphertext_size_bytes(string_ctxt->GetSegments());
  uint64_t serial_total_bytes = calculate_serialized_size(string_ctxt);

  double calc_total_mb = static_cast<double>(calc_total_bytes) / (1024.0 * 1024.0);
  double serial_total_mb = static_cast<double>(serial_total_bytes) / (1024.0 * 1024.0);

  double calc_bytes_per_slot = static_cast<double>(calc_total_bytes) / RingDim;
  double serial_bytes_per_slot = static_cast<double>(serial_total_bytes) / RingDim;

  double calc_bytes_per_string = calc_bytes_per_slot * string_length;
  double serial_bytes_per_string = serial_bytes_per_slot * string_length;

  double calc_kb_per_string = calc_bytes_per_string / 1024.0;
  double serial_kb_per_string = serial_bytes_per_string / 1024.0;

  double overhead_pct = ((static_cast<double>(serial_total_bytes) / calc_total_bytes) - 1.0) * 100.0;

  const auto& segments = string_ctxt->GetSegments();

  uint32_t num_segments = segments.size();
  uint32_t num_rns_towers = 0;

  if (!segments.empty()) {
    const auto& elements = segments[0]->GetElements();
    if (!elements.empty()) {
      num_rns_towers = elements[0].GetNumOfElements();
    }
  }

  std::cout << "Structure:\n";
  std::cout << "  Number of segments:     " << num_segments << "\n";
  std::cout << "  RNS Towers per element: " << num_rns_towers << "\n";
  std::cout << "Total Size (all " << RingDim << " slots):\n";
  std::cout << "  Calculated:  " << std::fixed << std::setprecision(3) << calc_total_mb << " MB\n";
  std::cout << "  Serialized:  " << std::fixed << std::setprecision(3) << serial_total_mb << " MB\n";
  std::cout << "Per String (length " << string_length << "):\n";
  std::cout << "  Calculated:  " << std::fixed << std::setprecision(3) << calc_kb_per_string << " KB\n";
  std::cout << "  Serialized:  " << std::fixed << std::setprecision(3) << serial_kb_per_string << " KB\n\n";

  release_crypto_context();
  return StringSizeResult{
    radix, num_segments, num_rns_towers,
    calc_total_mb, serial_total_mb,
    calc_kb_per_string, serial_kb_per_string,
    overhead_pct
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Part 2: Integer (Radix) Ciphertext Size (Table 6)
// ─────────────────────────────────────────────────────────────────────────────

struct IntSizeConfig {
  uint32_t precision;
  uint32_t radix;
  uint32_t mdepth;
};

struct IntSizeResult {
  uint32_t precision;
  uint32_t radix;
  uint32_t segment_count;
  uint32_t num_rns_towers;
  uint64_t slot_count;
  double ciphertext_size_mb;
};

uint32_t calculateSegmentCount(uint32_t precision, uint32_t radix) {
  return (precision + radix - 1) / radix;
}

IntSizeResult run_int_size_test(const IntSizeConfig& config, uint64_t RingDim)
{
  uint32_t precision = config.precision;
  uint32_t radix = config.radix;
  uint32_t mdepth = config.mdepth;
  uint32_t segment_count = calculateSegmentCount(precision, radix);
  uint32_t B = 1 << radix;

  std::cout << "\n=== Integer Ciphertext Size: Precision = " << precision
            << " bits, B = 2^" << radix << " = " << B
            << ", segments = " << segment_count << " ===" << std::endl;

  uint64_t p = RingParams::GetPlaintextModulus(RingDim);

  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetPlaintextModulus(p);
  parameters.SetMultiplicativeDepth(mdepth);
  parameters.SetRingDim(RingDim);
  if (RingDim < (1 << 16))
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
  else
    parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  KeyPair<DCRTPoly> keyPair = cc->KeyGen();

  ApexParams fparams;
  fparams.SetRadix(radix);
  fparams.SetSegmentCount(segment_count);

  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);

  const usint SLOT_COUNT = RingDim;
  int64_t max_value = std::min(static_cast<int64_t>(std::pow(2, precision/2) - 1),
                               static_cast<int64_t>(1000000));

  std::default_random_engine engine(42);
  std::uniform_int_distribution<int64_t> dist(-max_value, max_value);

  std::vector<int64_t> vecX(SLOT_COUNT);
  for (uint32_t i = 0; i < SLOT_COUNT; i++) {
    vecX[i] = dist(engine);
  }

  RadixPlaintext radixX = ctx->MakePackedRadixPlaintext(vecX);
  auto ctX = ctx->Encrypt(radixX);

  size_t ciphertextBytes = calculate_ciphertext_size_bytes(ctX->GetSegments());
  double ciphertextSizeMB = static_cast<double>(ciphertextBytes) / (1024.0 * 1024.0);

  uint32_t num_rns_towers = 0;
  const auto& segments = ctX->GetSegments();
  if (!segments.empty()) {
    const auto& elements = segments[0]->GetElements();
    if (!elements.empty()) {
      num_rns_towers = elements[0].GetNumOfElements();
    }
  }

  std::cout << "  Segments: " << segment_count
            << ", RNS Towers: " << num_rns_towers
            << ", Slots: " << SLOT_COUNT
            << ", Size: " << std::fixed << std::setprecision(3) << ciphertextSizeMB << " MB"
            << std::endl;

  release_crypto_context();
  return IntSizeResult{
    precision, radix, segment_count, num_rns_towers,
    SLOT_COUNT, ciphertextSizeMB
  };
}

// ─────────────────────────────────────────────────────────────────────────────
// Main
// ─────────────────────────────────────────────────────────────────────────────

int main(int argc, char* argv[])
{
  uint64_t cli_ring_dim = 1 << 16;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--ring-dim" && i + 1 < argc) {
      cli_ring_dim = std::stoull(argv[++i]);
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Part 1: String Ciphertext Size (Table 5)
  // ═══════════════════════════════════════════════════════════════════════════

  std::cout << "\n" << std::string(80, '=') << "\n";
  std::cout << "PART 1: String Ciphertext Size Analysis\n";
  std::cout << std::string(80, '=') << "\n";

  std::vector<StringSizeConfig> string_configs = {
    {cli_ring_dim, 16, 19, 2},
    {cli_ring_dim, 16, 20, 4},
    {cli_ring_dim, 16, 22, 8},
  };

  std::vector<StringSizeResult> string_results;
  for (const auto& config : string_configs) {
    string_results.push_back(run_string_size_test(config));
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Part 2: Integer Ciphertext Size (Table 6)
  // ═══════════════════════════════════════════════════════════════════════════

  std::cout << "\n\n" << std::string(80, '=') << "\n";
  std::cout << "PART 2: Integer (Radix) Ciphertext Size Analysis\n";
  std::cout << std::string(80, '=') << "\n";

  // Same test cases as comparison.cpp (using depth_greater for each)
  std::vector<IntSizeConfig> int_configs = {
    {8,  2, 9},
    {8,  4, 9},
    {8,  8, 13},
    {16, 2, 9},
    {16, 4, 11},
    {16, 8, 14},
    {20, 2, 10},
    {20, 4, 11},
    {20, 8, 15},
    {32, 2, 10},
    {32, 4, 11},
    {32, 8, 16},
    {64, 2, 11},
    {64, 4, 12},
    {64, 8, 16},
  };

  std::vector<IntSizeResult> int_results;
  for (const auto& config : int_configs) {
    try {
      int_results.push_back(run_int_size_test(config, cli_ring_dim));
    } catch (const std::exception& e) {
      std::cerr << "Error: precision=" << config.precision
                << ", radix=" << config.radix << ": " << e.what() << std::endl;
    }
  }

  // ═══════════════════════════════════════════════════════════════════════════
  // Summary Tables
  // ═══════════════════════════════════════════════════════════════════════════

  // String summary
  const int W1 = 28;
  const int W2 = 14;

  std::cout << "\n\n" << std::string(80, '=') << "\n";
  std::cout << "SUMMARY: String Ciphertext Size (string length = 16)\n";
  std::cout << std::string(80, '=') << "\n";

  std::cout << std::left << std::setw(W1) << "Metric";
  for (const auto& r : string_results) {
    std::cout << std::right << std::setw(W2) << ("radix=" + std::to_string(r.radix));
  }
  std::cout << "\n" << std::string(W1 + W2 * string_results.size(), '-') << "\n";

  std::cout << std::left << std::setw(W1) << "Segments";
  for (const auto& r : string_results) {
    std::cout << std::right << std::setw(W2) << r.num_segments;
  }
  std::cout << "\n";

  std::cout << std::left << std::setw(W1) << "RNS Towers";
  for (const auto& r : string_results) {
    std::cout << std::right << std::setw(W2) << r.num_rns_towers;
  }
  std::cout << "\n";

  std::cout << std::left << std::setw(W1) << "Total (calc, MB)";
  for (const auto& r : string_results) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3) << r.calc_total_mb;
    std::cout << std::right << std::setw(W2) << oss.str();
  }
  std::cout << "\n";

  std::cout << std::left << std::setw(W1) << "Total (serial, MB)";
  for (const auto& r : string_results) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(3) << r.serial_total_mb;
    std::cout << std::right << std::setw(W2) << oss.str();
  }
  std::cout << "\n";

  std::cout << std::left << std::setw(W1) << "Serialization Overhead";
  for (const auto& r : string_results) {
    std::ostringstream oss;
    oss << std::fixed << std::setprecision(2) << r.overhead_pct << "%";
    std::cout << std::right << std::setw(W2) << oss.str();
  }
  std::cout << "\n" << std::string(W1 + W2 * string_results.size(), '-') << "\n";

  // Integer summary
  if (!int_results.empty()) {
    std::cout << "\n" << std::string(80, '=') << "\n";
    std::cout << "SUMMARY: Integer Ciphertext Size\n";
    std::cout << std::string(80, '=') << "\n";

    std::cout << std::left
              << std::setw(10) << "Prec"
              << std::setw(8) << "Radix"
              << std::setw(10) << "Segments"
              << std::setw(10) << "Towers"
              << std::setw(10) << "Slots"
              << std::setw(15) << "Size (MB)"
              << std::endl;
    std::cout << std::string(63, '-') << std::endl;

    for (const auto& r : int_results) {
      std::cout << std::left
                << std::setw(10) << r.precision
                << std::setw(8) << r.radix
                << std::setw(10) << r.segment_count
                << std::setw(10) << r.num_rns_towers
                << std::setw(10) << r.slot_count
                << std::setw(15) << std::fixed << std::setprecision(3) << r.ciphertext_size_mb
                << std::endl;
    }

    std::cout << std::string(63, '-') << "\n";
  }

  std::cout << "\n✓ All ciphertext size analyses completed successfully!\n\n";
  return 0;
}
