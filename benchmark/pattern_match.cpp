#include <libapex.h>
#include <cryptocontextfactory.h>
#include <fstream>
#include <iomanip>
#include <ctime>

using namespace lbcrypto;
using namespace apex;

// Release OpenFHE global state (context registry + cached keys) to free memory.
// Without this, each GenCryptoContext accumulates in a global static map.
static void release_crypto_context() {
  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

// Helper function to generate random lowercase string
std::string generate_random_string(size_t length, std::default_random_engine& engine)
{
  std::uniform_int_distribution<int> char_dist(0, 25); // a-z
  std::string str(length, ' ');
  for (size_t i = 0; i < length; i++) {
    str[i] = 'a' + char_dist(engine);
  }
  return str;
}

// Helper function to generate query pattern with evenly distributed wildcards
// First and last positions must be characters
// Wildcards distributed evenly in positions [1, query_length-2]
// wildcard_char: '_' for ANY1, '%' for STAR
std::string generate_query_pattern_distributed(uint32_t query_length, uint32_t num_wildcards,
                                                char wildcard_char,
                                                std::default_random_engine& engine)
{
  std::uniform_int_distribution<int> char_dist(0, 25); // a-z

  // Start with all characters
  std::string pattern(query_length, ' ');
  for (uint32_t i = 0; i < query_length; i++) {
    pattern[i] = 'a' + char_dist(engine);
  }

  // Place wildcards evenly distributed
  if (num_wildcards > 0) {
    uint32_t available_positions = query_length - 2; // Exclude first and last
    double interval = (double)available_positions / num_wildcards;

    for (uint32_t i = 0; i < num_wildcards; i++) {
      uint32_t pos = 1 + (uint32_t)(i * interval);
      pattern[pos] = wildcard_char;
    }
  }

  return pattern;
}

// Helper function to check if a string matches a pattern
// Pattern can contain: '_' (ANY1 - matches single char), '%' (STAR - matches any length)
bool matches_pattern(const std::string& str, const std::string& pattern)
{
  if (str.length() != pattern.length()) {
    return false;
  }

  for (size_t i = 0; i < str.length(); i++) {
    // '_' and '%' are wildcards that match any character
    if (pattern[i] != '_' && pattern[i] != '%' && str[i] != pattern[i]) {
      return false;
    }
  }

  return true;
}

// Helper function to generate a string that matches a pattern
// Replaces wildcards ('_' or '%') with random characters
std::string generate_matching_string(const std::string& pattern, std::default_random_engine& engine)
{
  std::uniform_int_distribution<int> char_dist(0, 25); // a-z
  std::string str = pattern;

  for (size_t i = 0; i < str.length(); i++) {
    if (str[i] == '_' || str[i] == '%') {
      str[i] = 'a' + char_dist(engine);
    }
  }

  return str;
}

// Calculate total ciphertext size in bytes
uint64_t calculate_ciphertext_size(const StringCiphertext& ct)
{
  uint64_t total_size = 0;

  // Calculate size from segments
  const auto& segments = ct->GetSegments();
  for (const auto& segment : segments) {
    const auto& elements = segment->GetElements();
    for (size_t i = 0; i < elements.size(); i++) {
      total_size += elements[i].GetLength() * sizeof(uint64_t);
    }
  }

  // Calculate size from mask
  const auto& mask = ct->GetMask();
  for (const auto& mask_ct : mask) {
    const auto& elements = mask_ct->GetElements();
    for (size_t i = 0; i < elements.size(); i++) {
      total_size += elements[i].GetLength() * sizeof(uint64_t);
    }
  }

  return total_size;
}

// Write results to CSV file
void write_to_csv(const std::string& filename,
                  uint32_t test_id,
                  uint64_t ring_dim,
                  uint32_t radix,
                  uint32_t string_length,
                  uint32_t num_wildcards,
                  const std::string& wildcard_type,
                  uint32_t query_length,
                  double total_time_sec,
                  double per_string_time_ms,
                  uint64_t ciphertext_size_bytes,
                  double per_slot_size_kb,
                  double per_string_size_kb,
                  uint64_t num_slots,
                  uint64_t num_matches,
                  double match_rate,
                  uint32_t depth_allocated,
                  uint32_t depth_used)
{
  bool file_exists = false;
  std::ifstream check_file(filename);
  if (check_file.good()) {
    file_exists = true;
  }
  check_file.close();

  std::ofstream csv_file(filename, std::ios::app);

  // Write header if file doesn't exist
  if (!file_exists) {
    csv_file << "test_id,ring_dim,radix,string_length,num_wildcards,wildcard_type,query_length,"
             << "total_time_sec,per_string_time_ms,ciphertext_size_bytes,"
             << "per_slot_size_kb,per_string_size_kb,num_slots,num_matches,match_rate,"
             << "depth_allocated,depth_used,depth_remaining\n";
  }

  // Write data
  csv_file << test_id << ","
           << ring_dim << ","
           << radix << ","
           << string_length << ","
           << num_wildcards << ","
           << wildcard_type << ","
           << query_length << ","
           << std::fixed << std::setprecision(6) << total_time_sec << ","
           << std::fixed << std::setprecision(6) << per_string_time_ms << ","
           << ciphertext_size_bytes << ","
           << std::fixed << std::setprecision(6) << per_slot_size_kb << ","
           << std::fixed << std::setprecision(6) << per_string_size_kb << ","
           << num_slots << ","
           << num_matches << ","
           << std::fixed << std::setprecision(2) << match_rate << ","
           << depth_allocated << ","
           << depth_used << ","
           << (depth_allocated - depth_used) << "\n";

  csv_file.close();
}

// Test configuration structure
struct TestConfig {
  uint32_t param_value;  // The varying parameter (string_length, query_length, num_wildcards, etc.)
  uint32_t depth;
};

// Depth configuration for each radix
struct RadixDepthConfig {
  uint32_t radix;
  std::vector<uint32_t> test1_depths;  // Depths for varying string length
  std::vector<uint32_t> test2_depths;  // Depths for varying query length
  std::vector<uint32_t> test3_depths;  // Depths for varying ANY1 wildcards
  std::vector<uint32_t> test4_depths;  // Depths for varying STAR wildcards
};

// Helper function to combine param values with depths
std::vector<TestConfig> MakeTestConfigs(const std::vector<uint32_t>& params, const std::vector<uint32_t>& depths) {
  if (params.size() != depths.size()) {
    throw std::runtime_error("params and depths size mismatch");
  }
  std::vector<TestConfig> configs;
  for (size_t i = 0; i < params.size(); ++i) {
    configs.push_back({params[i], depths[i]});
  }
  return configs;
}

// Test 1: Varying string length (no wildcards)
// Fixed: query_length=5, num_wildcards=0
// Varying: string_length from 5 to 50
void test1_varying_string_length(uint64_t ring_dim, uint32_t radix, const std::vector<uint32_t>& depths)
{
  // Test parameters
  const std::vector<uint32_t> string_lengths = {5, 10, 15, 20, 25, 30, 35, 40, 45, 50};
  auto test_configs = MakeTestConfigs(string_lengths, depths);

  uint64_t p = RingParams::GetPlaintextModulus(ring_dim);
  const usint num_slots = ring_dim;

  std::cout << "\n========================================\n";
  std::cout << "Test 1: Varying String Length (No Wildcards)\n";
  std::cout << "========================================\n";
  std::cout << "RingDim: " << ring_dim << ", Slots: " << num_slots << "\n";
  std::cout << "Radix: " << radix << "\n";
  std::cout << "Fixed: query_length=5, num_wildcards=0\n\n";

  // Fixed parameters
  const uint32_t num_wildcards = 0;
  const uint32_t query_length = 5;

  std::default_random_engine engine(42); // Fixed seed for reproducibility

  uint32_t test_id = 1;
  for (const auto& config : test_configs) {
    uint32_t string_length = config.param_value;
    uint32_t mdepth = config.depth;

    std::cout << "Test " << test_id << ": String length = " << string_length << "\n";
    std::cout << "  Using multiplicative depth: " << mdepth << "\n";

    // Setup BGV CryptoContext
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(p);
    parameters.SetMultiplicativeDepth(mdepth);
    parameters.SetRingDim(ring_dim);
    if (ring_dim < (1 << 16))
      parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    else
      parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    parameters.SetSecretKeyDist(SecretKeyDist::SPARSE_TERNARY);

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

    // Generate query pattern with '%' prefix and suffix for substring matching
    std::string pattern_core = generate_random_string(query_length, engine);
    std::string pattern = "%" + pattern_core + "%";  // Add '%' at both ends
    std::cout << "  Query pattern: " << pattern << "\n";

    // Generate strings with ~50% match rate
    std::vector<std::string> values(num_slots);
    std::vector<bool> expected_matches(num_slots, false);
    std::uniform_int_distribution<int> match_dist(0, 1);
    uint64_t num_matches = 0;

    for (size_t i = 0; i < num_slots; i++) {
      bool should_match = (match_dist(engine) == 1);

      if (should_match && string_length >= query_length) {
        // Generate matching string: embed pattern_core at a random position
        if (string_length == query_length) {
          values[i] = pattern_core;
        } else {
          std::uniform_int_distribution<int> pos_dist(0, string_length - query_length);
          int insert_pos = pos_dist(engine);
          values[i] = generate_random_string(insert_pos, engine) +
                     pattern_core +
                     generate_random_string(string_length - query_length - insert_pos, engine);
        }
        expected_matches[i] = true;
        num_matches++;
      } else {
        // Generate non-matching string
        values[i] = generate_random_string(string_length, engine);
        // Ensure it doesn't accidentally contain pattern_core as substring
        while (values[i].find(pattern_core) != std::string::npos) {
          values[i][0] = (values[i][0] == 'a') ? 'b' : 'a'; // Modify first char
        }
        expected_matches[i] = false;
      }
    }

    double match_rate = (100.0 * num_matches) / num_slots;
    std::cout << "  Expected matches: " << num_matches << " (" << match_rate << "%)\n";

    // Print sample strings for debugging
    std::cout << "  Sample matching strings (first 3):\n";
    int match_count = 0;
    for (size_t i = 0; i < num_slots && match_count < 3; i++) {
      if (values[i].find(pattern_core) != std::string::npos) {
        std::cout << "    [" << i << "] \"" << values[i] << "\"\n";
        match_count++;
      }
    }
    std::cout << "  Sample non-matching strings (first 3):\n";
    int non_match_count = 0;
    for (size_t i = 0; i < num_slots && non_match_count < 3; i++) {
      if (values[i].find(pattern_core) == std::string::npos) {
        std::cout << "    [" << i << "] \"" << values[i] << "\"\n";
        non_match_count++;
      }
    }

    // Encrypt strings
    StringPlaintext string_ptxt = ctx->MakePackedStringPlaintext(values, string_length);
    auto string_ctxt = ctx->Encrypt(string_ptxt);

    // Encode pattern
    auto encoded_pattern = ctx->EncodePattern(pattern);
    auto encrypted_pattern = ctx->EncryptPattern(encoded_pattern);

    // Measure LIKE operation time
    std::chrono::system_clock::time_point start, end;
    start = std::chrono::system_clock::now();

    auto like_result = ctx->EvalLike(string_ctxt, encrypted_pattern);

    end = std::chrono::system_clock::now();

    double total_time_sec = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000000.0;

    // Get remaining depth
    uint32_t current_level = like_result->GetLevel();
    uint32_t remaining_depth = mdepth - current_level;

    // Verify results by decrypting
    Plaintext result_ptxt;
    cc->Decrypt(keyPair.secretKey, like_result, &result_ptxt);
    result_ptxt->SetLength(num_slots);
    std::vector<int64_t> decrypted_results = result_ptxt->GetPackedValue();

    // Compare with expected results
    uint64_t correct_predictions = 0;
    uint64_t false_positives = 0;
    uint64_t false_negatives = 0;

    for (size_t i = 0; i < num_slots; i++) {
      bool actual_match = (decrypted_results[i] != 0);
      bool expected_match = expected_matches[i];

      if (actual_match == expected_match) {
        correct_predictions++;
      } else if (actual_match && !expected_match) {
        false_positives++;
      } else if (!actual_match && expected_match) {
        false_negatives++;
      }
    }

    double accuracy = (100.0 * correct_predictions) / num_slots;
    std::cout << "  Verification: " << correct_predictions << "/" << num_slots << " correct (" << accuracy << "%)\n";
    if (false_positives > 0 || false_negatives > 0) {
      std::cout << "    False positives: " << false_positives << ", False negatives: " << false_negatives << "\n";
    }

    // Calculate ciphertext size
    uint64_t ciphertext_size_bytes = calculate_ciphertext_size(string_ctxt);

    // Calculate performance metrics
    uint64_t num_strings = num_slots;
    double per_string_time_ms = (total_time_sec * 1000.0) / num_strings;
    double per_slot_size_kb = (ciphertext_size_bytes / 1024.0) / num_slots;
    double per_string_size_kb = per_slot_size_kb;

    std::cout << "  Total time: " << total_time_sec << " sec\n";
    std::cout << "  Per-string time: " << per_string_time_ms << " ms\n";
    std::cout << "  Ciphertext size: " << ciphertext_size_bytes << " bytes\n";
    std::cout << "  Used levels: " << current_level << " / " << mdepth << "\n";
    std::cout << "  Remaining depth: " << remaining_depth << "\n\n";

    // Write to CSV
    write_to_csv("benchmark_test1_varying_string_length.csv",
                 test_id,
                 ring_dim,
                 radix,
                 string_length,
                 2,  // num_wildcards = 2 (% at both ends)
                 "STAR",
                 query_length + 2,  // query_length includes both '%' characters
                 total_time_sec,
                 per_string_time_ms,
                 ciphertext_size_bytes,
                 per_slot_size_kb,
                 per_string_size_kb,
                 num_slots,
                 num_matches,
                 match_rate,
                 mdepth,
                 current_level);

    release_crypto_context();
    test_id++;
  }

  std::cout << "\nTest 1 completed! Results written to benchmark_test1_varying_string_length.csv\n";
}

// Test 2: Varying query length (no wildcards)
// Fixed: string_length=50, num_wildcards=0
// Varying: query_length from 5 to 50
void test2_varying_query_length(uint64_t ring_dim, uint32_t radix, const std::vector<uint32_t>& depths)
{
  // Test parameters
  const std::vector<uint32_t> query_lengths = {5, 10, 15, 20, 25, 30, 35, 40, 45, 50};
  auto test_configs = MakeTestConfigs(query_lengths, depths);

  uint64_t p = RingParams::GetPlaintextModulus(ring_dim);
  const usint num_slots = ring_dim;

  std::cout << "\n========================================\n";
  std::cout << "Test 2: Varying Query Length (No Wildcards)\n";
  std::cout << "========================================\n";
  std::cout << "RingDim: " << ring_dim << ", Slots: " << num_slots << "\n";
  std::cout << "Radix: " << radix << "\n";
  std::cout << "Fixed: string_length=50, num_wildcards=0\n\n";

  // Fixed parameters
  const uint32_t string_length = 50;
  const uint32_t num_wildcards = 0;

  std::default_random_engine engine(42); // Fixed seed for reproducibility

  uint32_t test_id = 1;
  for (const auto& config : test_configs) {
    uint32_t query_length = config.param_value;
    uint32_t mdepth = config.depth;

    std::cout << "Test " << test_id << ": Query length = " << query_length << "\n";
    std::cout << "  Using multiplicative depth: " << mdepth << "\n";

    // Setup BGV CryptoContext
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(p);
    parameters.SetMultiplicativeDepth(mdepth);
    parameters.SetRingDim(ring_dim);
    if (ring_dim < (1 << 16))
      parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    else
      parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    parameters.SetSecretKeyDist(SecretKeyDist::SPARSE_TERNARY);

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

    // Generate query pattern with '%' prefix and suffix for substring matching
    std::string pattern_core = generate_random_string(query_length, engine);
    std::string pattern = "%" + pattern_core + "%";  // Add '%' at both ends
    std::cout << "  Query pattern: " << pattern << "\n";

    // Generate strings with ~50% match rate
    std::vector<std::string> values(num_slots);
    std::vector<bool> expected_matches(num_slots, false);
    std::uniform_int_distribution<int> match_dist(0, 1);
    uint64_t num_matches = 0;

    for (size_t i = 0; i < num_slots; i++) {
      bool should_match = (match_dist(engine) == 1);

      if (should_match) {
        // Generate matching string: embed pattern_core at a random position
        if (string_length == query_length) {
          values[i] = pattern_core;
        } else {
          std::uniform_int_distribution<int> pos_dist(0, string_length - query_length);
          int insert_pos = pos_dist(engine);
          values[i] = generate_random_string(insert_pos, engine) +
                     pattern_core +
                     generate_random_string(string_length - query_length - insert_pos, engine);
        }
        expected_matches[i] = true;
        num_matches++;
      } else {
        // Generate non-matching string
        values[i] = generate_random_string(string_length, engine);
        // Ensure it doesn't accidentally contain pattern_core as substring
        while (values[i].find(pattern_core) != std::string::npos) {
          values[i][0] = (values[i][0] == 'a') ? 'b' : 'a'; // Modify first char
        }
        expected_matches[i] = false;
      }
    }

    double match_rate = (100.0 * num_matches) / num_slots;
    std::cout << "  Expected matches: " << num_matches << " (" << match_rate << "%)\n";

    // Print sample strings for debugging
    std::cout << "  Sample matching strings (first 3):\n";
    int match_count = 0;
    for (size_t i = 0; i < num_slots && match_count < 3; i++) {
      if (values[i].find(pattern_core) != std::string::npos) {
        std::cout << "    [" << i << "] \"" << values[i] << "\"\n";
        match_count++;
      }
    }
    std::cout << "  Sample non-matching strings (first 3):\n";
    int non_match_count = 0;
    for (size_t i = 0; i < num_slots && non_match_count < 3; i++) {
      if (values[i].find(pattern_core) == std::string::npos) {
        std::cout << "    [" << i << "] \"" << values[i] << "\"\n";
        non_match_count++;
      }
    }

    // Encrypt strings
    StringPlaintext string_ptxt = ctx->MakePackedStringPlaintext(values, string_length);
    auto string_ctxt = ctx->Encrypt(string_ptxt);

    // Encode pattern
    auto encoded_pattern = ctx->EncodePattern(pattern);
    auto encrypted_pattern = ctx->EncryptPattern(encoded_pattern);

    // Measure LIKE operation time
    std::chrono::system_clock::time_point start, end;
    start = std::chrono::system_clock::now();

    auto like_result = ctx->EvalLike(string_ctxt, encrypted_pattern);

    end = std::chrono::system_clock::now();

    double total_time_sec = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000000.0;

    // Get remaining depth
    uint32_t current_level = like_result->GetLevel();
    uint32_t remaining_depth = mdepth - current_level;

    // Verify results by decrypting
    Plaintext result_ptxt;
    cc->Decrypt(keyPair.secretKey, like_result, &result_ptxt);
    result_ptxt->SetLength(num_slots);
    std::vector<int64_t> decrypted_results = result_ptxt->GetPackedValue();

    // Compare with expected results
    uint64_t correct_predictions = 0;
    uint64_t false_positives = 0;
    uint64_t false_negatives = 0;

    for (size_t i = 0; i < num_slots; i++) {
      bool actual_match = (decrypted_results[i] != 0);
      bool expected_match = expected_matches[i];

      if (actual_match == expected_match) {
        correct_predictions++;
      } else if (actual_match && !expected_match) {
        false_positives++;
      } else if (!actual_match && expected_match) {
        false_negatives++;
      }
    }

    double accuracy = (100.0 * correct_predictions) / num_slots;
    std::cout << "  Verification: " << correct_predictions << "/" << num_slots << " correct (" << accuracy << "%)\n";
    if (false_positives > 0 || false_negatives > 0) {
      std::cout << "    False positives: " << false_positives << ", False negatives: " << false_negatives << "\n";
    }

    // Calculate ciphertext size
    uint64_t ciphertext_size_bytes = calculate_ciphertext_size(string_ctxt);

    // Calculate performance metrics
    uint64_t num_strings = num_slots;
    double per_string_time_ms = (total_time_sec * 1000.0) / num_strings;
    double per_slot_size_kb = (ciphertext_size_bytes / 1024.0) / num_slots;
    double per_string_size_kb = per_slot_size_kb;

    std::cout << "  Total time: " << total_time_sec << " sec\n";
    std::cout << "  Per-string time: " << per_string_time_ms << " ms\n";
    std::cout << "  Ciphertext size: " << ciphertext_size_bytes << " bytes\n";
    std::cout << "  Used levels: " << current_level << " / " << mdepth << "\n";
    std::cout << "  Remaining depth: " << remaining_depth << "\n\n";

    // Write to CSV
    write_to_csv("benchmark_test2_varying_query_length.csv",
                 test_id,
                 ring_dim,
                 radix,
                 string_length,
                 2,  // num_wildcards = 2 (% at both ends)
                 "STAR",
                 query_length + 2,  // query_length includes both '%' characters
                 total_time_sec,
                 per_string_time_ms,
                 ciphertext_size_bytes,
                 per_slot_size_kb,
                 per_string_size_kb,
                 num_slots,
                 num_matches,
                 match_rate,
                 mdepth,
                 current_level);

    release_crypto_context();
    test_id++;
  }

  std::cout << "\nTest 2 completed! Results written to benchmark_test2_varying_query_length.csv\n";
}

// Test 3: Varying ANY1 wildcard count
// Fixed: string_length=25, query_length=25
// Varying: num_wildcards from 1 to 10 (ANY1 wildcards)
void test3_varying_any1_wildcards(uint64_t ring_dim, uint32_t radix, const std::vector<uint32_t>& depths)
{
  // Test parameters
  const std::vector<uint32_t> wildcard_counts = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  auto test_configs = MakeTestConfigs(wildcard_counts, depths);

  uint64_t p = RingParams::GetPlaintextModulus(ring_dim);
  const usint num_slots = ring_dim;

  std::cout << "\n========================================\n";
  std::cout << "Test 3: Varying ANY1 Wildcards\n";
  std::cout << "========================================\n";
  std::cout << "RingDim: " << ring_dim << ", Slots: " << num_slots << "\n";
  std::cout << "Radix: " << radix << "\n";
  std::cout << "Fixed: string_length=25, query_length=25\n\n";

  // Fixed parameters
  const uint32_t string_length = 25;
  const uint32_t query_length = 25;

  std::default_random_engine engine(42); // Fixed seed for reproducibility

  uint32_t test_id = 1;
  for (const auto& config : test_configs) {
    uint32_t num_wildcards = config.param_value;
    uint32_t mdepth = config.depth;

    std::cout << "Test " << test_id << ": Wildcards = " << num_wildcards << "\n";
    std::cout << "  Using multiplicative depth: " << mdepth << "\n";

    // Setup BGV CryptoContext
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(p);
    parameters.SetMultiplicativeDepth(mdepth);
    parameters.SetRingDim(ring_dim);
    if (ring_dim < (1 << 16))
      parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    else
      parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    parameters.SetSecretKeyDist(SecretKeyDist::SPARSE_TERNARY);

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

    // Generate query pattern with evenly distributed ANY1 wildcards (_)
    std::string pattern = generate_query_pattern_distributed(query_length, num_wildcards, '_', engine);
    std::cout << "  Query pattern: " << pattern << "\n";

    // Generate strings with ~50% match rate
    std::vector<std::string> values(num_slots);
    std::vector<bool> expected_matches(num_slots, false);
    std::uniform_int_distribution<int> match_dist(0, 1);
    uint64_t num_matches = 0;

    for (size_t i = 0; i < num_slots; i++) {
      bool should_match = (match_dist(engine) == 1);

      if (should_match) {
        // Generate matching string based on pattern
        values[i] = generate_matching_string(pattern, engine);
        expected_matches[i] = true;
        num_matches++;
      } else {
        // Generate non-matching string
        values[i] = generate_random_string(string_length, engine);
        // Ensure it doesn't accidentally match
        while (matches_pattern(values[i], pattern)) {
          values[i][0] = (values[i][0] == 'a') ? 'b' : 'a';
        }
        expected_matches[i] = false;
      }
    }

    double match_rate = (100.0 * num_matches) / num_slots;
    std::cout << "  Expected matches: " << num_matches << " (" << match_rate << "%)\n";

    // Print sample strings for debugging
    std::cout << "  Sample matching strings (first 3):\n";
    int match_count = 0;
    for (size_t i = 0; i < num_slots && match_count < 3; i++) {
      if (matches_pattern(values[i], pattern)) {
        std::cout << "    [" << i << "] \"" << values[i] << "\"\n";
        match_count++;
      }
    }
    std::cout << "  Sample non-matching strings (first 3):\n";
    int non_match_count = 0;
    for (size_t i = 0; i < num_slots && non_match_count < 3; i++) {
      if (!matches_pattern(values[i], pattern)) {
        std::cout << "    [" << i << "] \"" << values[i] << "\"\n";
        non_match_count++;
      }
    }

    // Encrypt strings
    StringPlaintext string_ptxt = ctx->MakePackedStringPlaintext(values, string_length);
    auto string_ctxt = ctx->Encrypt(string_ptxt);

    // Encode pattern
    auto encoded_pattern = ctx->EncodePattern(pattern);
    auto encrypted_pattern = ctx->EncryptPattern(encoded_pattern);

    // Measure LIKE operation time
    std::chrono::system_clock::time_point start, end;
    start = std::chrono::system_clock::now();

    auto like_result = ctx->EvalLike(string_ctxt, encrypted_pattern);

    end = std::chrono::system_clock::now();

    double total_time_sec = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000000.0;

    // Get remaining depth
    uint32_t current_level = like_result->GetLevel();
    uint32_t remaining_depth = mdepth - current_level;

    // Verify results by decrypting
    Plaintext result_ptxt;
    cc->Decrypt(keyPair.secretKey, like_result, &result_ptxt);
    result_ptxt->SetLength(num_slots);
    std::vector<int64_t> decrypted_results = result_ptxt->GetPackedValue();

    // Compare with expected results
    uint64_t correct_predictions = 0;
    uint64_t false_positives = 0;
    uint64_t false_negatives = 0;

    for (size_t i = 0; i < num_slots; i++) {
      bool actual_match = (decrypted_results[i] != 0);
      bool expected_match = expected_matches[i];

      if (actual_match == expected_match) {
        correct_predictions++;
      } else if (actual_match && !expected_match) {
        false_positives++;
      } else if (!actual_match && expected_match) {
        false_negatives++;
      }
    }

    double accuracy = (100.0 * correct_predictions) / num_slots;
    std::cout << "  Verification: " << correct_predictions << "/" << num_slots << " correct (" << accuracy << "%)\n";
    if (false_positives > 0 || false_negatives > 0) {
      std::cout << "    False positives: " << false_positives << ", False negatives: " << false_negatives << "\n";
    }

    // Calculate ciphertext size
    uint64_t ciphertext_size_bytes = calculate_ciphertext_size(string_ctxt);

    // Calculate performance metrics
    uint64_t num_strings = num_slots;
    double per_string_time_ms = (total_time_sec * 1000.0) / num_strings;
    double per_slot_size_kb = (ciphertext_size_bytes / 1024.0) / num_slots;
    double per_string_size_kb = per_slot_size_kb;

    std::cout << "  Total time: " << total_time_sec << " sec\n";
    std::cout << "  Per-string time: " << per_string_time_ms << " ms\n";
    std::cout << "  Ciphertext size: " << ciphertext_size_bytes << " bytes\n";
    std::cout << "  Used levels: " << current_level << " / " << mdepth << "\n";
    std::cout << "  Remaining depth: " << remaining_depth << "\n\n";

    // Write to CSV
    write_to_csv("benchmark_test3_varying_any1_wildcards.csv",
                 test_id,
                 ring_dim,
                 radix,
                 string_length,
                 num_wildcards,
                 "ANY1",
                 query_length,
                 total_time_sec,
                 per_string_time_ms,
                 ciphertext_size_bytes,
                 per_slot_size_kb,
                 per_string_size_kb,
                 num_slots,
                 num_matches,
                 match_rate,
                 mdepth,
                 current_level);

    release_crypto_context();
    test_id++;
  }

  std::cout << "\nTest 3 completed! Results written to benchmark_test3_varying_any1_wildcards.csv\n";
}

// Test 4: Varying STAR wildcard count
// Fixed: string_length=25, query_length=25
// Varying: num_wildcards from 1 to 10 (STAR wildcards)
void test4_varying_star_wildcards(uint64_t ring_dim, uint32_t radix, const std::vector<uint32_t>& depths)
{
  // Test parameters
  const std::vector<uint32_t> wildcard_counts = {1, 2, 3, 4, 5, 6, 7, 8, 9, 10};
  auto test_configs = MakeTestConfigs(wildcard_counts, depths);

  uint64_t p = RingParams::GetPlaintextModulus(ring_dim);
  const usint num_slots = ring_dim;

  std::cout << "\n========================================\n";
  std::cout << "Test 4: Varying STAR Wildcards\n";
  std::cout << "========================================\n";
  std::cout << "RingDim: " << ring_dim << ", Slots: " << num_slots << "\n";
  std::cout << "Radix: " << radix << "\n";
  std::cout << "Fixed: string_length=25, query_length=25\n\n";

  // Fixed parameters
  const uint32_t string_length = 25;
  const uint32_t query_length = 25;

  std::default_random_engine engine(42); // Fixed seed for reproducibility

  uint32_t test_id = 1;
  for (const auto& config : test_configs) {
    uint32_t num_wildcards = config.param_value;
    uint32_t mdepth = config.depth;

    std::cout << "Test " << test_id << ": Wildcards = " << num_wildcards << "\n";
    std::cout << "  Using multiplicative depth: " << mdepth << "\n";

    // Setup BGV CryptoContext
    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(p);
    parameters.SetMultiplicativeDepth(mdepth);
    parameters.SetRingDim(ring_dim);
    if (ring_dim < (1 << 16))
      parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
    else
      parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);
    parameters.SetSecretKeyDist(SecretKeyDist::SPARSE_TERNARY);

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

    // Generate query pattern with evenly distributed STAR wildcards (%)
    std::string pattern = generate_query_pattern_distributed(query_length, num_wildcards, '%', engine);
    std::cout << "  Query pattern: " << pattern << "\n";

    // Generate strings with ~50% match rate
    std::vector<std::string> values(num_slots);
    std::vector<bool> expected_matches(num_slots, false);
    std::uniform_int_distribution<int> match_dist(0, 1);
    uint64_t num_matches = 0;

    for (size_t i = 0; i < num_slots; i++) {
      bool should_match = (match_dist(engine) == 1);

      if (should_match) {
        // Generate matching string based on pattern
        values[i] = generate_matching_string(pattern, engine);
        expected_matches[i] = true;
        num_matches++;
      } else {
        // Generate non-matching string
        values[i] = generate_random_string(string_length, engine);
        // Ensure it doesn't accidentally match
        while (matches_pattern(values[i], pattern)) {
          values[i][0] = (values[i][0] == 'a') ? 'b' : 'a';
        }
        expected_matches[i] = false;
      }
    }

    double match_rate = (100.0 * num_matches) / num_slots;
    std::cout << "  Expected matches: " << num_matches << " (" << match_rate << "%)\n";

    // Print sample strings for debugging
    std::cout << "  Sample matching strings (first 3):\n";
    int match_count = 0;
    for (size_t i = 0; i < num_slots && match_count < 3; i++) {
      if (matches_pattern(values[i], pattern)) {
        std::cout << "    [" << i << "] \"" << values[i] << "\"\n";
        match_count++;
      }
    }
    std::cout << "  Sample non-matching strings (first 3):\n";
    int non_match_count = 0;
    for (size_t i = 0; i < num_slots && non_match_count < 3; i++) {
      if (!matches_pattern(values[i], pattern)) {
        std::cout << "    [" << i << "] \"" << values[i] << "\"\n";
        non_match_count++;
      }
    }

    // Encrypt strings
    StringPlaintext string_ptxt = ctx->MakePackedStringPlaintext(values, string_length);
    auto string_ctxt = ctx->Encrypt(string_ptxt);

    // Encode pattern
    auto encoded_pattern = ctx->EncodePattern(pattern);
    auto encrypted_pattern = ctx->EncryptPattern(encoded_pattern);

    // Measure LIKE operation time
    std::chrono::system_clock::time_point start, end;
    start = std::chrono::system_clock::now();

    auto like_result = ctx->EvalLike(string_ctxt, encrypted_pattern);

    end = std::chrono::system_clock::now();

    double total_time_sec = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000000.0;

    // Get remaining depth
    uint32_t current_level = like_result->GetLevel();
    uint32_t remaining_depth = mdepth - current_level;

    // Verify results by decrypting
    Plaintext result_ptxt;
    cc->Decrypt(keyPair.secretKey, like_result, &result_ptxt);
    result_ptxt->SetLength(num_slots);
    std::vector<int64_t> decrypted_results = result_ptxt->GetPackedValue();

    // Compare with expected results
    uint64_t correct_predictions = 0;
    uint64_t false_positives = 0;
    uint64_t false_negatives = 0;

    for (size_t i = 0; i < num_slots; i++) {
      bool actual_match = (decrypted_results[i] != 0);
      bool expected_match = expected_matches[i];

      if (actual_match == expected_match) {
        correct_predictions++;
      } else if (actual_match && !expected_match) {
        false_positives++;
      } else if (!actual_match && expected_match) {
        false_negatives++;
      }
    }

    double accuracy = (100.0 * correct_predictions) / num_slots;
    std::cout << "  Verification: " << correct_predictions << "/" << num_slots << " correct (" << accuracy << "%)\n";
    if (false_positives > 0 || false_negatives > 0) {
      std::cout << "    False positives: " << false_positives << ", False negatives: " << false_negatives << "\n";
    }

    // Calculate ciphertext size
    uint64_t ciphertext_size_bytes = calculate_ciphertext_size(string_ctxt);

    // Calculate performance metrics
    uint64_t num_strings = num_slots;
    double per_string_time_ms = (total_time_sec * 1000.0) / num_strings;
    double per_slot_size_kb = (ciphertext_size_bytes / 1024.0) / num_slots;
    double per_string_size_kb = per_slot_size_kb;

    std::cout << "  Total time: " << total_time_sec << " sec\n";
    std::cout << "  Per-string time: " << per_string_time_ms << " ms\n";
    std::cout << "  Ciphertext size: " << ciphertext_size_bytes << " bytes\n";
    std::cout << "  Used levels: " << current_level << " / " << mdepth << "\n";
    std::cout << "  Remaining depth: " << remaining_depth << "\n\n";

    // Write to CSV
    write_to_csv("benchmark_test4_varying_star_wildcards.csv",
                 test_id,
                 ring_dim,
                 radix,
                 string_length,
                 num_wildcards,
                 "STAR",
                 query_length,
                 total_time_sec,
                 per_string_time_ms,
                 ciphertext_size_bytes,
                 per_slot_size_kb,
                 per_string_size_kb,
                 num_slots,
                 num_matches,
                 match_rate,
                 mdepth,
                 current_level);

    release_crypto_context();
    test_id++;
  }

  std::cout << "\nTest 4 completed! Results written to benchmark_test4_varying_star_wildcards.csv\n";
}

int main()
{
  std::cout << "========================================\n";
  std::cout << "FHE Wildcard Matching Benchmark\n";
  std::cout << "========================================\n";

  // ============ BENCHMARK CONFIGURATION ============
  // Default RingDim (can be modified)
  uint64_t ring_dim = 1 << 7;

  // Depth configurations for each radix
  std::vector<RadixDepthConfig> radix_depth_configs = {
    // Radix = 2
    {
      2,  // radix
      {12, 15, 16, 16, 17, 17, 17, 18, 18, 18},  // test1_depths (varying string_length: 5-50)
      {18, 19, 19, 19, 19, 19, 19, 19, 18, 15},  // test2_depths (varying query_length: 5-50)
      {14, 14, 14, 14, 14, 14, 14, 14, 14, 14},  // test3_depths (varying ANY1 wildcards: 1-10)
      {15, 17, 20, 23, 25, 28, 32, 34, 37, 40},  // test4_depths (varying STAR wildcards: 1-10)
    },

    // Radix = 4 (MODIFY DEPTHS AS NEEDED)
    {
      4,  // radix
      {13, 16, 17, 17, 18, 18, 18, 19, 19, 19},  // test1_depths (varying string_length: 5-50)
      {19, 20, 20, 20, 20, 20, 20, 20, 19, 16},  // test2_depths (varying query_length: 5-50)
      {15, 15, 15, 15, 15, 15, 15, 15, 15, 15},  // test3_depths (varying ANY1 wildcards: 1-10)
      {17, 18, 22, 24, 27, 29, 33, 35, 38, 41},  // test4_depths (varying STAR wildcards: 1-10)
    },

    // Radix = 8 (MODIFY DEPTHS AS NEEDED)
    {
      8,  // radix
      {15, 18, 19, 19, 20, 20, 20, 21, 21, 21},  // test1_depths (varying string_length: 5-50)
      {21, 22, 22, 22, 22, 22, 22, 22, 21, 18},  // test2_depths (varying query_length: 5-50)
      {17, 17, 17, 17, 17, 17, 17, 17, 17, 17},  // test3_depths (varying ANY1 wildcards: 1-10)
      {19, 21, 24, 26, 29, 31, 35, 37, 40, 43},  // test4_depths (varying STAR wildcards: 1-10)
    },
  };
  // ============ END CONFIGURATION ============

  std::cout << "Using RingDim = " << ring_dim << " (" << ring_dim << " slots)\n\n";

  // Run tests for each radix configuration
  for (const auto& depth_config : radix_depth_configs) {
    std::cout << "\n========================================\n";
    std::cout << "Running tests with Radix = " << depth_config.radix << "\n";
    std::cout << "========================================\n";

    // Run Test 1: Varying string length (no wildcards)
    test1_varying_string_length(ring_dim, depth_config.radix, depth_config.test1_depths);

    // Run Test 2: Varying query length (no wildcards)
    test2_varying_query_length(ring_dim, depth_config.radix, depth_config.test2_depths);

    // Run Test 3: Varying ANY1 wildcards
    test3_varying_any1_wildcards(ring_dim, depth_config.radix, depth_config.test3_depths);

    // Run Test 4: Varying STAR wildcards
    test4_varying_star_wildcards(ring_dim, depth_config.radix, depth_config.test4_depths);
  }

  std::cout << "\n========================================\n";
  std::cout << "All tests completed!\n";
  std::cout << "Output files:\n";
  std::cout << "  - benchmark_test1_varying_string_length.csv\n";
  std::cout << "  - benchmark_test2_varying_query_length.csv\n";
  std::cout << "  - benchmark_test3_varying_any1_wildcards.csv\n";
  std::cout << "  - benchmark_test4_varying_star_wildcards.csv\n";
  std::cout << "========================================\n";

  return 0;
}
