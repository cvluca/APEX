#include <libapex.h>
#include <cryptocontextfactory.h>
#include <fstream>
#include <ctime>
#include <algorithm>
#include <iomanip>

using namespace lbcrypto;
using namespace apex;

// Release OpenFHE global state (context registry + cached keys) to free memory.
// Without this, each GenCryptoContext accumulates in a global static map.
static void release_crypto_context() {
  CryptoContextImpl<DCRTPoly>::ClearEvalMultKeys();
  CryptoContextImpl<DCRTPoly>::ClearEvalAutomorphismKeys();
  CryptoContextFactory<DCRTPoly>::ReleaseAllContexts();
}

struct QueryResult {
  std::string query_name;
  uint32_t radix;
  double filtering_time;
  double aggregation_time;
  double total_time;
  double amortized_total;  // ms
  uint32_t depth_consumed;
  // Q1 breakdown
  double q1_exact_match = 0;
  double q1_prefix_match = 0;
  double q1_substring_match = 0;
  double q1_rahc = 0;
  double q1_and_ops = 0;
  // Q2 breakdown
  double q2_homlike = 0;
  double q2_rahc = 0;          // shipdate + sign
  double q2_multiplication = 0;
  double q2_subtraction = 0;
  double q2_carry_propagation = 0;  // total carry
  double q2_and_ops = 0;
  // Q2 carry detail (eager vs lazy comparison)
  double carry_after_mult = 0;
  double carry_before_sign = 0;
};

// Helper function to write results to CSV
void write_to_csv(const std::string& query_name, uint64_t ring_dim, uint64_t p, uint32_t radix,
                  uint32_t seed, double brand_time, double type_time, double size_time,
                  double comment_time, double combine_time, double filtering_time, double aggregation_time)
{
  const std::string filename = "hybrid_queries_q1_results.csv";
  bool file_exists = false;

  std::ifstream check_file(filename);
  if (check_file.good()) {
    file_exists = true;
  }
  check_file.close();

  std::ofstream csv_file(filename, std::ios::app);

  if (!file_exists) {
    csv_file << "query_name,ring_dim,p,radix,segment_count,seed,"
             << "brand_exact_match_ms,type_prefix_match_ms,size_comparison_ms,comment_substring_match_ms,combine_filters_ms,"
             << "filtering_time_ms,aggregation_time_ms,total_time_ms,"
             << "amortized_filtering_ms,amortized_aggregation_ms,amortized_total_ms,timestamp\n";
  }

  std::time_t now = std::time(nullptr);
  char timestamp[100];
  std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

  double total_time = filtering_time + aggregation_time;
  uint32_t segment_count = (radix > 0) ? (16 / radix) : 0;

  double amortized_filtering = filtering_time / ring_dim;
  double amortized_aggregation = aggregation_time / ring_dim;
  double amortized_total = total_time / ring_dim;

  csv_file << query_name << ","
           << ring_dim << ","
           << p << ","
           << radix << ","
           << segment_count << ","
           << seed << ","
           << brand_time << ","
           << type_time << ","
           << size_time << ","
           << comment_time << ","
           << combine_time << ","
           << filtering_time << ","
           << aggregation_time << ","
           << total_time << ","
           << std::fixed << std::setprecision(3)
           << amortized_filtering << ","
           << amortized_aggregation << ","
           << amortized_total << ","
           << timestamp << "\n";

  csv_file.close();
  std::cout << "Results written to " << filename << std::endl;
}

// Helper function to write Q2 results to CSV with detailed arithmetic breakdown
void write_q2_csv(const std::string& query_name, const std::string& mode,
                  uint64_t ring_dim, uint64_t p, uint32_t radix,
                  uint32_t seed, double type_time, double shipdate_time,
                  double eval_sub1_time,
                  double mult_time, double carry_after_mult_time,
                  double eval_sub2_time,
                  double reduce_time, double carry_time, double sign_time,
                  double arithmetic_time, double combine_time,
                  double filtering_time, double aggregation_time)
{
  const std::string filename = "hybrid_queries_q2_results.csv";
  bool file_exists = false;

  std::ifstream check_file(filename);
  if (check_file.good()) {
    file_exists = true;
  }
  check_file.close();

  std::ofstream csv_file(filename, std::ios::app);

  if (!file_exists) {
    csv_file << "query_name,mode,ring_dim,p,radix,segment_count,seed,"
             << "type_prefix_match_ms,shipdate_range_ms,"
             << "eval_sub1_ms,mult_ms,carry_after_mult_ms,eval_sub2_ms,"
             << "reduce_ms,carry_ms,sign_ms,"
             << "arithmetic_total_ms,combine_filters_ms,"
             << "filtering_time_ms,aggregation_time_ms,total_time_ms,"
             << "amortized_filtering_ms,amortized_aggregation_ms,amortized_total_ms,timestamp\n";
  }

  std::time_t now = std::time(nullptr);
  char timestamp[100];
  std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

  double total_time = filtering_time + aggregation_time;
  uint32_t segment_count = (radix > 0) ? (24 / radix) : 0;

  // Calculate amortized times (in milliseconds per row)
  double amortized_filtering = filtering_time / ring_dim;
  double amortized_aggregation = aggregation_time / ring_dim;
  double amortized_total = total_time / ring_dim;

  csv_file << query_name << ","
           << mode << ","
           << ring_dim << ","
           << p << ","
           << radix << ","
           << segment_count << ","
           << seed << ","
           << type_time << ","
           << shipdate_time << ","
           << eval_sub1_time << ","
           << mult_time << ","
           << carry_after_mult_time << ","
           << eval_sub2_time << ","
           << reduce_time << ","
           << carry_time << ","
           << sign_time << ","
           << arithmetic_time << ","
           << combine_time << ","
           << filtering_time << ","
           << aggregation_time << ","
           << total_time << ","
           << std::fixed << std::setprecision(3)
           << amortized_filtering << ","
           << amortized_aggregation << ","
           << amortized_total << ","
           << timestamp << "\n";

  csv_file.close();
  std::cout << "Results written to " << filename << std::endl;
}

/*
 * Hybrid Query 1 (Based on TPC-H Q16)
 *
 * This query demonstrates a realistic hybrid workload combining:
 * - String exact matching (p_brand <> 'Brand#45')
 * - String prefix matching (p_type not like 'ANODIZED%')
 * - Integer IN operation (p_size in (47, 15, 37, 30, 46, 16, 18, 6))
 * - String substring matching (s_comment not like '%Customer%')
 *
 * SQL equivalent (simplified from TPC-H Q16):
 * SELECT COUNT(*)
 * FROM partsupp_part_supplier_joined
 * WHERE p_brand <> 'Brand#45'
 *   AND p_type NOT LIKE 'ANODIZED%'
 *   AND p_size IN (47, 15, 37, 30, 46, 16, 18, 6)
 *   AND s_comment NOT LIKE '%Customer%';
 */
QueryResult run_hybrid_q1(uint64_t RingDim, uint64_t p, uint32_t radix, uint32_t mdepth)
{
  const usint SLOT_COUNT = RingDim;

  std::cout << "\n========================================\n";
  std::cout << "Running Hybrid Query 1 (TPC-H Q16 variant)\n";
  std::cout << "========================================\n";
  std::cout << "Record number: " << SLOT_COUNT
            << ", p: " << p
            << ", radix: " << radix
            << ", depth: " << mdepth << std::endl;

  //---------------------------------------------
  // Preparation works
  //---------------------------------------------
  CCParams<CryptoContextBGVRNS> parameters;
  SecretKeyDist secretKeyDist = SPARSE_TERNARY;
  parameters.SetSecretKeyDist(secretKeyDist);
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
  cc->EvalMultKeyGen(keyPair.secretKey);

  ApexParams fparams;
  fparams.SetRadix(radix);
  fparams.SetSegmentCount(8 / radix);
  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);
  ctx->GenSumKey(keyPair.secretKey);

  //---------------------------------------------
  // Generate random inputs
  // ---------------------------------------------
  std::random_device seed_gen;
  auto seed = seed_gen();
  std::cout << "Seed: " << seed << std::endl;
  std::default_random_engine engine(seed);

  const uint32_t brand_length = 16;
  const uint32_t type_length = 16;
  const uint32_t comment_length = 16;

  std::uniform_int_distribution<int> char_dist(0, 25);
  auto gen_random_string = [&](size_t len) -> std::string {
    std::string str(len, ' ');
    for (size_t i = 0; i < len; i++) {
      str[i] = 'a' + char_dist(engine);
    }
    return str;
  };

  std::vector<std::string> p_brand(SLOT_COUNT);
  std::vector<std::string> p_type(SLOT_COUNT);
  std::vector<std::string> s_comment(SLOT_COUNT);
  std::vector<uint64_t> p_size(SLOT_COUNT);

  std::uniform_int_distribution<int> brand_dist(0, 1);  // 50% Brand#45
  std::uniform_int_distribution<int> type_dist(0, 1);   // 50% starts with "ANODIZED"
  std::uniform_int_distribution<int> comment_dist(0, 1); // 50% contains "Customer"
  std::vector<uint64_t> valid_sizes = {47, 15, 37, 30, 46, 16, 18, 6};
  std::uniform_int_distribution<int> size_dist(0, 7);
  std::uniform_int_distribution<uint64_t> other_size_dist(1, 100);

  for (size_t i = 0; i < SLOT_COUNT; i++) {
    // Generate p_brand: "Brand#45" or random brand
    if (brand_dist(engine) == 0) {
      p_brand[i] = "Brand#45";  // Target brand
    } else {
      p_brand[i] = gen_random_string(brand_length);
    }

    // Generate p_type: starts with "ANODIZED" or random
    if (type_dist(engine) == 0) {
      std::string prefix = "ANODIZED";  // "ANODIZED" prefix
      p_type[i] = prefix + gen_random_string(type_length - prefix.length());
    } else {
      p_type[i] = gen_random_string(type_length);
    }

    // Generate s_comment: contains "Customer" or random
    if (comment_dist(engine) == 0) {
      std::string word = "Customer";

      if (word.length() < comment_length) {
        // Calculate remaining space for prefix and suffix
        size_t remaining = comment_length - word.length();
        size_t prefix_len = std::uniform_int_distribution<size_t>(0, remaining)(engine);
        size_t suffix_len = remaining - prefix_len;

        s_comment[i] = gen_random_string(prefix_len) + word +
                       gen_random_string(suffix_len);
      } else {
        s_comment[i] = gen_random_string(comment_length);
      }
    } else {
      s_comment[i] = gen_random_string(comment_length);
    }

    // Generate p_size: in valid set or random
    if (brand_dist(engine) == 0) {
      p_size[i] = valid_sizes[size_dist(engine)];
    } else {
      // Make sure it's not in valid set
      do {
        p_size[i] = other_size_dist(engine);
      } while (std::find(valid_sizes.begin(), valid_sizes.end(), p_size[i]) != valid_sizes.end());
    }
  }

  // Create plaintexts for strings
  auto p_brand_ptxt = ctx->MakePackedStringPlaintext(p_brand, brand_length);
  auto p_type_ptxt = ctx->MakePackedStringPlaintext(p_type, type_length);
  auto s_comment_ptxt = ctx->MakePackedStringPlaintext(s_comment, comment_length);

  // Create plaintexts for integers
  auto p_size_ptxt = ctx->MakePackedRadixPlaintext(p_size, fparams);

  // Create predicate plaintexts for p_size
  std::vector<RadixPlaintext> size_predicates_ptxt;
  for (auto size : valid_sizes) {
    std::vector<uint64_t> predicate_vec(SLOT_COUNT, size);
    size_predicates_ptxt.push_back(ctx->MakePackedRadixPlaintext(predicate_vec, fparams));
  }

  // Encrypt data
  auto p_brand_ctxt = ctx->Encrypt(p_brand_ptxt);
  auto p_type_ctxt = ctx->Encrypt(p_type_ptxt);
  auto s_comment_ctxt = ctx->Encrypt(s_comment_ptxt);
  auto p_size_ctxt = ctx->Encrypt(p_size_ptxt);

  std::vector<RadixCiphertext> size_predicates_ctxt;
  for (const auto& pred : size_predicates_ptxt) {
    size_predicates_ctxt.push_back(ctx->Encrypt(pred));
  }

  // Create patterns for string matching
  std::string brand_pattern = "Brand#45";      // Exact match
  std::string type_pattern = "ANODIZED%";      // Prefix match
  std::string comment_pattern = "%Customer%";  // Substring match with wildcard

  auto brand_encoded = ctx->EncodePattern(brand_pattern);
  auto brand_encrypted = ctx->EncryptPattern(brand_encoded);

  auto type_encoded = ctx->EncodePattern(type_pattern);
  auto type_encrypted = ctx->EncryptPattern(type_encoded);

  auto comment_encoded = ctx->EncodePattern(comment_pattern);
  auto comment_encrypted = ctx->EncryptPattern(comment_encoded);

  auto one_ptxt = cc->MakePackedPlaintext(std::vector<int64_t>(SLOT_COUNT, 1));

  //---------------------------------------------
  // Filtering with time breakdown
  // ---------------------------------------------
  double filtering_time = 0, aggregation_time = 0;
  double brand_time = 0, type_time = 0, size_time = 0, comment_time = 0, combine_time = 0;
  std::chrono::system_clock::time_point start, end;

  // 1. p_brand <> 'Brand#45' - Exact match
  start = std::chrono::system_clock::now();
  auto brand_match = ctx->EvalLike(p_brand_ctxt, brand_encrypted);
  auto brand_not_match = cc->EvalNegate(brand_match);
  brand_not_match = cc->EvalAdd(brand_not_match, one_ptxt);
  end = std::chrono::system_clock::now();
  brand_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

  // 2. p_type not like 'ANODIZED%' - Prefix match
  start = std::chrono::system_clock::now();
  auto type_match = ctx->EvalLike(p_type_ctxt, type_encrypted);
  auto type_not_match = cc->EvalNegate(type_match);
  type_not_match = cc->EvalAdd(type_not_match, one_ptxt);
  end = std::chrono::system_clock::now();
  type_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

  // 3. p_size in (47, 15, 37, 30, 46, 16, 18, 6) - Integer comparison
  start = std::chrono::system_clock::now();
  std::vector<lbcrypto::Ciphertext<DCRTPoly>> size_matches;
  for (const auto& pred_ctxt : size_predicates_ctxt) {
    size_matches.push_back(ctx->EvalComp(p_size_ctxt, pred_ctxt, CompType::EQ));
  }
  // OR all size matches together
  auto size_match = size_matches[0];
  for (size_t i = 1; i < size_matches.size(); i++) {
    size_match = cc->EvalAdd(size_match, size_matches[i]);
  }
  end = std::chrono::system_clock::now();
  size_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

  // 4. s_comment not like '%Customer%' - Substring matching
  start = std::chrono::system_clock::now();
  auto comment_match = ctx->EvalLike(s_comment_ctxt, comment_encrypted);
  auto comment_not_match = cc->EvalNegate(comment_match);
  comment_not_match = cc->EvalAdd(comment_not_match, one_ptxt);
  end = std::chrono::system_clock::now();
  comment_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

  // 5. Combine all filters with AND operations
  start = std::chrono::system_clock::now();
  auto filter_result = cc->EvalMult(brand_not_match, type_not_match);
  filter_result = cc->EvalMult(filter_result, size_match);
  filter_result = cc->EvalMult(filter_result, comment_not_match);
  end = std::chrono::system_clock::now();
  combine_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

  filtering_time = brand_time + type_time + size_time + comment_time + combine_time;

  std::cout << "\n********** Filtering Time Breakdown **********\n";
  std::cout << std::setw(45) << "Operation" << " | " << std::setw(12) << "Time (ms)" << "\n";
  std::cout << std::string(60, '-') << "\n";
  std::cout << std::setw(45) << "1. Brand exact match (NOT LIKE)" << " | " << std::setw(12) << brand_time << "\n";
  std::cout << std::setw(45) << "2. Type prefix match (NOT LIKE)" << " | " << std::setw(12) << type_time << "\n";
  std::cout << std::setw(45) << "3. Size IN comparison (8 values)" << " | " << std::setw(12) << size_time << "\n";
  std::cout << std::setw(45) << "4. Comment substring match (NOT LIKE)" << " | " << std::setw(12) << comment_time << "\n";
  std::cout << std::setw(45) << "5. Combine filters (3x AND)" << " | " << std::setw(12) << combine_time << "\n";
  std::cout << std::string(60, '-') << "\n";
  std::cout << std::setw(45) << "Total filtering time" << " | " << std::setw(12) << filtering_time << "\n";

  //---------------------------------------------
  // Decrypt intermediate filter results
  // ---------------------------------------------
  std::cout << "\n********** Decrypting intermediate filter results **********\n";

  Plaintext brand_not_match_ptxt, type_not_match_ptxt, size_match_ptxt, comment_not_match_ptxt;
  cc->Decrypt(keyPair.secretKey, brand_not_match, &brand_not_match_ptxt);
  cc->Decrypt(keyPair.secretKey, type_not_match, &type_not_match_ptxt);
  cc->Decrypt(keyPair.secretKey, size_match, &size_match_ptxt);
  cc->Decrypt(keyPair.secretKey, comment_not_match, &comment_not_match_ptxt);

  brand_not_match_ptxt->SetLength(SLOT_COUNT);
  type_not_match_ptxt->SetLength(SLOT_COUNT);
  size_match_ptxt->SetLength(SLOT_COUNT);
  comment_not_match_ptxt->SetLength(SLOT_COUNT);

  auto brand_dec = brand_not_match_ptxt->GetPackedValue();
  auto type_dec = type_not_match_ptxt->GetPackedValue();
  auto size_dec = size_match_ptxt->GetPackedValue();
  auto comment_dec = comment_not_match_ptxt->GetPackedValue();

  // Calculate statistics for each encrypted condition
  uint64_t enc_brand_pass = 0, enc_type_pass = 0, enc_size_pass = 0, enc_comment_pass = 0;
  for (size_t i = 0; i < SLOT_COUNT; i++) {
    if (brand_dec[i] != 0 && brand_dec[i] == 1) enc_brand_pass++;
    if (type_dec[i] != 0 && type_dec[i] == 1) enc_type_pass++;
    if (size_dec[i] != 0 && size_dec[i] == 1) enc_size_pass++;
    if (comment_dec[i] != 0 && comment_dec[i] == 1) enc_comment_pass++;
  }

  // Calculate expected statistics
  uint64_t exp_brand_pass = 0, exp_type_pass = 0, exp_size_pass = 0, exp_comment_pass = 0;
  for (size_t i = 0; i < SLOT_COUNT; i++) {
    if (p_brand[i] != "Brand#45") exp_brand_pass++;
    if (p_type[i].substr(0, 8) != "ANODIZED") exp_type_pass++;
    if (std::find(valid_sizes.begin(), valid_sizes.end(), p_size[i]) != valid_sizes.end()) exp_size_pass++;

    // Check if comment matches pattern %Customer%
    bool has_pattern = (s_comment[i].find("Customer") != std::string::npos);
    if (!has_pattern) exp_comment_pass++;
  }

  std::cout << std::setw(40) << "Filter Condition" << " | "
            << std::setw(12) << "Expected" << " | "
            << std::setw(12) << "Encrypted" << " | "
            << std::setw(8) << "Match" << "\n";
  std::cout << std::string(80, '-') << "\n";

  std::cout << std::setw(40) << "p_brand <> 'Brand#45'" << " | "
            << std::setw(12) << exp_brand_pass << " | "
            << std::setw(12) << enc_brand_pass << " | "
            << std::setw(8) << (exp_brand_pass == enc_brand_pass ? "✓" : "✗") << "\n";

  std::cout << std::setw(40) << "p_type not like 'ANODIZED%'" << " | "
            << std::setw(12) << exp_type_pass << " | "
            << std::setw(12) << enc_type_pass << " | "
            << std::setw(8) << (exp_type_pass == enc_type_pass ? "✓" : "✗") << "\n";

  std::cout << std::setw(40) << "p_size in (47,15,37,30,46,16,18,6)" << " | "
            << std::setw(12) << exp_size_pass << " | "
            << std::setw(12) << enc_size_pass << " | "
            << std::setw(8) << (exp_size_pass == enc_size_pass ? "✓" : "✗") << "\n";

  std::cout << std::setw(40) << "s_comment not like '%Customer%'" << " | "
            << std::setw(12) << exp_comment_pass << " | "
            << std::setw(12) << enc_comment_pass << " | "
            << std::setw(8) << (exp_comment_pass == enc_comment_pass ? "✓" : "✗") << "\n";

  //---------------------------------------------
  // Aggregation - Count matches
  // ---------------------------------------------
  start = std::chrono::system_clock::now();
  ctx->EvalSumInPlace(filter_result);
  end = std::chrono::system_clock::now();

  aggregation_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
  std::cout << "\naggregation time = " << aggregation_time << " ms\n";

  // Calculate and display amortized times
  double total_query_time = filtering_time + aggregation_time;
  double amortized_filtering = filtering_time / SLOT_COUNT;
  double amortized_aggregation = aggregation_time / SLOT_COUNT;
  double amortized_total = total_query_time / SLOT_COUNT;

  std::cout << "\n********** Amortized Time (per row) **********\n";
  std::cout << std::setw(45) << "Filtering time per row" << " | " << std::fixed << std::setprecision(3) << std::setw(12) << amortized_filtering << " ms\n";
  std::cout << std::setw(45) << "Aggregation time per row" << " | " << std::fixed << std::setprecision(3) << std::setw(12) << amortized_aggregation << " ms\n";
  std::cout << std::setw(45) << "Total time per row" << " | " << std::fixed << std::setprecision(3) << std::setw(12) << amortized_total << " ms\n";

  // Check depth consumption
  uint32_t level_consumed = filter_result->GetLevel();
  std::cout << "Depth consumed: " << level_consumed << ", Remaining depth: " << (mdepth - level_consumed) << "\n";

  // Decrypt final aggregated result
  Plaintext result_ptxt;
  cc->Decrypt(keyPair.secretKey, filter_result, &result_ptxt);
  result_ptxt->SetLength(1);
  auto result_count = result_ptxt->GetPackedValue()[0];

  // Calculate expected final result
  uint64_t expected_count = 0;
  for (size_t i = 0; i < SLOT_COUNT; i++) {
    bool brand_ok = (p_brand[i] != "Brand#45");
    bool type_ok = (p_type[i].substr(0, 8) != "ANODIZED");
    bool size_ok = (std::find(valid_sizes.begin(), valid_sizes.end(), p_size[i]) != valid_sizes.end());

    // Check if comment matches pattern %Customer%
    bool has_pattern = (s_comment[i].find("Customer") != std::string::npos);
    bool comment_ok = !has_pattern;

    if (brand_ok && type_ok && size_ok && comment_ok) {
      expected_count++;
    }
  }

  std::cout << "\n********** Final Query Result **********\n";
  std::cout << "Query Evaluation Time: " << filtering_time + aggregation_time << " ms" << std::endl;
  std::cout << "Total records matching ALL conditions:\n";
  std::cout << "  Expected count:  " << expected_count << "\n";
  std::cout << "  Encrypted count: " << result_count << "\n";

  if (result_count == expected_count) {
    std::cout << "\n✓ Result is CORRECT!\n";
  } else {
    std::cout << "\n✗ Result is INCORRECT!\n";
    std::cout << "  Difference: " << (int64_t)result_count - (int64_t)expected_count << "\n";
  }

  // Write results to CSV
  write_to_csv("HybridQ1", RingDim, p, radix, seed,
               brand_time, type_time, size_time, comment_time, combine_time,
               filtering_time, aggregation_time);

  QueryResult result;
  result.query_name = "Q1";
  result.radix = radix;
  result.filtering_time = filtering_time;
  result.aggregation_time = aggregation_time;
  result.total_time = total_query_time;
  result.amortized_total = amortized_total;
  result.depth_consumed = level_consumed;
  result.q1_exact_match = brand_time;
  result.q1_prefix_match = type_time;
  result.q1_substring_match = comment_time;
  result.q1_rahc = size_time;
  result.q1_and_ops = combine_time;
  release_crypto_context();
  return result;
}

/*
 * Hybrid Query 2 (Based on TPC-H Q14)
 *
 * This query demonstrates a hybrid workload combining:
 * - String prefix matching (p_type like 'PROMO%')
 * - Integer range comparison (l_shipdate > 9999 AND l_shipdate < 10030)
 * - Arithmetic operation and comparison (l_extendedprice * (1 - l_discount) < 50)
 *
 * SQL equivalent (simplified from TPC-H Q14):
 * SELECT COUNT(*)
 * FROM lineitem_part_joined
 * WHERE p_type LIKE 'PROMO%'
 *   AND l_shipdate > 9999
 *   AND l_shipdate < 10030
 *   AND l_extendedprice * (1 - l_discount) < 50;
 *
 * Business meaning: Count promotional items within date range where
 * discounted price is less than $50
 */
QueryResult run_hybrid_q2(uint64_t RingDim, uint64_t p, uint32_t radix, uint32_t mdepth, bool eager_carry = false)
{
  const usint SLOT_COUNT = RingDim;

  std::cout << "\n========================================\n";
  std::cout << "Running Hybrid Query 2 (TPC-H Q14 variant) [" << (eager_carry ? "eager" : "lazy") << " carry]\n";
  std::cout << "========================================\n";
  std::cout << "Record number: " << SLOT_COUNT
            << ", p: " << p
            << ", radix: " << radix
            << ", depth: " << mdepth << std::endl;

  //---------------------------------------------
  // Preparation works
  //---------------------------------------------
  CCParams<CryptoContextBGVRNS> parameters;
  SecretKeyDist secretKeyDist = SPARSE_TERNARY;
  parameters.SetSecretKeyDist(secretKeyDist);
  parameters.SetPlaintextModulus(p);
  parameters.SetMultiplicativeDepth(mdepth);
  parameters.SetRingDim(RingDim);
  if (RingDim <= (1 << 16))
    parameters.SetSecurityLevel(SecurityLevel::HEStd_NotSet);
  else
    parameters.SetSecurityLevel(SecurityLevel::HEStd_128_classic);

  CryptoContext<DCRTPoly> cc = GenCryptoContext(parameters);
  cc->Enable(PKE);
  cc->Enable(KEYSWITCH);
  cc->Enable(LEVELEDSHE);
  cc->Enable(ADVANCEDSHE);

  KeyPair<DCRTPoly> keyPair = cc->KeyGen();
  cc->EvalMultKeyGen(keyPair.secretKey);

  ApexParams fparams;
  fparams.SetRadix(radix);
  fparams.SetSegmentCount(16 / radix);
  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);
  ctx->GenSumKey(keyPair.secretKey);

  //---------------------------------------------
  // Generate random inputs
  // ---------------------------------------------
  std::random_device seed_gen;
  auto seed = seed_gen();
  std::cout << "Seed: " << seed << std::endl;
  std::default_random_engine engine(seed);

  const uint32_t type_length = 16;
  std::uniform_int_distribution<int> char_dist(0, 25);
  auto gen_random_string = [&](size_t len) -> std::string {
    std::string str(len, ' ');
    for (size_t i = 0; i < len; i++) {
      str[i] = 'a' + char_dist(engine);
    }
    return str;
  };

  std::vector<std::string> p_type(SLOT_COUNT);
  std::vector<uint64_t> l_shipdate(SLOT_COUNT);
  std::vector<double> l_extendedprice(SLOT_COUNT);
  std::vector<double> l_discount(SLOT_COUNT);

  std::uniform_int_distribution<int> type_dist(0, 1);           // 50% starts with "PROMO"
  std::uniform_int_distribution<uint64_t> shipdate_dist(9990, 10040);  // Around the range
  std::uniform_int_distribution<uint64_t> price_dist(40, 60);   // Price range 40-60 (representing $40-$60)
  std::uniform_int_distribution<uint64_t> discount_dist(0, 20); // Discount 0-20%

  for (size_t i = 0; i < SLOT_COUNT; i++) {
    // Generate p_type: starts with "PROMO" or random
    if (type_dist(engine) == 0) {
      std::string prefix = "PROMO";
      p_type[i] = prefix + gen_random_string(type_length - prefix.length());
    } else {
      p_type[i] = gen_random_string(type_length);
    }

    l_shipdate[i] = shipdate_dist(engine);
    l_extendedprice[i] = (double)price_dist(engine);
    l_discount[i] = discount_dist(engine)/ 100.0;
  }

  // Create predicate plaintexts
  std::vector<uint64_t> shipdate_lower(SLOT_COUNT, 9999);   // Use > 9999 instead of >= 10000
  std::vector<uint64_t> shipdate_upper(SLOT_COUNT, 10030);
  std::vector<double> price_threshold(SLOT_COUNT, 50.0);  // Representing $50
  std::vector<double> discount_scale(SLOT_COUNT, 1.0);  // 100%

  // Create plaintexts for strings
  auto p_type_ptxt = ctx->MakePackedStringPlaintext(p_type, type_length);

  // Create plaintexts for integers
  auto l_shipdate_ptxt = ctx->MakePackedRadixPlaintext(l_shipdate, fparams);
  auto shipdate_lower_ptxt = ctx->MakePackedRadixPlaintext(shipdate_lower, fparams);
  auto shipdate_upper_ptxt = ctx->MakePackedRadixPlaintext(shipdate_upper, fparams);

  fparams.SetSegmentCount(8 / radix);
  auto l_extendedprice_ptxt = ctx->MakePackedRadixPlaintext(l_extendedprice, fparams);

  fparams.SetSegmentCount(24 / radix);
  fparams.SetFracSegmentCount(16 / radix);
  auto discount_scale_ptxt = ctx->MakePackedRadixPlaintext(discount_scale, fparams);
  auto l_discount_ptxt = ctx->MakePackedRadixPlaintext(l_discount, fparams);

  fparams.SetSegmentCount(32 / radix - 1);
  auto price_threshold_ptxt = ctx->MakePackedRadixPlaintext(price_threshold, fparams);

  // Encrypt data
  auto p_type_ctxt = ctx->Encrypt(p_type_ptxt);
  auto l_shipdate_ctxt = ctx->Encrypt(l_shipdate_ptxt);
  auto l_extendedprice_ctxt = ctx->Encrypt(l_extendedprice_ptxt);
  auto l_discount_ctxt = ctx->Encrypt(l_discount_ptxt);
  auto shipdate_lower_ctxt = ctx->Encrypt(shipdate_lower_ptxt);
  auto shipdate_upper_ctxt = ctx->Encrypt(shipdate_upper_ptxt);
  auto price_threshold_ctxt = ctx->Encrypt(price_threshold_ptxt);
  auto discount_scale_ctxt = ctx->Encrypt(discount_scale_ptxt);

  // Create patterns for string matching
  std::string type_pattern = "PROMO%";  // Prefix match

  auto type_encoded = ctx->EncodePattern(type_pattern);
  auto type_encrypted = ctx->EncryptPattern(type_encoded);

  auto one_ptxt = cc->MakePackedPlaintext(std::vector<int64_t>(SLOT_COUNT, 1));

  //---------------------------------------------
  // Filtering with time breakdown
  // ---------------------------------------------
  double filtering_time = 0, aggregation_time = 0;
  double type_time = 0, shipdate_time = 0, arithmetic_time = 0, combine_time = 0;
  std::chrono::system_clock::time_point start, end;

  // 1. p_type like 'PROMO%' - Prefix match
  start = std::chrono::system_clock::now();
  auto type_match = ctx->EvalLike(p_type_ctxt, type_encrypted);
  end = std::chrono::system_clock::now();
  type_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

  // 2. l_shipdate > 9999 AND l_shipdate < 10030 - Integer range comparison
  start = std::chrono::system_clock::now();
  auto shipdate_gt = ctx->EvalComp(l_shipdate_ctxt, shipdate_lower_ctxt, CompType::GT);
  auto shipdate_lt = ctx->EvalComp(l_shipdate_ctxt, shipdate_upper_ctxt, CompType::LT);
  auto shipdate_match = cc->EvalMult(shipdate_gt, shipdate_lt);
  end = std::chrono::system_clock::now();
  shipdate_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

  fparams.SetSegmentCount(24 / radix);
  // 3. l_extendedprice * (1 - l_discount) < 50 - Arithmetic and comparison
  // Detailed timing for all arithmetic operations
  std::chrono::system_clock::time_point eval_sub1_start, eval_sub1_end;
  std::chrono::system_clock::time_point mult_start, mult_end;
  std::chrono::system_clock::time_point eval_sub2_start, eval_sub2_end;
  std::chrono::system_clock::time_point reduce_start, reduce_end;
  std::chrono::system_clock::time_point carry_start, carry_end;
  std::chrono::system_clock::time_point sign_start, sign_end;
  double eval_sub1_time = 0, mult_time = 0, carry_after_mult_time = 0, eval_sub2_time = 0;
  double reduce_time = 0, carry_time = 0, sign_time = 0;

  // Calculate (1 - discount)
  eval_sub1_start = std::chrono::system_clock::now();
  auto discount_complement = ctx->EvalSub(discount_scale_ctxt, l_discount_ctxt);
  eval_sub1_end = std::chrono::system_clock::now();
  eval_sub1_time = std::chrono::duration_cast<std::chrono::microseconds>(eval_sub1_end - eval_sub1_start).count() / 1000.0;

  // Calculate l_extendedprice * (1 - l_discount)
  mult_start = std::chrono::system_clock::now();
  auto discounted_price = ctx->EvalMult(l_extendedprice_ctxt, discount_complement);
  mult_end = std::chrono::system_clock::now();
  mult_time = std::chrono::duration_cast<std::chrono::microseconds>(mult_end - mult_start).count() / 1000.0;

  if (eager_carry) {
    auto carry2_start = std::chrono::system_clock::now();
    ctx->EvalBalanceInPlace(discounted_price);
    ctx->EvalCarryInPlace(discounted_price, true);
    auto carry2_end = std::chrono::system_clock::now();
    carry_after_mult_time = std::chrono::duration_cast<std::chrono::microseconds>(carry2_end - carry2_start).count() / 1000.0;
  }

  // Compare: discounted_price < 50 (equivalent to threshold - discounted_price > 0)
  eval_sub2_start = std::chrono::system_clock::now();
  auto price_cmp = ctx->EvalSub(price_threshold_ctxt, discounted_price);
  eval_sub2_end = std::chrono::system_clock::now();
  eval_sub2_time = std::chrono::duration_cast<std::chrono::microseconds>(eval_sub2_end - eval_sub2_start).count() / 1000.0;

  if (radix < 8) {
    reduce_start = std::chrono::system_clock::now();
    ctx->ReduceSegmentInPlace(price_cmp, fparams);
    reduce_end = std::chrono::system_clock::now();
    reduce_time = std::chrono::duration_cast<std::chrono::microseconds>(reduce_end - reduce_start).count() / 1000.0;
  }

  carry_start = std::chrono::system_clock::now();
  ctx->EvalBalanceInPlace(price_cmp);
  ctx->EvalCarryInPlace(price_cmp, true);
  carry_end = std::chrono::system_clock::now();
  carry_time = std::chrono::duration_cast<std::chrono::microseconds>(carry_end - carry_start).count() / 1000.0;

  sign_start = std::chrono::system_clock::now();
  auto price_match = ctx->EvalSign(price_cmp);
  sign_end = std::chrono::system_clock::now();
  sign_time = std::chrono::duration_cast<std::chrono::microseconds>(sign_end - sign_start).count() / 1000.0;

  // Total arithmetic time is sum of all operations
  arithmetic_time = eval_sub1_time + mult_time + carry_after_mult_time + eval_sub2_time + reduce_time + carry_time + sign_time;

  // 4. Combine all filters with AND operations
  start = std::chrono::system_clock::now();
  auto filter_result = cc->EvalMult(type_match, shipdate_match);
  filter_result = cc->EvalMult(filter_result, price_match);
  end = std::chrono::system_clock::now();
  combine_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;

  filtering_time = type_time + shipdate_time + arithmetic_time + combine_time;

  std::cout << "\n********** Filtering Time Breakdown **********\n";
  std::cout << std::setw(50) << "Operation" << " | " << std::setw(12) << "Time (ms)" << "\n";
  std::cout << std::string(65, '-') << "\n";
  std::cout << std::setw(50) << "1. Type prefix match (LIKE 'PROMO%')" << " | " << std::setw(12) << type_time << "\n";
  std::cout << std::setw(50) << "2. Shipdate range comparison (> AND <)" << " | " << std::setw(12) << shipdate_time << "\n";
  std::cout << std::setw(50) << "3. Price arithmetic & comparison" << " | " << std::setw(12) << arithmetic_time << "\n";
  std::cout << std::setw(50) << "   - EvalSub (1 - discount)" << " | " << std::setw(12) << eval_sub1_time << "\n";
  std::cout << std::setw(50) << "   - EvalMult (price * (1-discount))" << " | " << std::setw(12) << mult_time << "\n";
  if (eager_carry) {
    std::cout << std::setw(50) << "   - Carry after EvalMult" << " | " << std::setw(12) << carry_after_mult_time << "\n";
  }
  std::cout << std::setw(50) << "   - EvalSub (50 - discounted_price)" << " | " << std::setw(12) << eval_sub2_time << "\n";
  if (radix < 8) {
    std::cout << std::setw(50) << "   - ReduceSegmentInPlace" << " | " << std::setw(12) << reduce_time << "\n";
  }
  std::cout << std::setw(50) << "   - Carry before EvalSign" << " | " << std::setw(12) << carry_time << "\n";
  std::cout << std::setw(50) << "   - EvalSign" << " | " << std::setw(12) << sign_time << "\n";
  std::cout << std::setw(50) << "4. Combine filters (2x AND)" << " | " << std::setw(12) << combine_time << "\n";
  std::cout << std::string(65, '-') << "\n";
  std::cout << std::setw(50) << "Total filtering time" << " | " << std::setw(12) << filtering_time << "\n";

  //---------------------------------------------
  // Decrypt intermediate filter results
  // ---------------------------------------------
  std::cout << "\n********** Decrypting intermediate filter results **********\n";

  Plaintext type_match_ptxt_verify, shipdate_match_ptxt, price_match_ptxt;
  cc->Decrypt(keyPair.secretKey, type_match, &type_match_ptxt_verify);
  cc->Decrypt(keyPair.secretKey, shipdate_match, &shipdate_match_ptxt);
  cc->Decrypt(keyPair.secretKey, price_match, &price_match_ptxt);

  type_match_ptxt_verify->SetLength(SLOT_COUNT);
  shipdate_match_ptxt->SetLength(SLOT_COUNT);
  price_match_ptxt->SetLength(SLOT_COUNT);

  auto type_dec = type_match_ptxt_verify->GetPackedValue();
  auto shipdate_dec = shipdate_match_ptxt->GetPackedValue();
  auto price_dec = price_match_ptxt->GetPackedValue();

  // Calculate statistics for each encrypted condition
  uint64_t enc_type_pass = 0, enc_shipdate_pass = 0, enc_price_pass = 0;
  for (size_t i = 0; i < SLOT_COUNT; i++) {
    if (type_dec[i] != 0 && type_dec[i] == 1) enc_type_pass++;
    if (shipdate_dec[i] != 0 && shipdate_dec[i] == 1) enc_shipdate_pass++;
    if (price_dec[i] != 0 && price_dec[i] == 1) enc_price_pass++;
  }

  // Calculate expected statistics
  uint64_t exp_type_pass = 0, exp_shipdate_pass = 0, exp_price_pass = 0;
  for (size_t i = 0; i < SLOT_COUNT; i++) {
    if (p_type[i].substr(0, 5) == "PROMO") exp_type_pass++;
    if (l_shipdate[i] > 9999 && l_shipdate[i] < 10030) exp_shipdate_pass++;

    // Calculate discounted price: price * (1 - discount)
    double discounted_price = l_extendedprice[i] * (1.0 - l_discount[i]);
    if (discounted_price < 50.0) exp_price_pass++;
  }

  std::cout << std::setw(50) << "Filter Condition" << " | "
            << std::setw(12) << "Expected" << " | "
            << std::setw(12) << "Encrypted" << " | "
            << std::setw(8) << "Match" << "\n";
  std::cout << std::string(85, '-') << "\n";

  std::cout << std::setw(50) << "p_type LIKE 'PROMO%'" << " | "
            << std::setw(12) << exp_type_pass << " | "
            << std::setw(12) << enc_type_pass << " | "
            << std::setw(8) << (exp_type_pass == enc_type_pass ? "✓" : "✗") << "\n";

  std::cout << std::setw(50) << "l_shipdate > 9999 AND < 10030" << " | "
            << std::setw(12) << exp_shipdate_pass << " | "
            << std::setw(12) << enc_shipdate_pass << " | "
            << std::setw(8) << (exp_shipdate_pass == enc_shipdate_pass ? "✓" : "✗") << "\n";

  std::cout << std::setw(50) << "price * (1-discount) < 50" << " | "
            << std::setw(12) << exp_price_pass << " | "
            << std::setw(12) << enc_price_pass << " | "
            << std::setw(8) << (exp_price_pass == enc_price_pass ? "✓" : "✗") << "\n";

  //---------------------------------------------
  // Aggregation - Count matches
  // ---------------------------------------------
  start = std::chrono::system_clock::now();
  ctx->EvalSumInPlace(filter_result);
  end = std::chrono::system_clock::now();

  aggregation_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
  std::cout << "\naggregation time = " << aggregation_time << " ms\n";

  // Calculate and display amortized times
  double total_query_time = filtering_time + aggregation_time;
  double amortized_filtering = filtering_time / SLOT_COUNT;
  double amortized_aggregation = aggregation_time / SLOT_COUNT;
  double amortized_total = total_query_time / SLOT_COUNT;

  std::cout << "\n********** Amortized Time (per row) **********\n";
  std::cout << std::setw(50) << "Filtering time per row" << " | " << std::fixed << std::setprecision(3) << std::setw(12) << amortized_filtering << " ms\n";
  std::cout << std::setw(50) << "Aggregation time per row" << " | " << std::fixed << std::setprecision(3) << std::setw(12) << amortized_aggregation << " ms\n";
  std::cout << std::setw(50) << "Total time per row" << " | " << std::fixed << std::setprecision(3) << std::setw(12) << amortized_total << " ms\n";

  // Check depth consumption
  uint32_t level_consumed = filter_result->GetLevel();
  std::cout << "Depth consumed: " << level_consumed << ", Remaining depth: " << (mdepth - level_consumed) << "\n";

  // Decrypt final aggregated result
  Plaintext result_ptxt;
  cc->Decrypt(keyPair.secretKey, filter_result, &result_ptxt);
  result_ptxt->SetLength(1);
  auto result_count = result_ptxt->GetPackedValue()[0];

  // Calculate expected final result
  uint64_t expected_count = 0;
  for (size_t i = 0; i < SLOT_COUNT; i++) {
    bool type_ok = (p_type[i].substr(0, 5) == "PROMO");
    bool shipdate_ok = (l_shipdate[i] > 9999 && l_shipdate[i] < 10030);
    // Calculate discounted price: price * (1 - discount)
    double discounted_price = l_extendedprice[i] * (1.0 - l_discount[i]);
    bool price_ok = (discounted_price < 50.0);

    if (type_ok && shipdate_ok && price_ok) {
      expected_count++;
    }
  }

  std::cout << "\n********** Final Query Result **********\n";
  std::cout << "Query Evaluation Time: " << filtering_time + aggregation_time << " ms" << std::endl;
  std::cout << "Total records matching ALL conditions:\n";
  std::cout << "  Expected count:  " << expected_count << "\n";
  std::cout << "  Encrypted count: " << result_count << "\n";

  if (result_count == expected_count) {
    std::cout << "\n✓ Result is CORRECT!\n";
  } else {
    std::cout << "\n✗ Result is INCORRECT!\n";
    std::cout << "  Difference: " << (int64_t)result_count - (int64_t)expected_count << "\n";
  }

  // Write results to CSV
  std::string mode = eager_carry ? "eager" : "lazy";
  write_q2_csv("HybridQ2", mode, RingDim, p, radix, seed,
               type_time, shipdate_time,
               eval_sub1_time,
               mult_time, carry_after_mult_time,
               eval_sub2_time,
               reduce_time, carry_time, sign_time,
               arithmetic_time, combine_time,
               filtering_time, aggregation_time);

  QueryResult result;
  result.query_name = eager_carry ? "Q2 (eager)" : "Q2 (lazy)";
  result.radix = radix;
  result.filtering_time = filtering_time;
  result.aggregation_time = aggregation_time;
  result.total_time = total_query_time;
  result.amortized_total = amortized_total;
  result.depth_consumed = level_consumed;
  result.q2_homlike = type_time;
  result.q2_rahc = shipdate_time + sign_time;
  result.q2_multiplication = mult_time;
  result.q2_subtraction = eval_sub1_time + eval_sub2_time;
  result.q2_carry_propagation = carry_after_mult_time + reduce_time + carry_time;
  result.q2_and_ops = combine_time;
  result.carry_after_mult = carry_after_mult_time;
  result.carry_before_sign = reduce_time + carry_time;
  release_crypto_context();
  return result;
}

// Depth configuration for each radix
struct RadixDepthConfig {
  uint32_t radix;
  uint32_t q1_depth;
  uint32_t q2_depth;
};

// Simplified configuration structure
int main(int argc, char* argv[])
{
  std::cout << "========================================\n";
  std::cout << "FHE Hybrid SQL Queries Benchmark\n";
  std::cout << "========================================\n";
  std::cout << "Testing queries with mixed string and integer operations\n\n";

  // Parse command-line arguments
  uint64_t ring_dim = 1 << 14;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--ring-dim" && i + 1 < argc) {
      ring_dim = std::stoull(argv[++i]);
    } else if (arg == "--quick") {
      ring_dim = 1 << 7;
    }
  }
  std::cout << "RingDim = " << ring_dim << std::endl;

  // Depth configuration for each radix (fixed for all ring_dim)
  std::vector<RadixDepthConfig> radix_depths = {
    {2, 17, 41},  // radix=2: Q1=17, Q2=41
    {4, 18, 42},  // radix=4: Q1=18, Q2=42
    {8, 20, 48},  // radix=8: Q1=20, Q2=48
  };

  // Test configurations: radix values to test
  std::vector<uint32_t> radix_configs = {2, 4, 8};

  // Run benchmarks
  std::vector<QueryResult> all_results;

  for (uint32_t radix : radix_configs) {
    // Find depth config for this radix
    auto it = std::find_if(radix_depths.begin(), radix_depths.end(),
                          [&](const RadixDepthConfig& rd) { return rd.radix == radix; });

    if (it == radix_depths.end()) {
      std::cerr << "Error: No depth config found for radix=" << radix << "\n";
      continue;
    }

    uint32_t q1_depth = it->q1_depth;
    uint32_t q2_depth = it->q2_depth;

    // Get plaintext modulus from RingParams
    uint64_t p = RingParams::GetPlaintextModulus(ring_dim);

    std::cout << "\n========================================\n";
    std::cout << "Configuration:\n";
    std::cout << "  RingDim = " << ring_dim << " (" << ring_dim << " slots)\n";
    std::cout << "  Plaintext modulus p = " << p << "\n";
    std::cout << "  Radix = " << radix << " (segment_count = " << (16/radix) << ")\n";
    std::cout << "  Q1 Depth = " << q1_depth << "\n";
    std::cout << "  Q2 Depth = " << q2_depth << "\n";
    std::cout << "========================================\n";

    all_results.push_back(run_hybrid_q1(ring_dim, p, radix, q1_depth));
    all_results.push_back(run_hybrid_q2(ring_dim, p, radix, q2_depth, false));
    all_results.push_back(run_hybrid_q2(ring_dim, p, radix, q2_depth, true));
  }

  // Helper: find result by query name and radix
  auto find_result = [&](const std::string& name, uint32_t r) -> const QueryResult* {
    for (const auto& res : all_results)
      if (res.query_name == name && res.radix == r) return &res;
    return nullptr;
  };

  int W = 14;  // column width for values
  int LW = 24; // label width

  auto print_val = [&](double v) {
    std::cout << std::setw(W) << std::fixed << std::setprecision(1) << v;
  };

  // ===== HQ1 Breakdown =====
  std::cout << "\n========================================\n";
  std::cout << "HQ1 Latency Breakdown (ms). RingDim = " << ring_dim << "\n";
  std::cout << "========================================\n";
  std::cout << std::left << std::setw(LW) << ""
            << std::setw(W) << "APEX (2-bit)"
            << std::setw(W) << "APEX (4-bit)"
            << std::setw(W) << "APEX (8-bit)" << "\n";
  std::cout << std::string(LW + W * 3, '-') << "\n";

  // HomLIKE header
  std::cout << std::left << std::setw(LW) << "HomLIKE" << "\n";
  // Exact match
  std::cout << std::left << std::setw(LW) << "  Exact match";
  for (uint32_t r : radix_configs) { auto* p = find_result("Q1", r); print_val(p ? p->q1_exact_match : 0); }
  std::cout << "\n";
  // Prefix match
  std::cout << std::left << std::setw(LW) << "  Prefix match";
  for (uint32_t r : radix_configs) { auto* p = find_result("Q1", r); print_val(p ? p->q1_prefix_match : 0); }
  std::cout << "\n";
  // Substring match
  std::cout << std::left << std::setw(LW) << "  Substring match";
  for (uint32_t r : radix_configs) { auto* p = find_result("Q1", r); print_val(p ? p->q1_substring_match : 0); }
  std::cout << "\n";
  // RAHC
  std::cout << std::left << std::setw(LW) << "RAHC";
  for (uint32_t r : radix_configs) { auto* p = find_result("Q1", r); print_val(p ? p->q1_rahc : 0); }
  std::cout << "\n";
  // AND operations
  std::cout << std::left << std::setw(LW) << "AND operations";
  for (uint32_t r : radix_configs) { auto* p = find_result("Q1", r); print_val(p ? p->q1_and_ops : 0); }
  std::cout << "\n";
  std::cout << std::string(LW + W * 3, '-') << "\n";
  // Filtering (total)
  std::cout << std::left << std::setw(LW) << "Filtering (total)";
  for (uint32_t r : radix_configs) { auto* p = find_result("Q1", r); print_val(p ? p->filtering_time : 0); }
  std::cout << "\n";
  // Aggregation
  std::cout << std::left << std::setw(LW) << "Aggregation";
  for (uint32_t r : radix_configs) { auto* p = find_result("Q1", r); print_val(p ? p->aggregation_time : 0); }
  std::cout << "\n";
  // Total
  std::cout << std::left << std::setw(LW) << "Total";
  for (uint32_t r : radix_configs) { auto* p = find_result("Q1", r); print_val(p ? p->total_time : 0); }
  std::cout << "\n";
  // Amortized (ms)
  std::cout << std::left << std::setw(LW) << "Amortized (ms)";
  for (uint32_t r : radix_configs) { auto* p = find_result("Q1", r); print_val(p ? p->amortized_total : 0); }
  std::cout << "\n";

  // ===== HQ2 Breakdown (lazy vs eager side by side) =====
  int W2 = 10;  // narrower columns for 6-column layout
  auto print_val2 = [&](double v) {
    std::cout << std::setw(W2) << std::fixed << std::setprecision(1) << v;
  };

  std::cout << "\n========================================\n";
  std::cout << "HQ2 Latency Breakdown (ms). RingDim = " << ring_dim << "\n";
  std::cout << "========================================\n";
  // Header: two sub-columns (lazy/eager) per radix
  std::cout << std::left << std::setw(LW) << ""
            << std::setw(W2 * 2) << "APEX (2-bit)"
            << std::setw(W2 * 2) << "APEX (4-bit)"
            << std::setw(W2 * 2) << "APEX (8-bit)" << "\n";
  std::cout << std::left << std::setw(LW) << "";
  for (int i = 0; i < 3; i++) std::cout << std::setw(W2) << "lazy" << std::setw(W2) << "eager";
  std::cout << "\n";
  std::cout << std::string(LW + W2 * 6, '-') << "\n";

  // Helper to print a row with lazy/eager values
  auto print_q2_row = [&](const std::string& label, auto getter) {
    std::cout << std::left << std::setw(LW) << label;
    for (uint32_t r : radix_configs) {
      auto* lazy = find_result("Q2 (lazy)", r);
      auto* eager = find_result("Q2 (eager)", r);
      print_val2(lazy ? getter(lazy) : 0);
      print_val2(eager ? getter(eager) : 0);
    }
    std::cout << "\n";
  };

  print_q2_row("HomLIKE", [](const QueryResult* p) { return p->q2_homlike; });
  print_q2_row("RAHC", [](const QueryResult* p) { return p->q2_rahc; });
  std::cout << std::left << std::setw(LW) << "Seg-wise arithmetic" << "\n";
  print_q2_row("  Multiplication", [](const QueryResult* p) { return p->q2_multiplication; });
  print_q2_row("  Subtraction", [](const QueryResult* p) { return p->q2_subtraction; });
  print_q2_row("  Carry propagation", [](const QueryResult* p) { return p->q2_carry_propagation; });
  print_q2_row("AND operations", [](const QueryResult* p) { return p->q2_and_ops; });
  std::cout << std::string(LW + W2 * 6, '-') << "\n";
  print_q2_row("Filtering (total)", [](const QueryResult* p) { return p->filtering_time; });
  print_q2_row("Aggregation", [](const QueryResult* p) { return p->aggregation_time; });
  print_q2_row("Total", [](const QueryResult* p) { return p->total_time; });
  print_q2_row("Amortized (ms)", [](const QueryResult* p) { return p->amortized_total; });

  std::cout << "\nBenchmark completed!\n";
  std::cout << "Results written to hybrid_queries_results.csv\n";

  return 0;
}
