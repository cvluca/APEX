#include <libapex.h>
#include <cryptocontextfactory.h>
#include <fstream>
#include <ctime>
#include <iomanip>
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

struct TpchResult {
  std::string query_name;
  uint32_t radix;
  double filtering_time;
  double aggregation_time;
  double total_time;
  double amortized_total;  // ms
};

// Helper function to write results to CSV
void write_to_csv(const std::string& query_name, uint64_t ring_dim, uint32_t radix,
                  uint32_t seed, double filtering_time, double aggregation_time)
{
  const std::string filename = "tpch_results.csv";
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
    csv_file << "query_name,ring_dim,radix,segment_count,seed,filtering_time_ms,aggregation_time_ms,total_time_ms,timestamp\n";
  }

  // Get current timestamp
  std::time_t now = std::time(nullptr);
  char timestamp[100];
  std::strftime(timestamp, sizeof(timestamp), "%Y-%m-%d %H:%M:%S", std::localtime(&now));

  // Write data
  double total_time = filtering_time + aggregation_time;
  uint32_t segment_count = 16 / radix;
  csv_file << query_name << ","
           << ring_dim << ","
           << radix << ","
           << segment_count << ","
           << seed << ","
           << filtering_time << ","
           << aggregation_time << ","
           << total_time << ","
           << timestamp << "\n";

  csv_file.close();
  std::cout << "Results written to " << filename << std::endl;
}

/***
 * TPC-H Query 1
    select
        l_returnflag,
        l_linestatus,
        sum(l_quantity) as sum_qty,
        sum(l_extendedprice) as sum_base_price,
        sum(l_extendedprice * (1 - l_discount)) as sum_disc_price,
        sum(l_extendedprice * (1 - l_discount) * (1 + l_tax)) as sum_charge,
        avg(l_quantity) as avg_qty,
        avg(l_extendedprice) as avg_price,
        avg(l_discount) as avg_disc,
        count(*) as count_order
    from
        lineitem
    where
        l_shipdate <= date '1998-12-01' - interval ':1' day (3)
    group by
        l_returnflag,
        l_linestatus
    order by
        l_returnflag,
        l_linestatus;
*/
TpchResult run_q1(uint64_t RingDim, uint32_t radix, uint32_t mdepth)
{
  uint64_t p = RingParams::GetPlaintextModulus(RingDim);
  const usint SLOT_COUNT = RingDim;
  uint32_t segment_count = 16 / radix;

  std::cout << "Running TPC-H Query 1 with record number: " << SLOT_COUNT
            << ", radix: " << radix << ", segment_count: " << segment_count
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
  fparams.SetSegmentCount(segment_count);

  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);
  ctx->GenSumKey(keyPair.secretKey);

  //---------------------------------------------
  // Generate random inputs
  // ---------------------------------------------
  std::uniform_int_distribution<uint64_t> shipdate_message(0, 10592 + 100);
  std::uniform_int_distribution<uint64_t> quantity_message(0, 8);
  std::uniform_int_distribution<uint32_t> binary_message(0, 1);

  std::random_device seed_gen;
  auto seed = seed_gen();
  std::cout << "Seed: " << seed << std::endl;
  std::default_random_engine engine(seed);

  std::vector<uint64_t> shipdate(SLOT_COUNT), returnflag(SLOT_COUNT),
  linestatus(SLOT_COUNT), shipdate_predicate(SLOT_COUNT, 10592),
  returnflag_predicate_Y(SLOT_COUNT, 1), returnflag_predicate_N(SLOT_COUNT, 0),
  linestatus_predicate_Y(SLOT_COUNT, 1), linestatus_predicate_N(SLOT_COUNT, 0);
  std::vector<int64_t> quantity(SLOT_COUNT);

  for (int i = 0; i < SLOT_COUNT; i++)
  {
    shipdate[i] = shipdate_message(engine);
    quantity[i] = quantity_message(engine);
    returnflag[i] = binary_message(engine);
    linestatus[i] = binary_message(engine);
  }

  // Create plaintexts
  auto quantity_ptxt = cc->MakePackedPlaintext(quantity);
  auto shipdate_ptxt = ctx->MakePackedRadixPlaintext(shipdate);
  auto shipdate_predicate_ptxt = ctx->MakePackedRadixPlaintext(shipdate_predicate);
  fparams.SetSegmentCount(1);
  auto returnflag_ptxt = ctx->MakePackedRadixPlaintext(returnflag, fparams);
  auto linestatus_ptxt = ctx->MakePackedRadixPlaintext(linestatus, fparams);
  auto returnflag_predicate_Y_ptxt = ctx->MakePackedRadixPlaintext(returnflag_predicate_Y, fparams);
  auto returnflag_predicate_N_ptxt = ctx->MakePackedRadixPlaintext(returnflag_predicate_N, fparams);
  auto linestatus_predicate_Y_ptxt = ctx->MakePackedRadixPlaintext(linestatus_predicate_Y, fparams);
  auto linestatus_predicate_N_ptxt = ctx->MakePackedRadixPlaintext(linestatus_predicate_N, fparams);

  // Encrypt
  auto quantity_ctxt = cc->Encrypt(keyPair.publicKey, quantity_ptxt);
  auto shipdate_ctxt = ctx->Encrypt(shipdate_ptxt);
  auto shipdate_predicate_ctxt = ctx->Encrypt(shipdate_predicate_ptxt);
  auto returnflag_ctxt = ctx->Encrypt(returnflag_ptxt);
  auto linestatus_ctxt = ctx->Encrypt(linestatus_ptxt);
  auto returnflag_predicate_Y_ctxt = ctx->Encrypt(returnflag_predicate_Y_ptxt);
  auto returnflag_predicate_N_ctxt = ctx->Encrypt(returnflag_predicate_N_ptxt);
  auto linestatus_predicate_Y_ctxt = ctx->Encrypt(linestatus_predicate_Y_ptxt);
  auto linestatus_predicate_N_ctxt = ctx->Encrypt(linestatus_predicate_N_ptxt);

  auto one_ptxt = cc->MakePackedPlaintext(std::vector<int64_t>(SLOT_COUNT, 1));
  //---------------------------------------------
  // Filtering: l_shipdate <= predicate_value
  // ---------------------------------------------
  double filtering_time = 0, aggregation_time = 0;
  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();

  auto shipdate_res = ctx->EvalComp(shipdate_ctxt, shipdate_predicate_ctxt, CompType::LT);

  auto returnflag_YY_res = ctx->EvalComp(returnflag_ctxt, returnflag_predicate_Y_ctxt, CompType::EQ);
  auto linestatus_YY_res = ctx->EvalComp(linestatus_ctxt, linestatus_predicate_Y_ctxt, CompType::EQ);

  auto returnflag_YY_neg = cc->EvalNegate(returnflag_YY_res);
  auto returnflag_YN_res = cc->EvalAdd(returnflag_YY_neg, one_ptxt);
  auto linestatus_YY_neg = cc->EvalNegate(linestatus_YY_res);
  auto linestatus_YN_res = cc->EvalAdd(linestatus_YY_neg, one_ptxt);

  auto filter_res_YY = cc->EvalMult(shipdate_res, returnflag_YY_res);
  filter_res_YY = cc->EvalMult(filter_res_YY, linestatus_YY_res);

  auto filter_res_YN = cc->EvalMult(shipdate_res, returnflag_YY_res);
  filter_res_YN = cc->EvalMult(filter_res_YN, linestatus_YN_res);

  auto filter_res_NY = cc->EvalMult(shipdate_res, returnflag_YN_res);
  filter_res_NY = cc->EvalMult(filter_res_NY, linestatus_YY_res);

  auto filter_res_NN = cc->EvalMult(shipdate_res, returnflag_YN_res);
  filter_res_NN = cc->EvalMult(filter_res_NN, linestatus_YN_res);

  end = std::chrono::system_clock::now();
  filtering_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0 * 3;
  std::cout << "filtering time = " << filtering_time << " ms\n";

  std::vector<uint64_t> plain_filter_res_YY(SLOT_COUNT, 0), plain_filter_res_YN(SLOT_COUNT, 0),
  plain_filter_res_NY(SLOT_COUNT, 0), plain_filter_res_NN(SLOT_COUNT, 0);
  uint64_t plain_agg_res_YY = 0, plain_agg_res_YN = 0, plain_agg_res_NY = 0, plain_agg_res_NN = 0;

  for (size_t i = 0; i < SLOT_COUNT; i++) {
    if (shipdate[i] < 10592) {
      if (returnflag[i] == 1) {
        if (linestatus[i] == 1) {
          plain_filter_res_YY[i] = 1;
          plain_agg_res_YY += quantity[i];
        } else {
          plain_filter_res_YN[i] = 1;
          plain_agg_res_YN += quantity[i];
        }
      } else {
        if (linestatus[i] == 1) {
          plain_filter_res_NY[i] = 1;
          plain_agg_res_NY += quantity[i];
        } else {
          plain_filter_res_NN[i] = 1;
          plain_agg_res_NN += quantity[i];
        }
      }
    }
  }

  std::cout << "Aggregating quanlity, Taking SUM(quantlity) as an example.." << std::endl;

  start = std::chrono::system_clock::now();
  auto sum_qty_cipher_YY = cc->EvalMult(quantity_ctxt, filter_res_YY);
  auto sum_qty_cipher_YN = cc->EvalMult(quantity_ctxt, filter_res_YN);
  auto sum_qty_cipher_NY = cc->EvalMult(quantity_ctxt, filter_res_NY);
  auto sum_qty_cipher_NN = cc->EvalMult(quantity_ctxt, filter_res_NN);

  ctx->EvalSumInPlace(sum_qty_cipher_YY);
  ctx->EvalSumInPlace(sum_qty_cipher_YN);
  ctx->EvalSumInPlace(sum_qty_cipher_NY);
  ctx->EvalSumInPlace(sum_qty_cipher_NN);
  end = std::chrono::system_clock::now();

  aggregation_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
  std::cout << "aggregation time = " << aggregation_time << " ms\n";

  // Check depth consumption
  uint32_t level_consumed_YY = sum_qty_cipher_YY->GetLevel();
  uint32_t level_consumed_YN = sum_qty_cipher_YN->GetLevel();
  uint32_t level_consumed_NY = sum_qty_cipher_NY->GetLevel();
  uint32_t level_consumed_NN = sum_qty_cipher_NN->GetLevel();
  std::cout << "Depth consumed (YY): " << level_consumed_YY << ", Remaining depth: " << (mdepth - level_consumed_YY) << "\n";
  std::cout << "Depth consumed (YN): " << level_consumed_YN << ", Remaining depth: " << (mdepth - level_consumed_YN) << "\n";
  std::cout << "Depth consumed (NY): " << level_consumed_NY << ", Remaining depth: " << (mdepth - level_consumed_NY) << "\n";
  std::cout << "Depth consumed (NN): " << level_consumed_NN << ", Remaining depth: " << (mdepth - level_consumed_NN) << "\n";

  Plaintext plaintextDec_agg_resultYY, plaintextDec_agg_resultYN, plaintextDec_agg_resultNY, plaintextDec_agg_resultNN;
  cc->Decrypt(keyPair.secretKey, sum_qty_cipher_YY, &plaintextDec_agg_resultYY);
  cc->Decrypt(keyPair.secretKey, sum_qty_cipher_YN, &plaintextDec_agg_resultYN);
  cc->Decrypt(keyPair.secretKey, sum_qty_cipher_NY, &plaintextDec_agg_resultNY);
  cc->Decrypt(keyPair.secretKey, sum_qty_cipher_NN, &plaintextDec_agg_resultNN);

  plaintextDec_agg_resultYY->SetLength(1);
  plaintextDec_agg_resultYN->SetLength(1);
  plaintextDec_agg_resultNY->SetLength(1);
  plaintextDec_agg_resultNN->SetLength(1);

  auto agg_resultYY = plaintextDec_agg_resultYY->GetPackedValue()[0];
  auto agg_resultYN = plaintextDec_agg_resultYN->GetPackedValue()[0];
  auto agg_resultNY = plaintextDec_agg_resultNY->GetPackedValue()[0];
  auto agg_resultNN = plaintextDec_agg_resultNN->GetPackedValue()[0];

  std::cout << "Query evaluation time: " << (filtering_time + aggregation_time) << " ms\n";
  std::cout << "--------------------------------------------------------" << std::endl;

  std::cout << "Encrypted query result: " << std::endl;
  std::cout << std::setw(16) << "returnfalg" << "|" << std::setw(16) << "linestatus" << "|" << std::setw(16) << "sum_qty" << std::endl;
  std::cout << std::setw(16) << "Y" << "|" << std::setw(16) << "Y" << "|" << std::setw(16) << agg_resultYY << std::endl;
  std::cout << std::setw(16) << "Y" << "|" << std::setw(16) << "N" << "|" << std::setw(16) << agg_resultYN << std::endl;
  std::cout << std::setw(16) << "N" << "|" << std::setw(16) << "Y" << "|" << std::setw(16) << agg_resultNY << std::endl;
  std::cout << std::setw(16) << "N" << "|" << std::setw(16) << "N" << "|" << std::setw(16) << agg_resultNN << std::endl;

  std::cout << "Plain query result: " << std::endl;
  std::cout << std::setw(16) << "returnflag" << "|" << std::setw(16) << "linestatus" << "|" << std::setw(16) << "sum_qty" << std::endl;
  std::cout << std::setw(16) << "Y" << "|" << std::setw(16) << "Y" << "|" << std::setw(16) << plain_agg_res_YY << std::endl;
  std::cout << std::setw(16) << "Y" << "|" << std::setw(16) << "N" << "|" << std::setw(16) << plain_agg_res_YN << std::endl;
  std::cout << std::setw(16) << "N" << "|" << std::setw(16) << "Y" << "|" << std::setw(16) << plain_agg_res_NY << std::endl;
  std::cout << std::setw(16) << "N" << "|" << std::setw(16) << "N" << "|" << std::setw(16) << plain_agg_res_NN << std::endl;

  // Write results to CSV
  write_to_csv("Q1", RingDim, radix, seed, filtering_time, aggregation_time);

  double total = filtering_time + aggregation_time;
  release_crypto_context();
  return {"Q1", radix, filtering_time, aggregation_time, total, total / SLOT_COUNT};
}

/***
 * TPC-H Query 6
 * select
        sum(l_extendedprice * l_discount) as revenue
    from
        lineitem
    where
        l_shipdate >= date ':1'
        and l_shipdate < date ':1' + interval '1' year
        and l_discount between :2 - 0.01 and :2 + 0.01
        and l_quantity < :3;

*/
TpchResult run_q6(uint64_t RingDim, uint32_t radix, uint32_t mdepth)
{
  uint64_t p = RingParams::GetPlaintextModulus(RingDim);
  const usint SLOT_COUNT = RingDim;
  uint32_t segment_count = 16 / radix;

  std::cout << "Running TPC-H Query 6 with record number: " << SLOT_COUNT
            << ", radix: " << radix << ", segment_count: " << segment_count
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
  fparams.SetSegmentCount(segment_count);

  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);
  ctx->GenSumKey(keyPair.secretKey);

  //---------------------------------------------
  // Generate random inputs
  // ---------------------------------------------
  std::uniform_int_distribution<int64_t> shipdate_message(10000, 15000);
  std::uniform_int_distribution<int64_t> discount_message(2000, 9000);
  std::uniform_int_distribution<int64_t> quantity_message(2400, 2500);
  std::uniform_int_distribution<int64_t> revenue_message(0, 100);

  std::random_device seed_gen;
  auto seed = seed_gen();
  std::cout << "Seed: " << seed << std::endl;
  std::default_random_engine engine(seed);

  std::vector<int64_t> revenue(SLOT_COUNT), 
  shipdate(SLOT_COUNT), discount(SLOT_COUNT), quantity(SLOT_COUNT);
  std::vector<int64_t> predicate1_value(SLOT_COUNT, 10592),
  predicate2_value(SLOT_COUNT, 10957), predicate3_value(SLOT_COUNT, 3500),
  predicate4_value(SLOT_COUNT, 4500), predicate5_value(SLOT_COUNT, 2450);

  for (size_t i = 0; i < SLOT_COUNT; ++i)
  {
    revenue[i] = revenue_message(engine);
    shipdate[i] = shipdate_message(engine);
    discount[i] = discount_message(engine);
    quantity[i] = quantity_message(engine);
  }

  auto shipdate_ptxt = ctx->MakePackedRadixPlaintext(shipdate);
  auto discount_ptxt = ctx->MakePackedRadixPlaintext(discount);
  auto quantity_ptxt = ctx->MakePackedRadixPlaintext(quantity);
  auto predicate1_ptxt = ctx->MakePackedRadixPlaintext(predicate1_value);
  auto predicate2_ptxt = ctx->MakePackedRadixPlaintext(predicate2_value);
  auto predicate3_ptxt = ctx->MakePackedRadixPlaintext(predicate3_value);
  auto predicate4_ptxt = ctx->MakePackedRadixPlaintext(predicate4_value);
  auto predicate5_ptxt = ctx->MakePackedRadixPlaintext(predicate5_value);
  auto revenue_ptxt = cc->MakePackedPlaintext(revenue);

  auto shipdate_ctxt = ctx->Encrypt(shipdate_ptxt);
  auto discount_ctxt = ctx->Encrypt(discount_ptxt);
  auto quantity_ctxt = ctx->Encrypt(quantity_ptxt);
  auto predicate1_ctxt = ctx->Encrypt(predicate1_ptxt);
  auto predicate2_ctxt = ctx->Encrypt(predicate2_ptxt);
  auto predicate3_ctxt = ctx->Encrypt(predicate3_ptxt);
  auto predicate4_ctxt = ctx->Encrypt(predicate4_ptxt);
  auto predicate5_ctxt = ctx->Encrypt(predicate5_ptxt);
  auto revenue_ctxt = cc->Encrypt(keyPair.publicKey, revenue_ptxt);

  //---------------------------------------------
  // Filtering
  // ---------------------------------------------
  double filtering_time = 0, aggregation_time = 0;
  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();

  std::vector<lbcrypto::Ciphertext<DCRTPoly>> filter_res_vec;
  filter_res_vec.push_back(ctx->EvalComp(shipdate_ctxt, predicate1_ctxt, CompType::GT));
  filter_res_vec.push_back(ctx->EvalComp(shipdate_ctxt, predicate2_ctxt, CompType::LT));
  filter_res_vec.push_back(ctx->EvalComp(discount_ctxt, predicate3_ctxt, CompType::GT));
  filter_res_vec.push_back(ctx->EvalComp(discount_ctxt, predicate4_ctxt, CompType::LT));
  filter_res_vec.push_back(ctx->EvalComp(quantity_ctxt, predicate5_ctxt, CompType::LT));
  filter_res_vec.push_back(revenue_ctxt);
  auto result = cc->EvalMultMany(filter_res_vec);

  end = std::chrono::system_clock::now();

  filtering_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
  std::cout << "filtering time = " << filtering_time << " ms\n";
  std::cout << "average time per slot = " << (filtering_time/ static_cast<double>(SLOT_COUNT)) << " ms\n";

  //---------------------------------------------
  // Aggregation
  // ---------------------------------------------
  start = std::chrono::system_clock::now();
  ctx->EvalSumInPlace(result);
  end = std::chrono::system_clock::now();
  aggregation_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
  std::cout << "aggregation time = " << aggregation_time << " ms\n";
  std::cout << "average time per slot = " << (aggregation_time / static_cast<double>(SLOT_COUNT)) << " ms\n";

  std::cout << "total time = " << (filtering_time + aggregation_time) << " ms\n";
  std::cout << "average time per slot = " << ((filtering_time + aggregation_time) / static_cast<double>(SLOT_COUNT)) << " ms\n";

  //---------------------------------------------
  // Decrypt and verify results
  //----------------------------------------------
  uint32_t level_consumed = result->GetLevel();
  std::cout << "Depth consumed: " << level_consumed << ", Remaining depth: " << (mdepth - level_consumed) << "\n";
  Plaintext result_ptxt;
  cc->Decrypt(keyPair.secretKey, result, &result_ptxt);
  result_ptxt->SetLength(SLOT_COUNT);
  const auto& result_vec = result_ptxt->GetPackedValue();

  int64_t expected_revenue = 0;
  for (size_t i = 0; i < SLOT_COUNT; ++i)
  {
    if (shipdate[i] > predicate1_value[i] && shipdate[i] < predicate2_value[i] &&
      discount[i] > predicate3_value[i] && discount[i] < predicate4_value[i] &&
      quantity[i] < predicate5_value[i])
    {
      expected_revenue += revenue[i];
    }
  }

  std::cout << "Expected revenue: " << expected_revenue << std::endl;
  std::cout << "Computed revenue: " << result_vec[0] << std::endl;
  if (expected_revenue > (p - 1) / 2)
  {
    std::cout << "Expected revenue exceeds modulus, please choose larger p." << std::endl;
  }

  if (result_vec[0] == expected_revenue)
  {
    std::cout << "Result is correct!" << std::endl;
  }
  else
{
    std::cout << "Result is incorrect!" << std::endl;
  }

  // Write results to CSV
  write_to_csv("Q6", RingDim, radix, seed, filtering_time, aggregation_time);

  double total = filtering_time + aggregation_time;
  release_crypto_context();
  return {"Q6", radix, filtering_time, aggregation_time, total, total / SLOT_COUNT};
}

/*
    TPC-H Query 12
    select
        l_shipmode,
        sum(case
            when o_orderpriority = '1-URGENT'
                or o_orderpriority = '2-HIGH'
                then 1
            else 0
        end) as high_line_count,
        sum(case
            when o_orderpriority <> '1-URGENT'
                and o_orderpriority <> '2-HIGH'
                then 1
            else 0
        end) as low_line_count
    from
        orders,
        lineitem
    where
        o_orderkey = l_orderkey
        and l_shipmode in (':1', ':2')
        and l_commitdate < l_receiptdate
        and l_shipdate < l_commitdate
        and l_receiptdate >= date ':3'
        and l_receiptdate < date ':3' + interval '1' year
    group by
        l_shipmode
    order by
        l_shipmode;
    Consider the joined table
*/
TpchResult run_q12(uint64_t RingDim, uint32_t radix, uint32_t mdepth)
{
  uint64_t p = RingParams::GetPlaintextModulus(RingDim);
  const usint SLOT_COUNT = RingDim;
  uint32_t segment_count = 16 / radix;

  std::cout << "Running TPC-H Query 12 with record number: " << SLOT_COUNT
            << ", radix: " << radix << ", segment_count: " << segment_count
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
  fparams.SetSegmentCount(segment_count);

  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);
  ctx->GenSumKey(keyPair.secretKey);

  //---------------------------------------------
  // Generate random inputs
  // ---------------------------------------------
  std::uniform_int_distribution<std::uint64_t> shipmode_message(1, 10);
  std::uniform_int_distribution<std::uint64_t> shipdate_message(0, 15000);
  std::uniform_int_distribution<std::uint64_t> receiptdate_message(0, 15000);
  std::uniform_int_distribution<std::uint64_t> commitdate_message(0, 15000);
  // orderpriority \in ('1-URGENT', '2-HIGH', '3-MEDIUM', '4-NOT SPECIFIED', '5-LOW')
  std::uniform_int_distribution<uint64_t> orderpriority_message(1, 5);

  std::random_device seed_gen;
  auto seed = seed_gen();
  std::cout << "Seed: " << seed << std::endl;
  std::default_random_engine engine(seed);

  std::vector<uint64_t> shipdate(SLOT_COUNT), commitdate(SLOT_COUNT), receiptdate(SLOT_COUNT),
  shipmode(SLOT_COUNT), orderpriority(SLOT_COUNT);
  std::vector<uint64_t> predicate_date1(SLOT_COUNT, 10000), predicate_date2(SLOT_COUNT, 13000),
  predicate_mail(SLOT_COUNT, 1), predicate_ship(SLOT_COUNT, 2), predicate_urgent(SLOT_COUNT, 1),
  predicate_high(SLOT_COUNT, 2);

  for (int i = 0; i < SLOT_COUNT; i++)
  {
    shipdate[i] = shipdate_message(engine);
    commitdate[i] = commitdate_message(engine);
    receiptdate[i] = receiptdate_message(engine);
    shipmode[i] = shipmode_message(engine);
    orderpriority[i] = orderpriority_message(engine);
  }

  // Create plaintexts
  auto shipdate_ptxt = ctx->MakePackedRadixPlaintext(shipdate);
  auto commitdate_ptxt = ctx->MakePackedRadixPlaintext(commitdate);
  auto receiptdate_ptxt = ctx->MakePackedRadixPlaintext(receiptdate);
  auto predicate_date1_ptxt = ctx->MakePackedRadixPlaintext(predicate_date1);
  auto predicate_date2_ptxt = ctx->MakePackedRadixPlaintext(predicate_date2);
  if (radix <= 2) fparams.SetSegmentCount(2);
  else fparams.SetSegmentCount(1);
  auto shipmode_ptxt = ctx->MakePackedRadixPlaintext(shipmode, fparams);
  auto predicate_mail_ptxt = ctx->MakePackedRadixPlaintext(predicate_mail, fparams);
  auto predicate_ship_ptxt = ctx->MakePackedRadixPlaintext(predicate_ship, fparams);
  auto orderpriority_ptxt = ctx->MakePackedRadixPlaintext(orderpriority, fparams);
  auto predicate_urgent_ptxt = ctx->MakePackedRadixPlaintext(predicate_urgent, fparams);
  auto predicate_high_ptxt = ctx->MakePackedRadixPlaintext(predicate_high, fparams);

  // Encrypt
  auto shipdate_ctxt = ctx->Encrypt(shipdate_ptxt);
  auto commitdate_ctxt = ctx->Encrypt(commitdate_ptxt);
  auto receiptdate_ctxt = ctx->Encrypt(receiptdate_ptxt);
  auto predicate_date1_ctxt = ctx->Encrypt(predicate_date1_ptxt);
  auto predicate_date2_ctxt = ctx->Encrypt(predicate_date2_ptxt);
  auto shipmode_ctxt = ctx->Encrypt(shipmode_ptxt);
  auto orderpriority_ctxt = ctx->Encrypt(orderpriority_ptxt);
  auto predicate_mail_ctxt = ctx->Encrypt(predicate_mail_ptxt);
  auto predicate_ship_ctxt = ctx->Encrypt(predicate_ship_ptxt);
  auto predicate_urgent_ctxt = ctx->Encrypt(predicate_urgent_ptxt);
  auto predicate_high_ctxt = ctx->Encrypt(predicate_high_ptxt);

  auto one_ptxt = cc->MakePackedPlaintext(std::vector<int64_t>(SLOT_COUNT, 1));
  //---------------------------------------------
  // Filtering: l_shipdate <= predicate_value
  // ---------------------------------------------
  double filtering_time = 0, aggregation_time = 0;
  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();

  std::vector<lbcrypto::Ciphertext<DCRTPoly>> pre_res_vec;
  pre_res_vec.push_back(ctx->EvalComp(receiptdate_ctxt, commitdate_ctxt, CompType::GT));
  pre_res_vec.push_back(ctx->EvalComp(commitdate_ctxt, shipdate_ctxt, CompType::GT));
  pre_res_vec.push_back(ctx->EvalComp(receiptdate_ctxt, predicate_date1_ctxt, CompType::GT));
  pre_res_vec.push_back(ctx->EvalComp(receiptdate_ctxt, predicate_date2_ctxt, CompType::LT));

  auto filter_res = cc->EvalMultMany(pre_res_vec);

  auto filter_res_mail = ctx->EvalComp(shipmode_ctxt, predicate_mail_ctxt, CompType::EQ);

  filter_res_mail = cc->EvalMult(filter_res_mail, filter_res);

  auto filter_res_ship = ctx->EvalComp(shipmode_ctxt, predicate_ship_ctxt, CompType::EQ);

  filter_res_ship = cc->EvalMult(filter_res_ship, filter_res);

  auto order_res = ctx->EvalComp(orderpriority_ctxt, predicate_urgent_ctxt, CompType::EQ);

  auto pre_res = ctx->EvalComp(orderpriority_ctxt, predicate_high_ctxt, CompType::EQ);
  end = std::chrono::system_clock::now();

  filtering_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
  std::cout << "filtering time = " << filtering_time << " ms\n";

  start = std::chrono::system_clock::now();
  auto neg_pre_res = cc->EvalNegate(pre_res);
  auto neg_order_res = cc->EvalNegate(order_res);
  neg_pre_res = cc->EvalAdd(neg_pre_res, one_ptxt);
  neg_order_res = cc->EvalAdd(neg_order_res, one_ptxt);

  auto YY_pre_order = cc->EvalMult(pre_res, order_res);
  auto NY_pre_order = cc->EvalMult(pre_res, neg_order_res);
  auto YN_pre_order = cc->EvalMult(neg_pre_res, order_res);
  order_res = cc->EvalAdd(YY_pre_order, NY_pre_order);
  order_res = cc->EvalAdd(order_res, YN_pre_order);

  auto count_mail_order = cc->EvalMult(filter_res_mail, order_res);

  auto count_ship_order = cc->EvalMult(filter_res_ship, order_res);

  auto count_mail = cc->EvalMult(filter_res_mail, filter_res_mail);

  auto count_ship = cc->EvalMult(filter_res_ship, filter_res_ship);

  ctx->EvalSumInPlace(count_mail_order);
  ctx->EvalSumInPlace(count_ship_order);
  ctx->EvalSumInPlace(count_mail);
  ctx->EvalSumInPlace(count_ship);
  end = std::chrono::system_clock::now();

  aggregation_time = std::chrono::duration_cast<std::chrono::microseconds>(end - start).count() / 1000.0;
  std::cout << "aggregation time = " << aggregation_time << " ms\n";

  std::vector<uint64_t> plain_filter_res_mail(SLOT_COUNT, 0), plain_filter_res_ship(SLOT_COUNT, 0), plain_filter_order(SLOT_COUNT, 0);
  std::vector<uint64_t> plain_res_mail_order(SLOT_COUNT, 0), plain_res_ship_order(SLOT_COUNT, 0);
  uint64_t agg_mail_res = 0, agg_mail_order_res = 0, agg_ship_res = 0, agg_ship_order_res = 0;
  bool ress;
  for (size_t i = 0; i < SLOT_COUNT; i++) {
    if (commitdate[i] < receiptdate[i] && shipdate[i] < commitdate[i] &&
      receiptdate[i] > predicate_date1[i] && receiptdate[i] < predicate_date2[i]) {
      ress = true;
    } else {
      ress = false;
    }

    if (orderpriority[i] == 1 || orderpriority[i] == 2) {
      plain_filter_order[i] = 1;
    }

    if (ress && shipmode[i] == 1) {
      plain_filter_res_mail[i] = 1;
      agg_mail_res += 1;
      if (plain_filter_order[i] == 1) {
        plain_res_mail_order[i] = 1;
        agg_mail_order_res += 1;
      }
    }
    if (ress && shipmode[i] == 2) {
      plain_filter_res_ship[i] = 1;
      agg_ship_res += 1;
      if (plain_filter_order[i] == 1) {
        plain_res_ship_order[i] = 1;
        agg_ship_order_res += 1;
      }
    }
  }

  // Check depth consumption
  uint32_t level_consumed_mail = count_mail->GetLevel();
  uint32_t level_consumed_ship = count_ship->GetLevel();
  uint32_t level_consumed_mail_order = count_mail_order->GetLevel();
  uint32_t level_consumed_ship_order = count_ship_order->GetLevel();
  std::cout << "Depth consumed (count_mail): " << level_consumed_mail << ", Remaining depth: " << (mdepth - level_consumed_mail) << "\n";
  std::cout << "Depth consumed (count_ship): " << level_consumed_ship << ", Remaining depth: " << (mdepth - level_consumed_ship) << "\n";
  std::cout << "Depth consumed (count_mail_order): " << level_consumed_mail_order << ", Remaining depth: " << (mdepth - level_consumed_mail_order) << "\n";
  std::cout << "Depth consumed (count_ship_order): " << level_consumed_ship_order << ", Remaining depth: " << (mdepth - level_consumed_ship_order) << "\n";

  Plaintext query_res_mail, query_res_ship, query_res_mail_order, query_res_ship_order;
  cc->Decrypt(keyPair.secretKey, count_mail, &query_res_mail);
  cc->Decrypt(keyPair.secretKey, count_ship, &query_res_ship);
  cc->Decrypt(keyPair.secretKey, count_mail_order, &query_res_mail_order);
  cc->Decrypt(keyPair.secretKey, count_ship_order, &query_res_ship_order);

  query_res_mail->SetLength(1);
  query_res_ship->SetLength(1);
  query_res_mail_order->SetLength(1);
  query_res_ship_order->SetLength(1);

  auto res_mail_dec = query_res_mail->GetPackedValue()[0];
  auto res_ship_dec = query_res_ship->GetPackedValue()[0];
  auto res_mail_order_dec = query_res_mail_order->GetPackedValue()[0];
  auto res_ship_order_dec = query_res_ship_order->GetPackedValue()[0];

  std::cout << "Query Evaluation Time: " << filtering_time + aggregation_time << " ms" << std::endl;
  std::cout << "Encrypted result: " << std::endl;
  std::cout << std::setw(12) << "shipmode" << "|" << std::setw(16) << "high_line_count" << "|" << std::setw(16) << "low_line_count" << std::endl;
  std::cout << std::setw(12) << "MAIL" << "|" << std::setw(16) << res_mail_order_dec << "|" << std::setw(16) << res_mail_dec - res_mail_order_dec << std::endl;
  std::cout << std::setw(12) << "SHIP" << "|" << std::setw(16) << res_ship_order_dec << "|" << std::setw(16) << res_ship_dec - res_ship_order_dec << std::endl;

  std::cout << "Plain result: " << std::endl;
  std::cout << std::setw(12) << "shipmode" << "|" << std::setw(16) << "high_line_count" << "|" << std::setw(16) << "low_line_count" << std::endl;
  std::cout << std::setw(12) << "MAIL" << "|" << std::setw(16) << agg_mail_order_res << "|" << std::setw(16) << agg_mail_res - agg_mail_order_res << std::endl;
  std::cout << std::setw(12) << "SHIP" << "|" << std::setw(16) << agg_ship_order_res << "|" << std::setw(16) << agg_ship_res - agg_ship_order_res << std::endl;

  // Write results to CSV
  write_to_csv("Q12", RingDim, radix, seed, filtering_time, aggregation_time);

  double total = filtering_time + aggregation_time;
  release_crypto_context();
  return {"Q12", radix, filtering_time, aggregation_time, total, total / SLOT_COUNT};
}

// Depth configuration for each radix and query combination
struct DepthConfig {
  uint32_t radix;
  uint32_t depth_q1;   // depth for Query 1
  uint32_t depth_q6;   // depth for Query 6
  uint32_t depth_q12;  // depth for Query 12
};

int main(int argc, char* argv[])
{
  std::cout << "========================================\n";
  std::cout << "TPC-H Benchmark\n";
  std::cout << "========================================\n";

  // Parse command-line arguments
  uint64_t ring_dim = 1 << 16;
  for (int i = 1; i < argc; i++) {
    std::string arg = argv[i];
    if (arg == "--ring-dim" && i + 1 < argc) {
      ring_dim = std::stoull(argv[++i]);
    } else if (arg == "--quick") {
      ring_dim = 1 << 7;
    }
  }
  std::cout << "RingDim = " << ring_dim << std::endl;

  // Define depth configurations for each radix
  // {radix, depth_q1, depth_q6, depth_q12}
  std::vector<DepthConfig> depth_configs = {
    {2, 14, 15, 16},  // radix=2, segment_count=8
    {4, 16, 17, 18},  // radix=4, segment_count=4
    {8, 19, 20, 21},  // radix=8, segment_count=2
  };

  std::vector<uint32_t> radix_configs = {2, 4, 8};
  std::vector<TpchResult> all_results;

  for (const auto& config : depth_configs) {
    std::cout << "\n========================================\n";
    std::cout << "Configuration:\n";
    std::cout << "  RingDim = " << ring_dim << " (" << ring_dim << " slots)\n";
    std::cout << "  Radix = " << config.radix
              << " (segment_count = " << (16/config.radix) << ")\n";
    std::cout << "  Q1 depth = " << config.depth_q1
              << ", Q6 depth = " << config.depth_q6
              << ", Q12 depth = " << config.depth_q12 << "\n";
    std::cout << "========================================\n";

    all_results.push_back(run_q1(ring_dim, config.radix, config.depth_q1));
    all_results.push_back(run_q6(ring_dim, config.radix, config.depth_q6));
    all_results.push_back(run_q12(ring_dim, config.radix, config.depth_q12));
  }

  // ===== Summary Table (matching paper Table 2 / Figure 4) =====
  auto find_result = [&](const std::string& name, uint32_t r) -> const TpchResult* {
    for (const auto& res : all_results)
      if (res.query_name == name && res.radix == r) return &res;
    return nullptr;
  };

  int W = 14;
  int LW = 20;
  auto print_val = [&](double v) {
    std::cout << std::setw(W) << std::fixed << std::setprecision(1) << v;
  };

  for (const std::string& qname : {"Q1", "Q6", "Q12"}) {
    std::cout << "\n========================================\n";
    std::cout << "TPC-H " << qname << " Breakdown (ms). RingDim = " << ring_dim << "\n";
    std::cout << "========================================\n";
    std::cout << std::left << std::setw(LW) << ""
              << std::setw(W) << "APEX (2-bit)"
              << std::setw(W) << "APEX (4-bit)"
              << std::setw(W) << "APEX (8-bit)" << "\n";
    std::cout << std::string(LW + W * 3, '-') << "\n";

    std::cout << std::left << std::setw(LW) << "Filtering";
    for (uint32_t r : radix_configs) { auto* p = find_result(qname, r); print_val(p ? p->filtering_time : 0); }
    std::cout << "\n";

    std::cout << std::left << std::setw(LW) << "Aggregation";
    for (uint32_t r : radix_configs) { auto* p = find_result(qname, r); print_val(p ? p->aggregation_time : 0); }
    std::cout << "\n";

    std::cout << std::left << std::setw(LW) << "Total";
    for (uint32_t r : radix_configs) { auto* p = find_result(qname, r); print_val(p ? p->total_time : 0); }
    std::cout << "\n";

    std::cout << std::left << std::setw(LW) << "Amortized (ms)";
    for (uint32_t r : radix_configs) { auto* p = find_result(qname, r); print_val(p ? p->amortized_total : 0); }
    std::cout << "\n";
  }

  std::cout << "\nBenchmark completed!\n";
  std::cout << "Results written to tpch_results.csv\n";

  return 0;
}
