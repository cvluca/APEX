#include <libapex.h>
#include <cryptocontextfactory.h>
#include <ring-params.h>
#include <chrono>
#include <cmath>
#include <iomanip>
#include <iostream>
#include <vector>
#include <fstream>
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

struct PrecisionResult {
    uint32_t precision;
    uint32_t radix;
    uint32_t segmentCount;
    uint64_t slotCount;
    double avgTime;
    double avgTimePerSlot;
    uint32_t finalLevel;
    uint32_t levelConsumed;
    double ciphertextSizeMB;
    std::string comparisonLabel;
};

enum class ComparisonType {
    Greater,
    Equal
};

struct TestCase {
    uint32_t precision;
    uint32_t radix;
    uint32_t depth_greater;
    uint32_t depth_equal;
};

uint32_t calculateSegmentCount(uint32_t precision, uint32_t radix) {
    return (precision + radix - 1) / radix;
}

PrecisionResult runTest(uint32_t precision, uint32_t radix,
                        ComparisonType comparisonType,
                        uint32_t depth,
                        uint64_t RingDim = 1 << 17) {
    PrecisionResult result;
    result.precision = precision;
    result.radix = radix;
    result.avgTimePerSlot = 0.0;
    result.ciphertextSizeMB = 0.0;
    result.comparisonLabel = comparisonType == ComparisonType::Greater ? "greater" : "equal";

    uint32_t B = 1 << radix;
    result.segmentCount = calculateSegmentCount(precision, radix);

    std::cout << "\n=== Testing Precision = " << precision << " bits (B = " << B
              << " = 2^" << radix << ", segments = " << result.segmentCount << ") ===" << std::endl;

    uint64_t p = RingParams::GetPlaintextModulus(RingDim);

    CCParams<CryptoContextBGVRNS> parameters;
    parameters.SetPlaintextModulus(p);
    parameters.SetMultiplicativeDepth(depth);
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
    fparams.SetSegmentCount(result.segmentCount);

    ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);

    const usint SLOT_COUNT = RingDim;
    result.slotCount = SLOT_COUNT;
    int64_t max_value = std::min(static_cast<int64_t>(std::pow(2, precision/2) - 1),
                                 static_cast<int64_t>(1000000));

    std::default_random_engine engine(42);
    std::uniform_int_distribution<int64_t> dist(-max_value, max_value);

    std::vector<int64_t> vecX(SLOT_COUNT), vecY(SLOT_COUNT);
    for (uint32_t i = 0; i < SLOT_COUNT; i++) {
        vecX[i] = dist(engine);
        vecY[i] = dist(engine);
    }

    RadixPlaintext radixX = ctx->MakePackedRadixPlaintext(vecX);
    RadixPlaintext radixY = ctx->MakePackedRadixPlaintext(vecY);
    auto ctX = ctx->Encrypt(radixX);
    auto ctY = ctx->Encrypt(radixY);

    size_t ciphertextBytes = 0;
    for (const auto& segment : ctX->GetSegments()) {
        const auto& elements = segment->GetElements();
        for (const auto& elem : elements) {
            size_t numTowers = elem.GetNumOfElements();
            size_t ringDim = elem.GetLength();
            ciphertextBytes += numTowers * ringDim * sizeof(uint64_t);
        }
    }
    result.ciphertextSizeMB = static_cast<double>(ciphertextBytes) / (1024.0 * 1024.0);

    auto ctDiff = ctx->EvalSub(ctX, ctY);

    auto evaluateComparison = [&](const RadixCiphertext& diff) {
        if (comparisonType == ComparisonType::Greater) {
            return ctx->EvalSign(diff);
        }
        return ctx->EvalZero(diff);
    };

    auto warmupComparison = evaluateComparison(ctDiff);

    const int numRuns = 1;
    std::vector<double> times;

    for (int run = 0; run < numRuns; run++) {
        auto ctDiffCopy = ctx->EvalSub(ctX, ctY);

        auto start = std::chrono::high_resolution_clock::now();
        auto ctComparison = evaluateComparison(ctDiffCopy);
        auto end = std::chrono::high_resolution_clock::now();

        auto duration = std::chrono::duration_cast<std::chrono::microseconds>(end - start);
        times.push_back(duration.count() / 1000.0);

        if (run == 0) {
            result.levelConsumed = ctComparison->GetLevel();
            result.finalLevel = depth - result.levelConsumed;
        }
    }

    double sumTime = 0.0;
    for (double t : times) {
        sumTime += t;
    }
    result.avgTime = sumTime / numRuns;
    result.avgTimePerSlot = result.avgTime / static_cast<double>(SLOT_COUNT);

    double variance = 0.0;
    for (double t : times) {
        variance += (t - result.avgTime) * (t - result.avgTime);
    }
    double stdDev = std::sqrt(variance / numRuns);

    Plaintext decryptedComparison;
    cc->Decrypt(keyPair.secretKey, warmupComparison, &decryptedComparison);

    const auto& comparisonVec = decryptedComparison->GetPackedValue();

    bool correct = true;
    for (size_t i = 0; i < std::min(static_cast<size_t>(10), static_cast<size_t>(SLOT_COUNT)); i++) {
        int64_t expected = 0;
        if (comparisonType == ComparisonType::Greater) {
            expected = (vecX[i] - vecY[i]) > 0 ? 1 : 0;
        } else {
            expected = (vecX[i] - vecY[i]) == 0 ? 1 : 0;
        }

        if (comparisonVec[i] != expected) {
            std::cerr << "Incorrect result at slot " << i << ": expected "
                      << expected << ", got " << comparisonVec[i] << std::endl;
            correct = false;
            break;
        }
    }

    if (!correct) {
        std::cerr << "ERROR: Comparison results are incorrect!" << std::endl;
    }

    std::cout << "Precision: " << precision << " bits" << std::endl;
    std::cout << "B = 2^" << radix << " = " << B << std::endl;
    std::cout << "Segments: " << result.segmentCount << std::endl;
    std::cout << "Comparison: " << result.comparisonLabel << std::endl;
    std::cout << "Average time: " << std::fixed << std::setprecision(3)
              << result.avgTime << " ± " << std::setprecision(3) << stdDev << " ms" << std::endl;
    std::cout << "Average time per slot: " << std::fixed << std::setprecision(6)
              << result.avgTimePerSlot << " ms/slot" << std::endl;
    std::cout << "Depth consumed: " << result.levelConsumed
              << ", Remaining depth: " << result.finalLevel << std::endl;
    std::cout << "Ciphertext size: " << std::fixed << std::setprecision(3)
              << result.ciphertextSizeMB << " MB" << std::endl;

    release_crypto_context();
    return result;
}

void printResults(const std::vector<PrecisionResult>& results, const std::string& label) {
    if (results.empty()) {
        return;
    }

    std::cout << "\n" << std::string(115, '=') << std::endl;
    std::cout << "PRECISION vs LATENCY ANALYSIS RESULTS (" << label << ")" << std::endl;
    std::cout << std::string(115, '=') << std::endl;

    std::cout << std::left
              << std::setw(10) << "Comp"
              << std::setw(8) << "Prec"
              << std::setw(8) << "B=2^r"
              << std::setw(8) << "ℓ"
              << std::setw(10) << "Slots"
              << std::setw(12) << "Time(ms)"
              << std::setw(16) << "Time/Slot(ms)"
              << std::setw(10) << "Consumed"
              << std::setw(10) << "Remaining"
              << std::setw(15) << "CipherSize(MB)"
              << std::endl;
    std::cout << std::string(125, '-') << std::endl;

    for (const auto& result : results) {
        uint32_t B = 1 << result.radix;

        std::cout << std::left
                  << std::setw(10) << result.comparisonLabel
                  << std::setw(8) << result.precision
                  << std::setw(8) << B
                  << std::setw(8) << result.segmentCount
                  << std::setw(10) << result.slotCount
                  << std::setw(12) << std::fixed << std::setprecision(3) << result.avgTime
                  << std::setw(16) << std::fixed << std::setprecision(6) << result.avgTimePerSlot
                  << std::setw(10) << result.levelConsumed
                  << std::setw(10) << result.finalLevel
                  << std::setw(15) << std::fixed << std::setprecision(3) << result.ciphertextSizeMB
                  << std::endl;
    }

    std::cout << "\n" << std::string(115, '=') << std::endl;
    std::cout << "ANALYSIS SUMMARY:" << std::endl;
    std::cout << "- Prec: Precision in bits" << std::endl;
    std::cout << "- B=2^r: Segment base (B = 2^radix, where radix is bits per segment)" << std::endl;
    std::cout << "- ℓ: Number of segments" << std::endl;
    std::cout << "- Consumed: Multiplicative depth consumed by comparison" << std::endl;
    std::cout << "- Remaining: Remaining multiplicative depth after comparison" << std::endl;
    std::cout << "- Time/Slot(ms): Average latency per packed slot (milliseconds per comparison)" << std::endl;
    std::cout << std::string(115, '=') << std::endl;
}

void exportToCSV(const std::vector<PrecisionResult>& results, const std::string& filename) {
    if (results.empty()) {
        std::cerr << "Warning: No results to export for " << filename << std::endl;
        return;
    }

    std::ofstream file(filename);
    if (!file.is_open()) {
        std::cerr << "Error: Could not open file " << filename << std::endl;
        return;
    }

    file << "comparison_type,precision,radix,segment_base_B,segment_count,slot_count,avg_time_ms,avg_time_per_slot_ms,level_consumed,remaining_depth,ciphertext_size_mb" << std::endl;

    for (const auto& result : results) {
        uint32_t B = 1 << result.radix;
        file << result.comparisonLabel << "," << result.precision << "," << result.radix << "," << B << "," << result.segmentCount << "," << result.slotCount << ","
             << std::fixed << std::setprecision(6) << result.avgTime << ","
             << std::fixed << std::setprecision(6) << result.avgTimePerSlot << ","
             << result.levelConsumed << "," << result.finalLevel << "," << std::fixed << std::setprecision(6) << result.ciphertextSizeMB << std::endl;
    }

    file.close();
    std::cout << "Results exported to " << filename << std::endl;
}

int main(int argc, char* argv[]) {
    std::cout << "Precision vs Latency Analysis for Homomorphic Comparisons" << std::endl;
    std::cout << "Testing RAHC performance across different precision levels" << std::endl;

    uint64_t RingDim = 1 << 16;
    for (int i = 1; i < argc; i++) {
        std::string arg = argv[i];
        if (arg == "--ring-dim" && i + 1 < argc) {
            RingDim = std::stoull(argv[++i]);
        } else if (arg == "--quick") {
            RingDim = 1 << 7;
        }
    }
    std::cout << "RingDim = " << RingDim << std::endl;

    std::vector<TestCase> testCases = {
        {8, 2, 9, 7},
        {8, 4, 9, 8},
        {8, 8, 13, 11},
        {16, 2, 9, 8},
        {16, 4, 11, 9},
        {16, 8, 14, 12},
        {20, 2, 10, 9},
        {20, 4, 11, 10},
        {20, 8, 15, 13},
        {32, 2, 10, 9},
        {32, 4, 11, 10},
        {32, 8, 16, 13},
        {64, 2, 11, 10},
        {64, 4, 12, 11},
        {64, 8, 16, 14}
    };

    std::vector<PrecisionResult> greaterResults;
    std::vector<PrecisionResult> equalResults;
    std::vector<PrecisionResult> allResults;

    for (const auto& testCase : testCases) {
        uint32_t precision = testCase.precision;
        uint32_t radix = testCase.radix;
        uint32_t depth_greater = testCase.depth_greater;
        uint32_t depth_equal = testCase.depth_equal;

        try {
            PrecisionResult greaterResult =
                runTest(precision, radix, ComparisonType::Greater, depth_greater, RingDim);
            greaterResults.push_back(greaterResult);
            allResults.push_back(greaterResult);
        } catch (const std::exception& e) {
            std::cerr << "Error in experiment with precision=" << precision
                      << ", radix=" << radix << " (greater): " << e.what() << std::endl;
        }

        try {
            PrecisionResult equalResult =
                runTest(precision, radix, ComparisonType::Equal, depth_equal, RingDim);
            equalResults.push_back(equalResult);
            allResults.push_back(equalResult);
        } catch (const std::exception& e) {
            std::cerr << "Error in experiment with precision=" << precision
                      << ", radix=" << radix << " (equal): " << e.what() << std::endl;
        }
    }

    if (!greaterResults.empty()) {
        printResults(greaterResults, "greater");
    }

    if (!equalResults.empty()) {
        printResults(equalResults, "equal");
    }

    if (!allResults.empty()) {
        exportToCSV(allResults, "comparison_results.csv");
    }

    if (allResults.empty()) {
        std::cerr << "No successful experiments completed!" << std::endl;
        return 1;
    }

    return 0;
}
