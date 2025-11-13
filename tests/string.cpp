#include <libapex.h>
#include <regex>
#include <iomanip>

using namespace lbcrypto;
using namespace apex;

struct PatternTestCase {
  std::string pattern;
  std::vector<std::string> should_match;
  std::vector<std::string> should_not_match;
};

struct TestResult {
  std::string pattern;
  int segments_count;
  bool passed;
  int64_t duration_ms;
  int total_cases;
  int passed_cases;
  int failed_cases;
};

std::string LikeToRegex(const std::string& pat) {
  static const std::unordered_set<char> regexMeta =
    {'.', '^', '$', '|', '(', ')', '[', ']', '{', '}', '*', '+', '?', '\\'};

  std::string rex;
  rex.reserve(pat.size() * 2 + 2);
  rex.push_back('^');

  for (char c : pat) {
    if (c == '%')       rex.append(".*");
    else if (c == '_')  rex.push_back('.');
    else {
      if (regexMeta.count(c)) rex.push_back('\\');
      rex.push_back(c);
    }
  }
  rex.push_back('$');
  return rex;
}

int count_segments(const std::string& pattern) {
  int count = 1;
  bool in_literal = pattern.size() > 0 && pattern[0] != '%';

  for (size_t i = 1; i < pattern.size(); ++i) {
    if (pattern[i] == '%' && in_literal) {
      in_literal = false;
    } else if (pattern[i] != '%' && !in_literal) {
      in_literal = true;
      count++;
    }
  }

  return in_literal ? count : count - 1;
}

void test_pattern_with_cases(
  ApexContext& ctx,
  CryptoContext<DCRTPoly>& cc,
  KeyPair<DCRTPoly>& keyPair,
  size_t max_length,
  const PatternTestCase& test_case,
  TestResult& result)
{
  result.pattern = test_case.pattern;
  result.segments_count = count_segments(test_case.pattern);
  result.passed = false;
  result.total_cases = test_case.should_match.size() + test_case.should_not_match.size();
  result.passed_cases = 0;
  result.failed_cases = 0;

  const usint SLOT_COUNT = cc->GetRingDimension();

  std::vector<std::string> values;
  std::vector<bool> expected;

  for (const auto& s : test_case.should_match) {
    values.push_back(s);
    expected.push_back(true);
  }

  for (const auto& s : test_case.should_not_match) {
    values.push_back(s);
    expected.push_back(false);
  }

  size_t known_cases = values.size();

  while (values.size() < SLOT_COUNT) {
    size_t idx = values.size() % known_cases;
    values.push_back(values[idx]);
    expected.push_back(expected[idx]);
  }

  StringPlaintext string_ptxt = ctx->MakePackedStringPlaintext(values, max_length);
  auto string_ctxt = ctx->Encrypt(string_ptxt);

  auto pattern = ctx->EncodePattern(test_case.pattern);
  auto enc_pattern = ctx->EncryptPattern(pattern);

  std::cout << "  Testing [" << std::setw(25) << std::left << test_case.pattern << "] "
            << "(" << result.segments_count << " segs, "
            << result.total_cases << " cases)... ";
  std::cout.flush();

  std::chrono::system_clock::time_point start, end;
  start = std::chrono::system_clock::now();

  auto like_result = ctx->EvalLike(string_ctxt, enc_pattern);

  end = std::chrono::system_clock::now();
  result.duration_ms = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

  Plaintext pt_like;
  cc->Decrypt(keyPair.secretKey, like_result, &pt_like);
  const auto& likeVec = pt_like->GetPackedValue();

  bool all_correct = true;
  for (size_t i = 0; i < known_cases; ++i) {
    bool matches = (likeVec[i] == 1);
    if (matches == expected[i]) {
      result.passed_cases++;
    } else {
      result.failed_cases++;
      if (all_correct) {
        std::cout << "FAIL\n";
        std::cerr << "    Failed for case " << i << ": string [" << values[i]
                  << "] expected=" << expected[i] << ", got=" << matches << "\n";
        all_correct = false;
      }
    }
  }

  result.passed = all_correct;

  if (all_correct) {
    std::cout << "PASS (" << result.duration_ms << " ms)\n";
  }
}

void test_string(uint64_t p, uint64_t RingDim, size_t max_length)
{
  std::cout << "\n========================================\n";
  std::cout << "Testing EvalLike with RingDim=" << RingDim << ", max_length=" << max_length << "\n";
  std::cout << "========================================\n";

  CCParams<CryptoContextBGVRNS> parameters;
  parameters.SetPlaintextModulus(p);
  parameters.SetMultiplicativeDepth(30);
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
  ApexContext ctx = MakeApexContext(cc, keyPair.publicKey, fparams);

  std::vector<PatternTestCase> test_cases = {
    // ============ BASIC PATTERNS (1-char segments) ============
    {"a%", {"a", "ab", "abc", "axyz"}, {"b", "ba", "xa"}},
    {"%a", {"a", "ba", "xya", "zzza"}, {"ab", "b", "xyz"}},
    {"%a%", {"a", "xa", "axb", "xax", "bac"}, {"b", "xyz", "def"}},
    {"abc", {"abc"}, {"ab", "abcd", "xabc", "abx", "bc"}},
    {"a%b", {"ab", "axb", "axxxb", "ayzb"}, {"a", "b", "ba", "axc"}},

    // ============ EDGE CASES ============
    // Wildcards only
    {"%", {"a", "abc", "hello", "z"}, {}},
    {"%%", {"a", "abc", "xyz"}, {}},
    {"%%%", {"a", "test", "abc"}, {}},

    // Consecutive wildcards
    {"a%%b", {"ab", "axb", "axxxb"}, {"a", "b", "ba", "abc"}},
    {"%%a%%", {"a", "xa", "aaa", "xax"}, {"b", "xyz"}},

    // Single character
    {"a", {"a"}, {"aa", "ab", "ba", "b"}},
    {"z", {"z"}, {"a", "zz", "az", "za"}},

    // Repeated characters
    {"aa", {"aa"}, {"a", "aaa", "ab", "ba"}},
    {"aaa", {"aaa"}, {"aa", "aaaa", "aab"}},
    {"a%a", {"aa", "axa", "aba"}, {"a", "ab", "ba"}},
    {"a%a%a", {"aaa", "axaxa", "abaca"}, {"aa", "ab", "aab"}},

    // Pattern at boundaries
    {"%abc", {"abc", "xabc", "zzabc"}, {"ab", "abcd", "abcx"}},
    {"abc%", {"abc", "abcx", "abcde"}, {"ab", "xabc", "zabc"}},

    // ============ LONG SEGMENTS (multi-char literals) ============
    // 2-char segments
    {"ab", {"ab"}, {"a", "abc", "aab", "abb", "ba"}},
    {"ab%cd", {"abcd", "abxcd", "abzzcd"}, {"abc", "abcde", "cd", "acd"}},
    {"%ab%cd", {"abcd", "xabcd", "abxcd"}, {"ab", "cd", "abc"}},
    {"ab%cd%", {"abcd", "abcdx", "abxcdz"}, {"abc", "acd"}},

    // 3-char segments
    {"abc%def", {"abcdef", "abcxdef", "abczzzdef"}, {"abc", "def", "abcde", "abcdefg"}},
    {"%abc%def%", {"abcdef", "xabcdefz", "abcxdeff"}, {"abc", "def", "abdef"}},

    // 4-5 char segments
    {"hello", {"hello"}, {"hell", "helloo", "helo", "hhello"}},
    {"hello%world", {"helloworld", "helloxworld"}, {"hello", "world", "helloworl"}},
    {"%hello%world", {"helloworld", "xhelloworld", "helloxworld"}, {"hello", "world"}},

    // Mixed length segments
    {"a%hello", {"ahello", "axhello", "azhello"}, {"hello", "a", "ahell"}},
    {"hello%a", {"helloa", "helloxa", "hellozza"}, {"hello", "a", "helloab"}},
    {"a%hello%b", {"ahellob", "axhellob", "ahelloxb"}, {"ahello", "hellob", "ab"}},
    {"ab%hello%cd", {"abhellocd", "abxhellocd"}, {"abhello", "hellocd", "abcd"}},

    // Long segments with multiple wildcards
    {"abc%def%ghi", {"abcdefghi", "abcxdefghi", "abcdefxghi"}, {"abcdef", "defghi", "abcghi"}},
    {"test%data%end", {"testdataend", "testxdataend"}, {"testdata", "dataend", "testend"}},

    // ============ COMPLEX PATTERNS (many segments) ============
    {"a%b%c", {"abc", "axbc", "abxc", "aybzc"}, {"ab", "ac", "bc", "cba", "abcd"}},
    {"%a%b%c%", {"abc", "xabcx", "xaxbxcx", "zaybzcw"}, {"ab", "acb", "cab"}},
    {"a%b%c%d%e", {"abcde", "axbcde", "abcxde"}, {"abcd", "bcde", "acde", "abce"}},

    // ============ HIGH COMPLEXITY (testing OOM fix) ============
    {"a%b%c%d%e%f", {"abcdef", "axbcdef"}, {"abcde", "bcdef", "abcdefg"}},
    {"a%b%c%d%e%f%g", {"abcdefg", "axbcdefg"}, {"abcdef", "bcdefg", "abcdefgh"}},
    {"a%b%c%d%e%f%g%h", {"abcdefgh", "axbcdefgh"}, {"abcdefg", "hgfedcba", "abcdefghi"}},
    {"a%b%c%d%e%f%g%h%i", {"abcdefghi", "axbcdefghi"}, {"abcdefgh", "bcdefghi"}},
    {"a%b%c%d%e%f%g%h%i%j", {"abcdefghij", "axbcdefghij"}, {"abcdefghi", "bcdefghij"}},

    // ============ UNDERSCORE WILDCARD (_) ============
    {"a_c", {"abc", "axc", "azc"}, {"ac", "abbc", "abcd", "a"}},
    {"_a", {"aa", "ba", "za"}, {"a", "aaa", "ab"}},
    {"a_", {"ab", "az", "aa"}, {"a", "abc"}},
    {"_", {"a", "b", "z"}, {}},
    {"__", {"ab", "xy", "zz"}, {"a", "abc"}},
    {"___", {"abc", "xyz"}, {"ab", "abcd"}},
    {"a_b_c", {"axbyc", "azbzc"}, {"abc", "abcd", "axxbyyc"}},

    // ============ MIXED WILDCARDS (% and _) ============
    {"a_%b", {"axb", "axxb", "ayyyb"}, {"ab", "a", "b"}},
    {"%_a", {"xa", "xya", "zzza"}, {"a"}},
    {"a_b%c", {"axbc", "axbzc", "axbyyc"}, {"abc", "ab", "ac"}},
    {"%_", {"ab", "xyz", "hello"}, {}},
    {"_%", {"abc", "z", "hello"}, {}},
    {"a_%_%b", {"axxyb", "axyb"}, {"ab", "axb"}},

    // ============ BOUNDARY LENGTH TESTS ============
    // Max length = 15
    {"abcdefghijklmno", {"abcdefghijklmno"}, {"abcdefghijklmn", "bcdefghijklmno"}},
    {"%abcdefghijklm", {"abcdefghijklm", "xabcdefghijklm"}, {"abcdefghijklmn"}},
    {"abcdefghijklm%", {"abcdefghijklm", "abcdefghijklmno"}, {"abcdefghijkl"}},

    // ============ EXTREME REPETITION ============
    {"aaaaaaaaaaaaaaa", {"aaaaaaaaaaaaaaa"}, {"aaaaaaaaaaaaaa", "aaaaaaaaaaaaa"}},
    {"a%a%a%a%a%a%a", {"aaaaaaa", "axaxaxaxaxaxa"}, {"aaaaaa", "baaaaaaa", "axaxaxa"}},
    {"%a%a%a%a%a", {"aaaaa", "xaxaxaxaxa", "bababababa"}, {"aaaa", "xaxaxa", "babababa"}},

    // ============ NO-MATCH CORNER CASES ============
    {"xyz%abc", {"xyzabc", "xyzzabc"}, {"xyz", "abc", "abcxyz", "xyabc"}},
    {"notthere", {"notthere"}, {"not", "there", "abc", "nothere"}},
  };

  std::vector<TestResult> results;
  int total_passed = 0;
  int total_failed = 0;

  std::cout << "\n-- Running EvalLike test cases --\n";

  for (const auto& test_case : test_cases) {
    TestResult result;
    test_pattern_with_cases(ctx, cc, keyPair, max_length, test_case, result);
    results.push_back(result);

    if (result.passed) {
      total_passed++;
    } else {
      total_failed++;
    }
  }

  // Print summary
  std::cout << "\n========================================\n";
  std::cout << "Summary:\n";
  std::cout << "  Total patterns tested: " << results.size() << "\n";
  std::cout << "  Passed: " << total_passed << "\n";
  std::cout << "  Failed: " << total_failed << "\n";
  std::cout << "========================================\n";

  // Show performance by complexity
  std::cout << "\nPerformance by complexity:\n";
  std::cout << std::setw(30) << std::left << "Pattern"
            << std::setw(10) << "Segments"
            << std::setw(15) << "Time (ms)"
            << std::setw(10) << "Status" << "\n";
  std::cout << std::string(65, '-') << "\n";

  std::sort(results.begin(), results.end(),
    [](const TestResult& a, const TestResult& b) {
      return a.segments_count < b.segments_count;
    });

  for (const auto& r : results) {
    std::cout << std::setw(30) << std::left << r.pattern
              << std::setw(10) << r.segments_count
              << std::setw(15) << r.duration_ms
              << std::setw(10) << (r.passed ? "PASS" : "FAIL") << "\n";
  }

  std::cout << "\n";
}

int main()
{
  std::cout << "======================================================\n";
  std::cout << "  EvalLike Comprehensive Test Suite\n";
  std::cout << "  Testing EvalLike variants\n";
  std::cout << "======================================================\n";

  test_string(257, 1 << 7, 15);

  std::cout << "\n======================================================\n";
  std::cout << "  All tests completed!\n";
  std::cout << "======================================================\n";

  return 0;
}
