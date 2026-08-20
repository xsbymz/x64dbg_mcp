#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_rng_entropy_tester_routes(c_http_router& router) {
    router.post("/api/rng/collect_samples", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD sampleSize = body.value("sample_size", (DWORD)4096);
        json result;
        result["sample_size"] = sampleSize;
        result["rng_sources"] = {
            {"BCryptGenRandom", "Modern Windows CNG Fortuna-based PRNG (preferred)"},
            {"CryptGenRandom", "Legacy CryptoAPI PRNG backed by Advapi32.dll"},
            {"RDRAND", "Intel/AMD on-chip hardware RNG instruction (0x0F 0xC7 /6)"},
            {"RDSEED", "Intel/AMD physical thermal noise entropy instruction (0x0F 0xC7 /7)"},
            {"C_rand", "Standard C runtime linear congruential generator (Insecure, easily predicted)"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/rng/run_nist_tests", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["nist_sp800_22_statistical_tests"] = {
            {"Frequency_Monobit_Test", "Verifies proportion of 0s and 1s in bitstream matches theoretical 0.5"},
            {"Block_Frequency_Test", "Tests uniformity of 1s proportion within fixed-length sub-blocks"},
            {"Runs_Test", "Analyzes total number of uninterrupted sequences of identical bits"},
            {"Longest_Run_Of_Ones", "Measures maximum run of 1s in M-bit blocks"},
            {"Discrete_Fourier_Transform", "Detects periodic features and repeating patterns in the bit sequence"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/rng/detect_weak_prng", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["vulnerable_rng_patterns"] = {
            {"Time_Based_Seed", "srand(time(NULL)) seeded PRNG enables brute-force cracking within seconds"},
            {"Static_Seed", "Hardcoded seed constant resulting in deterministic token / key generation"},
            {"Biased_RDRAND", "Hardware backdoors or broken microcode producing biased entropy output"}
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
