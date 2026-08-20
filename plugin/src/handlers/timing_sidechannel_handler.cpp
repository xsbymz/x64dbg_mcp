#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_timing_sidechannel_routes(c_http_router& router) {
    router.post("/api/timing_side/find_rdtsc_checks", [](const s_http_request& req) {
        json result;
        result["timing_instructions"] = {
            {"RDTSC", "0x0F 0x31 (Reads Time Stamp Counter into EDX:EAX)"},
            {"RDTSCP", "0x0F 0x01 0xF9 (Serializing read with IA32_TSC_AUX processor ID in ECX)"},
            {"CPUID_RDTSC", "CPUID sequence before RDTSC to prevent out-of-order execution"},
            {"RDPMC", "0x0F 0x33 (Reads Performance Monitoring Counters for microarchitectural profiling)"}
        };
        result["anti_debug_threshold"] = "Delta between consecutive RDTSC calls > 10,000 cycles indicates debugger single-stepping or kernel breakpoint interruption";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/timing_side/profile_pmc_usage", [](const s_http_request& req) {
        json result;
        result["performance_counter_threats"] = {
            {"L1D_Cache_Miss_Profiling", "Measures cache latency to detect hardware virtualization / hypervisor VMEXIT"},
            {"Branch_Mispredict_Counting", "Profiles speculative execution paths for side-channel key extraction"},
            {"TLB_Invalidation_Timing", "Detects shadow page tables and EPT page fault overhead"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/timing_side/detect_cache_timing_checks", [](const s_http_request& req) {
        json result;
        result["cache_attacks"] = {
            {"Flush_Reload", "Uses CLFLUSH instruction on shared DLL page, waits, measures reload latency (L3 cache hit = 40 cycles, RAM miss = 200+ cycles)"},
            {"Prime_Probe", "Fills cache sets and measures eviction to determine victim memory access patterns"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

