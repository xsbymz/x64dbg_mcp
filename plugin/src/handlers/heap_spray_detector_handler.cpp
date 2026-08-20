#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_heap_spray_detector_routes(c_http_router& router) {
    router.post("/api/heap_spray/scan_all_heaps", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["classic_spray_targets"] = {
            {"0x0C0C0C0C", "Classic 32-bit browser exploit spray target (192 MB spray)"},
            {"0x0D0D0D0D", "Alternative 32-bit target address"},
            {"0x20202020", "Common ASCII/UTF-16 safe pointer target"},
            {"0x0000000020000000", "64-bit low-memory heap spray target"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/heap_spray/detect_spray_patterns", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["spray_pattern_heuristics"] = {
            "1. Repetitive 4-byte or 8-byte DWORD/QWORD repeating patterns spanning > 1 MB continuous allocations",
            "2. High NOP sled density: long sequences of 0x90 (NOP), 0x41 (INC ECX), 0x0C 0x0C (OR AL, 0x0C)",
            "3. ROP gadget chains interleaved with sled padding bytes",
            "4. JavaScript TypedArray / ArrayBuffer spraying (Uint32Array repeating patterns in V8/Chakra heap)"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/heap_spray/calculate_shellcode_density", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["metric_definition"] = "Ratio of valid x86/x64 instruction sequences vs pure data within large committed heap blocks. High executable instruction density with Shannon entropy between 5.5 and 7.2 indicates sprayed shellcode payload.";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
