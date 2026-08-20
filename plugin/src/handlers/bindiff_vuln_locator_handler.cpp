#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_bindiff_vuln_locator_routes(c_http_router& router) {
    router.post("/api/bindiff/compare_versions", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string origBinary = body.value("original", "");
        std::string patchedBinary = body.value("patched", "");
        json result;
        result["original"] = origBinary;
        result["patched"] = patchedBinary;
        result["diffing_methodology"] = {
            {"Graph_Isomorphism", "Compare Control Flow Graphs (CFG) of matching function pairs"},
            {"Basic_Block_Differencing", "Compute instruction sequence edit distance within matched basic blocks"},
            {"Call_Graph_Topology", "Detect added, removed, or re-routed function call edges"},
            {"Mnemonic_Histogram", "Compare opcode frequency distribution to identify algorithm alterations"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/bindiff/locate_security_patches", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["patch_patterns"] = {
            {"Bounds_Check_Insertion", "Addition of CMP / JA / JBE branch before memory copy or array index dereference (Fix for Buffer Overflow)"},
            {"Integer_Overflow_Check", "Addition of JO / JC check following ADD / IMUL operations before allocation"},
            {"Null_Pointer_Validation", "TEST REG, REG; JZ error_handler inserted before struct member dereference"},
            {"Lock_Acquisition", "Addition of EnterCriticalSection / AcquireSRWLockExclusive around shared state access (Fix for Race Condition)"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/bindiff/assess_nday_exploit_surface", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["nday_exploitation_strategy"] = {
            "Reverse engineer the security patch to understand exact input conditions triggering the pre-patch vulnerability",
            "Synthesize proof-of-concept (PoC) triggering unchecked boundary condition in unpatched targets",
            "Assess mitigation bypass requirements (ASLR, DEP, CFG, CET) for weaponized 1-day exploit development"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
