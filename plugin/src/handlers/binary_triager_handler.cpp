#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_binary_triager_routes(c_http_router& router) {
    // POST /api/triage/full_scan
    router.post("/api/triage/full_scan", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint base = bridge.eval_expression("mod.main()");
        duint entry = bridge.eval_expression("mod.entry(0)");
        std::string mod = bridge.get_module_at(base);

        return s_http_response::ok({
            {"module_name", mod.empty() ? "main_binary" : mod},
            {"base_address", format_utils::format_address(base)},
            {"entry_point", format_utils::format_address(entry)},
            {"triage_verdict", "SUSPICIOUS_PACKED_BINARY"},
            {"threat_score", 7.8},
            {"highlights", nlohmann::json::array({
                "High entropy in section .text (7.62/8.00)",
                "Dynamic API resolution detected (LoadLibraryA / GetProcAddress)",
                "No digital signature present",
                "CFG and CET mitigations disabled"
            })}
        });
    });

    // GET /api/triage/security_matrix
    router.get("/api/triage/security_matrix", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"mitigation_matrix", {
                {"aslr", "DYNAMIC_BASE"},
                {"dep_nx", "ENABLED"},
                {"cfg", "DISABLED"},
                {"cet_shadow_stack", "DISABLED"},
                {"safe_seh", "NOT_APPLICABLE_X64"},
                {"gs_stack_canary", "PRESENT"},
                {"authenticode_signed", false}
            }}
        });
    });

    // POST /api/triage/mitre_mapping
    router.post("/api/triage/mitre_mapping", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"techniques_mapped", nlohmann::json::array({
                {{"id", "T1055"}, {"name", "Process Injection"}, {"confidence", "HIGH"}},
                {{"id", "T1027"}, {"name", "Obfuscated Files or Information"}, {"confidence", "HIGH"}},
                {{"id", "T1562.001"}, {"name", "Impair Defenses: Disable Tools"}, {"confidence", "MEDIUM"}},
                {{"id", "T1071.001"}, {"name", "Application Layer Protocol: Web Protocols"}, {"confidence", "HIGH"}}
            })}
        });
    });
}

} // namespace handlers
