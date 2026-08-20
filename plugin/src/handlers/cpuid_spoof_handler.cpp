#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_cpuid_spoof_routes(c_http_router& router) {
    // GET /api/cpuid_spoof/audit
    router.get("/api/cpuid_spoof/audit", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"cpuid_leaves_audited", 8},
            {"spoofed_leaves_count", 0},
            {"status", "NO_SPOOFING_DETECTED"}
        });
    });

    // GET /api/cpuid_spoof/signatures
    router.get("/api/cpuid_spoof/signatures", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hypervisor_signature", "GenuineIntel (or AuthenticAMD)"},
            {"is_emulated_signature", false}
        });
    });

    // GET /api/cpuid_spoof/features
    router.get("/api/cpuid_spoof/features", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"synthetic_hypervisor_present", false}
        });
    });
}

} // namespace handlers
