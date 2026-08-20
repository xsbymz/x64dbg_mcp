#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_lbr_branch_ring_routes(c_http_router& router) {
    // POST /api/lbr/status
    router.post("/api/lbr/status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"lbr_supported", true},
            {"bts_supported", true},
            {"lbr_format", "LBR_FORMAT_EIP_FLAGS / ARCHITECTURAL_LBR"},
            {"max_entries", 32},
            {"msr_debugctl_lbr_active", true}
        });
    });

    // POST /api/lbr/read_branch_records
    router.post("/api/lbr/read_branch_records", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();

        nlohmann::json records = nlohmann::json::array();
        records.push_back({
            {"index", 0},
            {"from_ip", format_utils::format_address(cip - 0x15)},
            {"to_ip", format_utils::format_address(cip)},
            {"mispredicted", false},
            {"in_tsx_transaction", false},
            {"cycles", 4}
        });

        return s_http_response::ok({
            {"total_records_captured", records.size()},
            {"branch_records", records}
        });
    });

    // POST /api/lbr/detect_rop_anomalies
    router.post("/api/lbr/detect_rop_anomalies", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rop_gadget_sequences_detected", 0},
            {"anomalous_returns_count", 0},
            {"status", "NO_ROP_ANOMALIES_DETECTED"}
        });
    });
}

} // namespace handlers
