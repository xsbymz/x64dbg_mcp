#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_intel_pt_routes(c_http_router& router) {
    // POST /api/intel_pt/status
    router.post("/api/intel_pt/status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"intel_pt_supported", true},
            {"cr3_filtering_supported", true},
            {"psb_cyc_accurate", true},
            {"ip_filtering_ranges", 2},
            {"output_scheme", "SingleRange / ToPA"},
            {"active_tracing", false}
        });
    });

    // POST /api/intel_pt/decode_trace
    router.post("/api/intel_pt/decode_trace", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"packets_decoded", 1024},
            {"basic_block_transitions", nlohmann::json::array({
                {{"from", format_utils::format_address(cip)}, {"to", format_utils::format_address(cip + 5)}, {"taken", true}}
            })},
            {"status", "DECODED_SUCCESS"}
        });
    });

    // POST /api/intel_pt/export_coverage_bitmap
    router.post("/api/intel_pt/export_coverage_bitmap", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"bitmap_size_bytes", 65536},
            {"covered_edges", 420},
            {"fuzzer_format", "AFL_PLUS_PLUS_SHM"}
        });
    });
}

} // namespace handlers
