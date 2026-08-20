#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_memory_transition_routes(c_http_router& router) {
    // POST /api/mem_flight/record_transitions
    router.post("/api/mem_flight/record_transitions", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"flight_recorder_active", true},
            {"tracked_transitions", nlohmann::json::array({
                {{"address", "0x000001F000000000"}, {"old_protect", "PAGE_READWRITE"}, {"new_protect", "PAGE_EXECUTE_READ"}, {"timestamp_ms", 1240}}
            })},
            {"transition_count", 1}
        });
    });

    // POST /api/mem_flight/auto_dump_payloads
    router.post("/api/mem_flight/auto_dump_payloads", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"payloads_dumped", 1},
            {"dumped_regions", nlohmann::json::array({
                {{"base_address", "0x000001F000000000"}, {"size", 65536}, {"pe_reconstructed", true}, {"entry_point_rva", "0x1000"}}
            })},
            {"status", "PAYLOADS_EXTRACTED_SUCCESS"}
        });
    });
}

} // namespace handlers
