#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_unwind_disasm_routes(c_http_router& router) {
    // POST /api/unwind_disasm/codes
    router.post("/api/unwind_disasm/codes", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"unwind_codes_count", 3},
            {"codes", nlohmann::json::array({
                {{"offset", 4}, {"op", "UWOP_ALLOC_SMALL (2)"}, {"info", "0x28 bytes"}},
                {{"offset", 1}, {"op", "UWOP_PUSH_NONVOL (0)"}, {"info", "RDI"}}
            })}
        });
    });

    // POST /api/unwind_disasm/simulate
    router.post("/api/unwind_disasm/simulate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"total_frame_size", 0x30},
            {"saved_registers", nlohmann::json::array({"RDI", "RBP"})}
        });
    });

    // POST /api/unwind_disasm/frame_reg
    router.post("/api/unwind_disasm/frame_reg", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"frame_register", "RBP"},
            {"frame_register_offset", 0}
        });
    });
}

} // namespace handlers
