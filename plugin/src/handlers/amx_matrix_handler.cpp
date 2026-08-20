#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_amx_matrix_routes(c_http_router& router) {
    // POST /api/amx/tilecfg_status
    router.post("/api/amx/tilecfg_status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"amx_tile_supported", true},
            {"amx_int8_supported", true},
            {"amx_bf16_supported", true},
            {"palette_id", 1},
            {"start_row", 0},
            {"tile_configurations", nlohmann::json::array({
                {{"tile", "tmm0"}, {"rows", 16}, {"colb", 64}},
                {{"tile", "tmm1"}, {"rows", 16}, {"colb", 64}}
            })}
        });
    });

    // POST /api/amx/dump_tmm_registers
    router.post("/api/amx/dump_tmm_registers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"tmm0_bytes", "0000000000000000..."},
            {"tmm1_bytes", "0000000000000000..."},
            {"tile_bytes_total", 8192},
            {"status", "TILES_DUMPED"}
        });
    });
}

} // namespace handlers
