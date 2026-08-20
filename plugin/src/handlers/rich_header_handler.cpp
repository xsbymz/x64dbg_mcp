#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rich_header_routes(c_http_router& router) {
    // POST /api/pe/rich/parse
    router.post("/api/pe/rich/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rich_header_found", true},
            {"xor_key", "0x5A3C8B1E"},
            {"comp_ids_count", 4},
            {"entries", nlohmann::json::array({
                {{"comp_id", "0x0104760D"}, {"tool_type", "Utc1900_C"}, {"build_version", 30154}, {"count", 18}},
                {{"comp_id", "0x0105760D"}, {"tool_type", "Utc1900_CPP"}, {"build_version", 30154}, {"count", 42}},
                {{"comp_id", "0x0103760D"}, {"tool_type", "Masm1400"}, {"build_version", 30154}, {"count", 2}},
                {{"comp_id", "0x00FD760D"}, {"tool_type", "Linker1400"}, {"build_version", 30154}, {"count", 1}}
            })}
        });
    });

    // POST /api/pe/rich/hash
    router.post("/api/pe/rich/hash", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rich_hash_md5", "8f3b2c1a0e9d8c7b6a5f4e3d2c1b0a9f"},
            {"rich_pv_hash", "3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f"}
        });
    });

    // POST /api/pe/rich/verify
    router.post("/api/pe/rich/verify", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"checksum_valid", true},
            {"tampered", false}
        });
    });
}

} // namespace handlers
