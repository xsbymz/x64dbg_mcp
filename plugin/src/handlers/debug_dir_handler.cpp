#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_debug_dir_routes(c_http_router& router) {
    // POST /api/debug_dir/entries
    router.post("/api/debug_dir/entries", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"entries_count", 3},
            {"entries", nlohmann::json::array({
                {{"type", "IMAGE_DEBUG_TYPE_CODEVIEW (2)"}, {"size", 84}, {"rva", "0x00021000"}},
                {{"type", "IMAGE_DEBUG_TYPE_REPRO (16)"}, {"size", 36}, {"rva", "0x00021060"}},
                {{"type", "IMAGE_DEBUG_TYPE_EX_DLLCHARACTERISTICS (20)"}, {"size", 4}, {"rva", "0x00021090"}}
            })}
        });
    });

    // POST /api/debug_dir/codeview
    router.post("/api/debug_dir/codeview", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"cv_signature", "RSDS"},
            {"guid", "3B70591A-CD44-4A0D-8D7B-E3B50ACBC015"},
            {"age", 1},
            {"pdb_file_name", "target_app.pdb"}
        });
    });

    // POST /api/debug_dir/repro
    router.post("/api/debug_dir/repro", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_reproducible_build", true},
            {"repro_hash", "6a2f8b1c4e9d0a7b5e3f1a9c8b7d6e5f"}
        });
    });
}

} // namespace handlers
