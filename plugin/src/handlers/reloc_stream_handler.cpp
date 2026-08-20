#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_reloc_stream_routes(c_http_router& router) {
    // POST /api/reloc_stream/all
    router.post("/api/reloc_stream/all", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"total_blocks", 14},
            {"total_relocations", 512}
        });
    });

    // POST /api/reloc_stream/page
    router.post("/api/reloc_stream/page", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"page_rva", "0x1000"},
            {"relocations_count", 32}
        });
    });

    // POST /api/reloc_stream/types
    router.post("/api/reloc_stream/types", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"IMAGE_REL_BASED_DIR64", 512},
            {"IMAGE_REL_BASED_ABSOLUTE", 4}
        });
    });
}

} // namespace handlers
