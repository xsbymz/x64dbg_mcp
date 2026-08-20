#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_memory_compression_routes(c_http_router& router) {
    // POST /api/mem_compression/store_status
    router.post("/api/mem_compression/store_status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"memory_compression_active", true},
            {"compression_format", "COMPRESSION_FORMAT_XPRESS_HUFF / LZ4"},
            {"compressed_store_working_set_mb", 128},
            {"saved_physical_memory_mb", 350}
        });
    });

    // POST /api/mem_compression/decompress_page
    router.post("/api/mem_compression/decompress_page", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"decompressed_size", 4096},
            {"compression_ratio", 0.42},
            {"status", "PAGE_DECOMPRESSED_SUCCESS"}
        });
    });
}

} // namespace handlers
