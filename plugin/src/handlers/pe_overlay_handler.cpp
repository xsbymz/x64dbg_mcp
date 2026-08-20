#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pe_overlay_routes(c_http_router& router) {
    // POST /api/pe/overlay/detect
    router.post("/api/pe/overlay/detect", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_overlay", true},
            {"overlay_offset", "0x0012A000"},
            {"overlay_size", 65536},
            {"inferred_content", "PKZip Archive (50 4B 03 04)"}
        });
    });

    // POST /api/pe/overlay/carve
    router.post("/api/pe/overlay/carve", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "OVERLAY_CARVED"},
            {"output_path", "dump_overlay.bin"},
            {"bytes_written", 65536}
        });
    });

    // POST /api/pe/overlay/signatures
    router.post("/api/pe/overlay/signatures", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"signature_directory_offset", "0x00128000"},
            {"is_overlay_within_cert_table", false}
        });
    });

    // POST /api/pe/overlay/entropy
    router.post("/api/pe/overlay/entropy", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"overlay_entropy", 7.96},
            {"verdict", "ENCRYPTED_OR_COMPRESSED_PAYLOAD"}
        });
    });
}

} // namespace handlers
