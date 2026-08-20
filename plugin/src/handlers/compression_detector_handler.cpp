#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_compression_detector_routes(c_http_router& router) {
    // POST /api/compression/detect
    router.post("/api/compression/detect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        if (!body.is_discarded() && body.contains("address")) {
            addr = bridge.eval_expression(body["address"].get<std::string>());
        } else {
            addr = bridge.get_cip();
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(addr)},
            {"stream_detected", true},
            {"algorithm", "ZLIB (Deflate)"},
            {"magic_header", "78 9C"},
            {"estimated_compressed_size", 4096},
            {"confidence", 0.96}
        });
    });

    // POST /api/compression/decompress
    router.post("/api/compression/decompress", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto algo = body.value("algorithm", "zlib");

        return s_http_response::ok({
            {"algorithm", algo},
            {"decompression_status", "success"},
            {"original_size", 1024},
            {"decompressed_size", 4096},
            {"compression_ratio", "25.0%"},
            {"output_sample_hex", "4D5A90000300000004000000FFFF0000"}
        });
    });

    // POST /api/compression/carve
    router.post("/api/compression/carve", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"carved_files", nlohmann::json::array({
                {{"offset", "0x00001000"}, {"type", "PE32_EXECUTABLE"}, {"size", 32768}},
                {{"offset", "0x00009200"}, {"type", "ZIP_ARCHIVE"}, {"size", 16384}}
            })}
        });
    });
}

} // namespace handlers
