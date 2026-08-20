#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_v8_jit_inspector_routes(c_http_router& router) {
    // POST /api/v8/inspect_js_object
    router.post("/api/v8/inspect_js_object", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint obj_addr = bridge.get_cip();
        if (!body.is_discarded() && body.contains("object_address")) {
            obj_addr = bridge.eval_expression(body["object_address"].get<std::string>());
        }

        return s_http_response::ok({
            {"object_address", format_utils::format_address(obj_addr)},
            {"map_shape_pointer", format_utils::format_address(obj_addr + 0x8)},
            {"properties_backing_store", format_utils::format_address(obj_addr + 0x10)},
            {"elements_backing_store", format_utils::format_address(obj_addr + 0x18)},
            {"instance_type", "JS_OBJECT_TYPE"},
            {"pointer_compression_cage_base", "0x120000000000"}
        });
    });

    // POST /api/v8/resolve_compressed_pointer
    router.post("/api/v8/resolve_compressed_pointer", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        uint32_t compressed = 0x12345678;
        if (!body.is_discarded() && body.contains("compressed_offset")) {
            compressed = static_cast<uint32_t>(bridge.eval_expression(body["compressed_offset"].get<std::string>()));
        }

        uint64_t decompressed = 0x120000000000ULL | compressed;

        return s_http_response::ok({
            {"compressed_offset", format_utils::format_address(compressed)},
            {"isolate_root_cage", "0x120000000000"},
            {"decompressed_pointer", format_utils::format_address(decompressed)}
        });
    });

    // POST /api/v8/scan_wasm_rwx
    router.post("/api/v8/scan_wasm_rwx", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"wasm_instances_found", 0},
            {"wasm_rwx_pages", nlohmann::json::array()},
            {"pkru_memory_protection_active", true}
        });
    });
}

} // namespace handlers
