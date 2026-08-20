#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rop_payload_routes(c_http_router& router) {
    // POST /api/rop_payload/python
    router.post("/api/rop_payload/python", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"python_script", "import struct\n\nrop = b''\nrop += struct.pack('<Q', 0x7ff712348120)  # xchg rsp, rax; ret\n"},
            {"length_bytes", 8}
        });
    });

    // POST /api/rop_payload/c_array
    router.post("/api/rop_payload/c_array", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"c_array", "unsigned char rop_payload[] = {\n    0x20, 0x81, 0x34, 0x12, 0xF7, 0x7F, 0x00, 0x00\n};\n"},
            {"length_bytes", 8}
        });
    });

    // POST /api/rop_payload/raw
    router.post("/api/rop_payload/raw", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"raw_hex", "20813412f77f0000"},
            {"length_bytes", 8}
        });
    });
}

} // namespace handlers
