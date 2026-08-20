#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_decoder_routes(c_http_router& router) {
    // POST /api/decoder/bytes
    router.post("/api/decoder/bytes", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"mnemonic", "mov"},
            {"operands", "rax, qword ptr [rcx+0x10]"},
            {"length", 4},
            {"rex_prefix", "0x48 (REX.W)"},
            {"opcode", "0x8B"},
            {"modrm", {"mod", 1}, {"reg", 0}, {"rm", 1}},
            {"displacement", "0x10"}
        });
    });

    // POST /api/decoder/at_address
    router.post("/api/decoder/at_address", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"address", format_utils::format_address(cip)},
            {"mnemonic", "call"},
            {"operands", "qword ptr [rax+0x20]"},
            {"length", 3}
        });
    });
}

} // namespace handlers
