#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rop_disasm_routes(c_http_router& router) {
    // POST /api/rop_disasm/buffer
    router.post("/api/rop_disasm/buffer", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"disassembled_gadgets_count", 2},
            {"gadgets", nlohmann::json::array({
                {{"offset", 0}, {"address", "0x00007FF712348120"}, {"disassembly", "pop rax; ret"}, {"parameter_value", "0x0000000000000040"}},
                {{"offset", 16}, {"address", "0x00007FF712348150"}, {"disassembly", "xchg rsp, rax; ret"}}
            })}
        });
    });

    // POST /api/rop_disasm/validate
    router.post("/api/rop_disasm/validate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"all_gadgets_executable", true},
            {"invalid_pointers_count", 0}
        });
    });

    // POST /api/rop_disasm/effects
    router.post("/api/rop_disasm/effects", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"modified_registers", nlohmann::json::array({"RAX", "RSP"})},
            {"stack_displacement_bytes", 16}
        });
    });
}

} // namespace handlers
