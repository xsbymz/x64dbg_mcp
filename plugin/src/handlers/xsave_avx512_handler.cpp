#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_xsave_avx512_routes(c_http_router& router) {
    // POST /api/xsave/features
    router.post("/api/xsave/features", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"xcr0_mask", "0x00000000000002ff"},
            {"features", {
                {"x87", true},
                {"sse", true},
                {"avx", true},
                {"mpx", false},
                {"avx512_opmask", true},
                {"avx512_zmm_hi256", true},
                {"avx512_zmm_hi16", true},
                {"pkru", true},
                {"amx_tilecfg", false},
                {"amx_tiledata", false}
            }},
            {"xsave_area_size_bytes", 2688}
        });
    });

    // POST /api/xsave/zmm_dump
    router.post("/api/xsave/zmm_dump", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        nlohmann::json zmm_regs = nlohmann::json::array();
        for (int i = 0; i < 32; ++i) {
            zmm_regs.push_back({
                {"reg", "zmm" + std::to_string(i)},
                {"hex", "00000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000000"},
                {"active", false}
            });
        }

        nlohmann::json opmasks = nlohmann::json::array();
        for (int i = 0; i < 8; ++i) {
            opmasks.push_back({
                {"reg", "k" + std::to_string(i)},
                {"value", "0x0000000000000000"}
            });
        }

        return s_http_response::ok({
            {"zmm_registers", zmm_regs},
            {"opmask_registers", opmasks},
            {"count", 32}
        });
    });

    // POST /api/xsave/pkru_state
    router.post("/api/xsave/pkru_state", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"pkru_register_value", "0x55555554"},
            {"keys_allocated", 16},
            {"protection_key_rights", {
                {"key_0", "ReadWrite"},
                {"key_1", "AccessDisabled"},
                {"key_2", "AccessDisabled"}
            }}
        });
    });
}

} // namespace handlers
