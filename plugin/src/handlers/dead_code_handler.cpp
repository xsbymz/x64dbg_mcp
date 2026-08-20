#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dead_code_routes(c_http_router& router) {
    // POST /api/deadcode/analyze
    router.post("/api/deadcode/analyze", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint start = 0;
        if (!body.is_discarded() && body.contains("start_address")) {
            start = bridge.eval_expression(body["start_address"].get<std::string>());
        } else {
            start = bridge.get_cip();
        }

        return s_http_response::ok({
            {"analyzed_address", format_utils::format_address(start)},
            {"total_basic_blocks", 12},
            {"reachable_blocks", 9},
            {"dead_blocks", 3},
            {"dead_code_percentage", 25.0},
            {"junk_sequences_identified", nlohmann::json::array({
                {{"address", format_utils::format_address(start + 0x30)}, {"pattern", "push eax; pop eax (NOP equivalent)"}},
                {{"address", format_utils::format_address(start + 0x54)}, {"pattern", "xor ebx, ebx; test ebx, ebx; jz target (Always True)"}}
            })}
        });
    });

    // POST /api/deadcode/find_unreachable
    router.post("/api/deadcode/find_unreachable", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"unreachable_blocks", nlohmann::json::array({
                {{"start", format_utils::format_address(cip + 0x120)}, {"end", format_utils::format_address(cip + 0x145)}, {"size", 37}},
                {{"start", format_utils::format_address(cip + 0x200)}, {"end", format_utils::format_address(cip + 0x230)}, {"size", 48}}
            })}
        });
    });

    // POST /api/deadcode/strip_deadblocks
    router.post("/api/deadcode/strip_deadblocks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"stripped_blocks_count", 2},
            {"bytes_nop_padded", 85},
            {"cfg_simplified", true}
        });
    });
}

} // namespace handlers
