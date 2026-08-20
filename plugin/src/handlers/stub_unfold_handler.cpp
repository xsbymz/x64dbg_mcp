#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_stub_unfold_routes(c_http_router& router) {
    // POST /api/stub_unfold/unfold
    router.post("/api/stub_unfold/unfold", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"unfolded_stubs_count", 1},
            {"stubs", nlohmann::json::array({
                {{"source", "0x00007FF712341000"}, {"pattern", "push rax; ret"}, {"target_resolved", "0x00007FF712342500"}}
            })}
        });
    });

    // POST /api/stub_unfold/push_ret
    router.post("/api/stub_unfold/push_ret", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"resolved_destination", "0x00007FF712342500"},
            {"intermediate_hops", 1}
        });
    });

    // POST /api/stub_unfold/opaque_jumps
    router.post("/api/stub_unfold/opaque_jumps", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"opaque_jump_eliminated", true},
            {"final_target", "0x00007FF712343000"}
        });
    });
}

} // namespace handlers
