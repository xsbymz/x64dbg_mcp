#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_clr_jit_routes(c_http_router& router) {
    // GET /api/clr_jit/heaps
    router.get("/api/clr_jit/heaps", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"jit_code_heaps_count", 1},
            {"heaps", nlohmann::json::array({
                {{"base", "0x00007FFB91000000"}, {"size", 0x100000}, {"type", "EEJitManager_CodeHeap"}}
            })}
        });
    });

    // GET /api/clr_jit/allocations
    router.get("/api/clr_jit/allocations", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_jitted_methods_count", 48},
            {"status", "JIT_ALLOCATIONS_CAPTURED"}
        });
    });

    // GET /api/clr_jit/manager
    router.get("/api/clr_jit/manager", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"execution_engine_jit_manager", "0x00007FFB90501020"},
            {"code_type", "RyuJIT_x64"}
        });
    });
}

} // namespace handlers
