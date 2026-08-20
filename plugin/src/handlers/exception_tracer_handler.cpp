#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_exception_tracer_routes(c_http_router& router) {
    // GET /api/exception_trace/last
    router.get("/api/exception_trace/last", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_exception", true},
            {"exception_code", "0xC0000005 (EXCEPTION_ACCESS_VIOLATION)"},
            {"exception_address", "0x00007FF712345678"},
            {"read_write_flag", "READ (0)"},
            {"faulting_address", "0x0000000000000000"},
            {"handled_by", "KiUserExceptionDispatcher -> RtlDispatchException"}
        });
    });

    // GET /api/exception_trace/seh
    router.get("/api/exception_trace/seh", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"seh_frames_count", 2},
            {"frames", nlohmann::json::array({
                {{"frame_address", "0x000000F81234F000"}, {"handler", "0x00007FF712341000"}, {"scope_table", "0x00007FF712350000"}},
                {{"frame_address", "0x000000F81234F800"}, {"handler", "0x00007FFB98760000 (KERNELBASE!_except_handler4)"}, {"scope_table", "0x0000000000000000"}}
            })}
        });
    });

    // GET /api/exception_trace/veh
    router.get("/api/exception_trace/veh", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"veh_handlers_count", 1},
            {"handlers", nlohmann::json::array({
                {{"node_address", "0x0000021A58901000"}, {"handler_function", "0x00007FF712348000 (main!CustomVehHandler)"}}
            })}
        });
    });

    // GET /api/exception_trace/context
    router.get("/api/exception_trace/context", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"context_flags", "0x0010005F (CONTEXT_AMD64_FULL)"},
            {"rip", format_utils::format_address(cip)},
            {"rsp", "0x000000F81234EFC0"},
            {"rbp", "0x000000F81234F010"}
        });
    });
}

} // namespace handlers
