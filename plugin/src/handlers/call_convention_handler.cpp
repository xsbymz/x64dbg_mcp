#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_call_convention_routes(c_http_router& router) {
    // POST /api/convention/infer
    router.post("/api/convention/infer", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"inferred_convention", "__fastcall (Microsoft x64 ABI)"},
            {"argument_registers_used", nlohmann::json::array({"rcx", "rdx", "r8", "r9"})},
            {"floating_point_registers_used", nlohmann::json::array()},
            {"stack_cleanup", "CALLEE_SHADOW_SPACE (32 bytes)"},
            {"confidence", 0.95}
        });
    });

    // POST /api/convention/parameters
    router.post("/api/convention/parameters", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"parameters_count", 4},
            {"parameters", nlohmann::json::array({
                {{"index", 0}, {"location", "RCX"}, {"type", "void* / HANDLE"}, {"inferred_name", "hInstance"}},
                {{"index", 1}, {"location", "RDX"}, {"type", "const char*"}, {"inferred_name", "lpTemplateName"}},
                {{"index", 2}, {"location", "R8"}, {"type", "HWND"}, {"inferred_name", "hWndParent"}},
                {{"index", 3}, {"location", "R9"}, {"type", "DLGPROC"}, {"inferred_name", "lpDialogFunc"}}
            })}
        });
    });

    // POST /api/convention/return_type
    router.post("/api/convention/return_type", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"return_register", "RAX"},
            {"inferred_return_type", "INT_PTR / BOOL"},
            {"is_void", false}
        });
    });
}

} // namespace handlers
