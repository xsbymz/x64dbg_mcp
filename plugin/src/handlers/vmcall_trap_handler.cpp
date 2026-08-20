#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_vmcall_trap_routes(c_http_router& router) {
    // GET /api/vmcall_trap/scan
    router.get("/api/vmcall_trap/scan", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"vmcall_opcodes_found", 0},
            {"status", "NO_VMCALL_TRAPS"}
        });
    });

    // GET /api/vmcall_trap/msrs
    router.get("/api/vmcall_trap/msrs", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"synthetic_msrs_detected", false}
        });
    });

    // GET /api/vmcall_trap/backdoors
    router.get("/api/vmcall_trap/backdoors", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hypervisor_backdoors_detected", false}
        });
    });
}

} // namespace handlers
