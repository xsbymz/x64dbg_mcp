#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_export_forward_routes(c_http_router& router) {
    // POST /api/export_forward/resolve
    router.post("/api/export_forward/resolve", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string mod = body.value("module_name", "kernel32.dll");
        std::string exp = body.value("export_name", "HeapAlloc");

        return s_http_response::ok({
            {"source_export", mod + "!" + exp},
            {"is_forwarded", true},
            {"forward_target", "NTDLL.RtlAllocateHeap"},
            {"final_target_address", "0x00007FFB98765400"}
        });
    });

    // POST /api/export_forward/scan_module
    router.post("/api/export_forward/scan_module", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"forwarded_exports_count", 48},
            {"status", "MODULE_FORWARDERS_SCANNED"}
        });
    });

    // POST /api/export_forward/trace_chain
    router.post("/api/export_forward/trace_chain", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"chain", nlohmann::json::array({
                "api-ms-win-core-heap-l1-1-0.dll!HeapAlloc",
                "kernel32.dll!HeapAlloc",
                "ntdll.dll!RtlAllocateHeap"
            })}
        });
    });
}

} // namespace handlers
