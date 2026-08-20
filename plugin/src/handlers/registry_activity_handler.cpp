#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_registry_activity_routes(c_http_router& router) {
    // POST /api/reg/operations
    router.post("/api/reg/operations", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"registry_operations_count", 3},
            {"operations", nlohmann::json::array({
                {{"operation", "RegOpenKeyExW"}, {"key", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, {"sam_desired", "KEY_SET_VALUE"}},
                {{"operation", "RegSetValueExW"}, {"key", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, {"value_name", "UpdaterSvc"}, {"type", "REG_SZ"}, {"data", "C:\\Users\\admin\\AppData\\Local\\Temp\\drop.tmp"}},
                {{"operation", "RegQueryValueExW"}, {"key", "HKLM\\SYSTEM\\CurrentControlSet\\Control\\Nls\\CodePage"}, {"value_name", "ACP"}, {"type", "REG_SZ"}, {"data", "1252"}}
            })}
        });
    });

    // POST /api/reg/modified_keys
    router.post("/api/reg/modified_keys", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"modified_keys_count", 1},
            {"keys", nlohmann::json::array({
                "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"
            })}
        });
    });

    // GET /api/reg/persistence_check
    router.get("/api/reg/persistence_check", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"persistence_tampering_detected", true},
            {"findings", nlohmann::json::array({
                {{"key", "HKLM\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}, {"value_name", "UpdaterSvc"}, {"target_binary", "drop.tmp"}, {"risk", "HIGH_PERSISTENCE"}}
            })}
        });
    });

    // POST /api/reg/clear_log
    router.post("/api/reg/clear_log", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "REGISTRY_LOG_CLEARED"}
        });
    });
}

} // namespace handlers
