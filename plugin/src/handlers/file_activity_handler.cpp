#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_file_activity_routes(c_http_router& router) {
    // POST /api/fs/operations
    router.post("/api/fs/operations", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"file_operations_count", 3},
            {"operations", nlohmann::json::array({
                {{"operation", "CreateFileW"}, {"path", "C:\\Users\\admin\\AppData\\Local\\Temp\\drop.tmp"}, {"desired_access", "GENERIC_WRITE"}, {"disposition", "CREATE_ALWAYS"}},
                {{"operation", "WriteFile"}, {"path", "C:\\Users\\admin\\AppData\\Local\\Temp\\drop.tmp"}, {"bytes_written", 4096}},
                {{"operation", "ReadFile"}, {"path", "C:\\Windows\\System32\\drivers\\etc\\hosts"}, {"bytes_read", 824}}
            })}
        });
    });

    // GET /api/fs/open_files
    router.get("/api/fs/open_files", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"open_files", nlohmann::json::array({
                "C:\\Users\\admin\\AppData\\Local\\Temp\\drop.tmp"
            })}
        });
    });

    // POST /api/fs/written_buffers
    router.post("/api/fs/written_buffers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"written_buffers_captured", 1},
            {"buffers", nlohmann::json::array({
                {{"file", "drop.tmp"}, {"size", 4096}, {"sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"}}
            })}
        });
    });

    // POST /api/fs/clear_log
    router.post("/api/fs/clear_log", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "LOG_CLEARED"}
        });
    });
}

} // namespace handlers
