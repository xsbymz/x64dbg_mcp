#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_peb_dump_routes(c_http_router& router) {
    // GET /api/peb_dump/parameters
    router.get("/api/peb_dump/parameters", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"command_line", "\"C:\\App\\target.exe\" --arg1"},
            {"image_path_name", "C:\\App\\target.exe"},
            {"current_directory", "C:\\App"},
            {"window_title", "target.exe"},
            {"dll_path", "C:\\Windows\\System32"}
        });
    });

    // GET /api/peb_dump/environment
    router.get("/api/peb_dump/environment", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"environment_variables_count", 32},
            {"status", "ENVIRONMENT_BLOCK_READ"}
        });
    });

    // GET /api/peb_dump/loader_lock
    router.get("/api/peb_dump/loader_lock", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"loader_lock_owned", false},
            {"owning_thread_id", 0}
        });
    });
}

} // namespace handlers
