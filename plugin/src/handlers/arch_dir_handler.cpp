#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_arch_dir_routes(c_http_router& router) {
    // GET /api/arch_dir/parse
    router.get("/api/arch_dir/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"architecture_entry_present", false},
            {"architecture_type", "IMAGE_FILE_MACHINE_AMD64 (0x8664)"}
        });
    });

    // GET /api/arch_dir/compatibility
    router.get("/api/arch_dir/compatibility", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_native_x64", true},
            {"requires_emulation", false}
        });
    });

    // GET /api/arch_dir/flags
    router.get("/api/arch_dir/flags", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"flags", 0},
            {"description", "Standard x64 PE image"}
        });
    });
}

} // namespace handlers
