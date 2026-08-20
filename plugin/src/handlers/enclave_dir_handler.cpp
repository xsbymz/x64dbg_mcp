#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_enclave_dir_routes(c_http_router& router) {
    // POST /api/enclave_dir/header
    router.post("/api/enclave_dir/header", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"has_enclave_directory", false},
            {"enclave_type", "NONE"},
            {"enclave_size", 0}
        });
    });

    // POST /api/enclave_dir/imports
    router.post("/api/enclave_dir/imports", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"enclave_imports_count", 0},
            {"imports", nlohmann::json::array()}
        });
    });

    // POST /api/enclave_dir/policy
    router.post("/api/enclave_dir/policy", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"policy_flags", "0x00000000"}
        });
    });
}

} // namespace handlers
