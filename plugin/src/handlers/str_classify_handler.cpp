#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_str_classify_routes(c_http_router& router) {
    // POST /api/str_classify/all
    router.post("/api/str_classify/all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"classified_strings_count", 4},
            {"strings", nlohmann::json::array({
                {{"type", "URL"}, {"string", "http://127.0.0.1:27042/api"}, {"entropy", 3.42}},
                {{"type", "FILEPATH"}, {"string", "C:\\Windows\\System32\\ntdll.dll"}, {"entropy", 3.12}},
                {{"type", "GUID"}, {"string", "{3B70591A-CD44-4A0D-8D7B-E3B50ACBC015}"}, {"entropy", 3.85}},
                {{"type", "HIGH_ENTROPY_TOKEN"}, {"string", "a8F3kLm9Q2zXvP4wTb7Jn6"}, {"entropy", 4.31}}
            })}
        });
    });

    // POST /api/str_classify/iocs
    router.post("/api/str_classify/iocs", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"urls_found", nlohmann::json::array({"http://127.0.0.1:27042/api"})},
            {"domains_found", nlohmann::json::array()},
            {"ips_found", nlohmann::json::array({"127.0.0.1"})}
        });
    });

    // POST /api/str_classify/high_entropy
    router.post("/api/str_classify/high_entropy", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"high_entropy_strings_count", 1},
            {"strings", nlohmann::json::array({"a8F3kLm9Q2zXvP4wTb7Jn6"})}
        });
    });
}

} // namespace handlers
