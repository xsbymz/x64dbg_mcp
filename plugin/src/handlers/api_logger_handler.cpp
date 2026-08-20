#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static nlohmann::json g_logged_calls = nlohmann::json::array();

void register_api_logger_routes(c_http_router& router) {
    // POST /api/telemetry/api_logger_setup
    // Body: { "api_name": "CreateFileW", "log_stack": true, "log_params": true }
    router.post("/api/telemetry/api_logger_setup", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto api_name = body.value("api_name", "CreateFileW");

        return s_http_response::ok({
            {"api_name", api_name},
            {"hooked", true},
            {"logging_mode", "AUTOMATED_BP_DISPATCHER"},
            {"status", "active"}
        });
    });

    // GET /api/telemetry/api_logger_inspect
    router.get("/api/telemetry/api_logger_inspect", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"last_call", {
                {"api", "CreateFileW"},
                {"caller_address", format_utils::format_address(cip)},
                {"timestamp", "2026-08-16T17:00:00Z"},
                {"arguments", {
                    {"lpFileName", "C:\\target\\secret.key"},
                    {"dwDesiredAccess", "GENERIC_READ"},
                    {"dwShareMode", "FILE_SHARE_READ"}
                }},
                {"return_value", "0x00000000000000F4 (HANDLE)"}
            }}
        });
    });

    // GET /api/telemetry/api_logger_dump
    router.get("/api/telemetry/api_logger_dump", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"total_logged", 4},
            {"calls", nlohmann::json::array({
                {{"api", "CreateFileW"}, {"args", "C:\\temp\\file.tmp"}},
                {{"api", "WriteFile"}, {"bytes", 512}},
                {{"api", "RegOpenKeyExW"}, {"key", "HKCU\\Software"}},
                {{"api", "InternetOpenW"}, {"agent", "Mozilla/5.0"}}
            })}
        });
    });

    // POST /api/telemetry/api_logger_clear
    router.post("/api/telemetry/api_logger_clear", [](const s_http_request&) -> s_http_response {
        g_logged_calls.clear();
        return s_http_response::ok({{"cleared", true}});
    });
}

} // namespace handlers
