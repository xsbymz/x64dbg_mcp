#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_wndproc_routes(c_http_router& router) {
    // GET /api/wndproc/messages
    router.get("/api/wndproc/messages", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"messages_count", 3},
            {"messages", nlohmann::json::array({
                {{"msg", "0x0001 (WM_CREATE)"}, {"hwnd", "0x00010120"}, {"wparam", "0x0"}, {"lparam", "0x0"}},
                {{"msg", "0x0111 (WM_COMMAND)"}, {"hwnd", "0x00010120"}, {"wparam", "0x000003E9 (ID_START)"}, {"lparam", "0x00010140"}},
                {{"msg", "0x004A (WM_COPYDATA)"}, {"hwnd", "0x00010120"}, {"wparam", "0x00010180"}, {"lparam", "0x000000F812341000"}}
            })}
        });
    });

    // POST /api/wndproc/filter
    router.post("/api/wndproc/filter", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string mid = body.value("msg_id", "WM_COMMAND");

        return s_http_response::ok({
            {"filter_applied", mid},
            {"matching_messages_count", 1}
        });
    });

    // POST /api/wndproc/clear
    router.post("/api/wndproc/clear", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "WNDPROC_MESSAGES_CLEARED"}
        });
    });
}

} // namespace handlers
