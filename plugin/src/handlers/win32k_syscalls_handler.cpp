#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_win32k_syscalls_routes(c_http_router& router) {
    // GET /api/win32k_syscalls/all
    router.get("/api/win32k_syscalls/all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"win32k_syscalls_count", 4},
            {"syscalls", nlohmann::json::array({
                {{"ssn", "0x1000"}, {"name", "NtUserGetDC"}, {"module", "win32kfull.sys"}},
                {{"ssn", "0x1001"}, {"name", "NtUserReleaseDC"}, {"module", "win32kfull.sys"}},
                {{"ssn", "0x1002"}, {"name", "NtUserPeekMessage"}, {"module", "win32kfull.sys"}},
                {{"ssn", "0x1003"}, {"name", "NtUserPostMessage"}, {"module", "win32kfull.sys"}}
            })}
        });
    });

    // POST /api/win32k_syscalls/by_ssn
    router.post("/api/win32k_syscalls/by_ssn", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int ssn = body.value("ssn", 0x1000);

        return s_http_response::ok({
            {"ssn", ssn},
            {"name", "NtUserGetDC"},
            {"module", "win32kfull.sys"}
        });
    });

    // POST /api/win32k_syscalls/by_name
    router.post("/api/win32k_syscalls/by_name", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string name = body.value("name", "NtUserGetDC");

        return s_http_response::ok({
            {"name", name},
            {"ssn", "0x1000"},
            {"module", "win32kfull.sys"}
        });
    });
}

} // namespace handlers
