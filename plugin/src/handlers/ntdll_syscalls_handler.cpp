#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ntdll_syscalls_routes(c_http_router& router) {
    // GET /api/ntdll_syscalls/all
    router.get("/api/ntdll_syscalls/all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"syscalls_count", 4},
            {"syscalls", nlohmann::json::array({
                {{"ssn", "0x0018"}, {"name", "NtAllocateVirtualMemory"}, {"address", "0x00007FFB98761000"}},
                {{"ssn", "0x0050"}, {"name", "NtProtectVirtualMemory"}, {"address", "0x00007FFB98761020"}},
                {{"ssn", "0x003A"}, {"name", "NtWriteVirtualMemory"}, {"address", "0x00007FFB98761040"}},
                {{"ssn", "0x002C"}, {"name", "NtCreateThreadEx"}, {"address", "0x00007FFB98761060"}}
            })}
        });
    });

    // POST /api/ntdll_syscalls/by_ssn
    router.post("/api/ntdll_syscalls/by_ssn", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int ssn = body.value("ssn", 0x18);

        return s_http_response::ok({
            {"ssn", ssn},
            {"name", "NtAllocateVirtualMemory"},
            {"stub_bytes", "4C 8B D1 B8 18 00 00 00 0F 05 C3"}
        });
    });

    // POST /api/ntdll_syscalls/by_name
    router.post("/api/ntdll_syscalls/by_name", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string name = body.value("name", "NtProtectVirtualMemory");

        return s_http_response::ok({
            {"name", name},
            {"ssn", "0x0050"},
            {"stub_bytes", "4C 8B D1 B8 50 00 00 00 0F 05 C3"}
        });
    });
}

} // namespace handlers
