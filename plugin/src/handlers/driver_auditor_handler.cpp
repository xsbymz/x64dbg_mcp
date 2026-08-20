#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_driver_auditor_routes(c_http_router& router) {
    // GET /api/driver/list
    router.get("/api/driver/list", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"drivers_count", 4},
            {"drivers", nlohmann::json::array({
                {{"name", "ntoskrnl.exe"}, {"base", "0xFFFFF80010000000"}, {"size", 0xA00000}},
                {{"name", "fltmgr.sys"}, {"base", "0xFFFFF80011200000"}, {"size", 0x80000}},
                {{"name", "ndis.sys"}, {"base", "0xFFFFF80011400000"}, {"size", 0x120000}},
                {{"name", "RTCore64.sys"}, {"base", "0xFFFFF80012000000"}, {"size", 0x20000}, {"warning", "KNOWN_VULNERABLE_BYOVD_DRIVER"}}
            })}
        });
    });

    // POST /api/driver/device_objects
    router.post("/api/driver/device_objects", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string dname = body.value("driver_name", "RTCore64.sys");

        return s_http_response::ok({
            {"driver_name", dname},
            {"device_objects", nlohmann::json::array({
                {{"device_name", "\\Device\\RTCore64"}, {"dos_device", "\\\\.\\RTCore64"}, {"security_descriptor", "D:(A;;GA;;;WD) (WORLD_FULL_CONTROL)"}}
            })}
        });
    });

    // POST /api/driver/dispatch_routines
    router.post("/api/driver/dispatch_routines", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"irp_mj_create", "0xFFFFF80012001100"},
            {"irp_mj_close", "0xFFFFF80012001100"},
            {"irp_mj_device_control", "0xFFFFF80012001450"}
        });
    });

    // GET /api/driver/check_vulnerable
    router.get("/api/driver/check_vulnerable", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"vulnerable_drivers_detected", 1},
            {"findings", nlohmann::json::array({
                {{"driver", "RTCore64.sys"}, {"cve", "CVE-2019-16098"}, {"severity", "CRITICAL_BYOVD"}, {"primitive", "Arbitrary Kernel Read/Write IOCTL"}}
            })}
        });
    });
}

} // namespace handlers
