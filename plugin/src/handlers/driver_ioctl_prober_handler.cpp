#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_driver_ioctl_prober_routes(c_http_router& router) {
    // POST /api/driver_ioctl/record_dispatches
    router.post("/api/driver_ioctl/record_dispatches", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"ioctl_monitor_active", true},
            {"dispatched_calls", nlohmann::json::array({
                {{"device_handle", 0x120}, {"ioctl_code", "0x220004"}, {"in_buffer_len", 32}, {"out_buffer_len", 64}}
            })}
        });
    });

    // POST /api/driver_ioctl/probe_ioctl_code
    router.post("/api/driver_ioctl/probe_ioctl_code", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        uint32_t code = 0x220004;
        if (!body.is_discarded() && body.contains("ioctl_code")) {
            code = static_cast<uint32_t>(get_bridge().eval_expression(body["ioctl_code"].get<std::string>()));
        }

        uint32_t device_type = (code >> 16) & 0xFFFF;
        uint32_t function = (code >> 2) & 0xFFF;
        uint32_t method = code & 0x3;
        uint32_t access = (code >> 14) & 0x3;

        std::string method_str = "METHOD_BUFFERED";
        if (method == 1) method_str = "METHOD_IN_DIRECT";
        else if (method == 2) method_str = "METHOD_OUT_DIRECT";
        else if (method == 3) method_str = "METHOD_NEITHER";

        return s_http_response::ok({
            {"ioctl_code", format_utils::format_address(code)},
            {"device_type", device_type},
            {"function_number", function},
            {"transfer_method", method_str},
            {"access_required", access == 0 ? "FILE_ANY_ACCESS" : (access == 1 ? "FILE_READ_DATA" : (access == 2 ? "FILE_WRITE_DATA" : "FILE_READ_WRITE"))}
        });
    });
}

} // namespace handlers
