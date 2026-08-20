#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ioctl_fuzzer_routes(c_http_router& router) {
    // POST /api/ioctl_fuzzer/generate
    router.post("/api/ioctl_fuzzer/generate", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"packet_size", 64},
            {"payload_hex", "41414141414141414141414141414141"},
            {"mutation_strategy", "BITFLIP_AND_BOUNDARY"}
        });
    });

    // POST /api/ioctl_fuzzer/decode
    router.post("/api/ioctl_fuzzer/decode", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int code = body.value("ioctl_code", 0x222000);

        return s_http_response::ok({
            {"ioctl_code", code},
            {"device_type", "FILE_DEVICE_UNKNOWN (0x22)"},
            {"function", "0x800"},
            {"method", "METHOD_BUFFERED (0)"},
            {"access", "FILE_ANY_ACCESS (0)"}
        });
    });

    // POST /api/ioctl_fuzzer/dispatch
    router.post("/api/ioctl_fuzzer/dispatch", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"simulated_dispatch_status", "STATUS_SUCCESS (0x00000000)"},
            {"bytes_returned", 16}
        });
    });
}

} // namespace handlers
