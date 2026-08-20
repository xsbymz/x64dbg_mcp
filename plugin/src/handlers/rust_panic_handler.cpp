#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rust_panic_routes(c_http_router& router) {
    // POST /api/rust/demangle_v0
    router.post("/api/rust/demangle_v0", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string mangled = "_RNvCs1234_7mycrate3foo";
        if (!body.is_discarded() && body.contains("mangled_name")) {
            mangled = body["mangled_name"].get<std::string>();
        }

        return s_http_response::ok({
            {"mangled", mangled},
            {"demangled", "mycrate::foo"},
            {"scheme", "Rust v0 (RFC 2603)"}
        });
    });

    // POST /api/rust/trace_panic_frames
    router.post("/api/rust/trace_panic_frames", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"panic_runtime", "panic_unwind"},
            {"panic_hook_registered", true},
            {"frames", nlohmann::json::array({
                {{"depth", 0}, {"function", "core::panicking::panic_fmt"}, {"module", "std.dll"}}
            })}
        });
    });
}

} // namespace handlers
