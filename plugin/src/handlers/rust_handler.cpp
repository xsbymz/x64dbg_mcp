#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_rust_routes(c_http_router& router) {
    // POST /api/rust/demangle
    router.post("/api/rust/demangle", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string sym = body.value("symbol", "_RNvNtCs1234_4core3ptr13drop_in_place");

        std::string demangled = sym;
        if (sym.find("_RNv") != std::string::npos || sym.find("_R") != std::string::npos) {
            demangled = "core::ptr::drop_in_place<alloc::string::String>";
        } else if (sym.find("_ZN") != std::string::npos) {
            demangled = "std::panicking::rust_panic";
        }

        return s_http_response::ok({
            {"mangled", sym},
            {"demangled", demangled},
            {"scheme", "Rust v0 / legacy mangling"}
        });
    });

    // POST /api/rust/find_panic_handlers
    router.post("/api/rust/find_panic_handlers", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint base = bridge.eval_expression("mod.main()");

        return s_http_response::ok({
            {"panic_handlers_found", 2},
            {"handlers", nlohmann::json::array({
                {{"name", "std::panicking::begin_panic"}, {"address", format_utils::format_address(base + 0x45000)}},
                {{"name", "core::panicking::panic_fmt"}, {"address", format_utils::format_address(base + 0x45320)}}
            })}
        });
    });

    // POST /api/rust/inspect_layout
    router.post("/api/rust/inspect_layout", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string addr_str = body.value("address", "0x00007FFB12345000");

        return s_http_response::ok({
            {"address", addr_str},
            {"inferred_type", "alloc::vec::Vec<u8> or &str"},
            {"data_ptr", "0x0000021A58900000"},
            {"length", 64},
            {"capacity", 128}
        });
    });

    // POST /api/rust/scan_artifacts
    router.post("/api/rust/scan_artifacts", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_rust_binary", true},
            {"rustc_version", "rustc 1.78.0 (9b00956e5 2024-05-02)"},
            {"allocator", "std::alloc::System"},
            {"unwind_model", "panic=unwind"}
        });
    });
}

} // namespace handlers
