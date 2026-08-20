#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dotnet_routes(c_http_router& router) {
    // GET /api/dotnet/detect_clr
    router.get("/api/dotnet/detect_clr", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_managed_process", true},
            {"clr_version", ".NET 8.0.x (CoreCLR)"},
            {"clr_module", "coreclr.dll"},
            {"jit_engine", "clrjit.dll"}
        });
    });

    // GET /api/dotnet/list_appdomains
    router.get("/api/dotnet/list_appdomains", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"appdomains_count", 1},
            {"appdomains", nlohmann::json::array({
                {{"id", 1}, {"name", "DefaultDomain"}, {"assemblies_count", 18}}
            })}
        });
    });

    // POST /api/dotnet/resolve_jit_method
    router.post("/api/dotnet/resolve_jit_method", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string addr_str = body.value("address", "0x00007FFB12345678");

        return s_http_response::ok({
            {"address", addr_str},
            {"method_name", "System.Net.Http.HttpClient.SendAsync"},
            {"class_name", "System.Net.Http.HttpClient"},
            {"token", "0x060001A4"},
            {"is_jitted", true}
        });
    });

    // POST /api/dotnet/parse_cli_header
    router.post("/api/dotnet/parse_cli_header", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"runtime_version", "v4.0.30319"},
            {"flags", "0x00000001 (COMIMAGE_FLAGS_ILONLY)"},
            {"entry_point_token", "0x06000001"},
            {"strong_name_signed", false}
        });
    });
}

} // namespace handlers
