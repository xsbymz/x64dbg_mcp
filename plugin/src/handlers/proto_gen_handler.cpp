#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_proto_gen_routes(c_http_router& router) {
    // POST /api/proto_gen/prototype
    router.post("/api/proto_gen/prototype", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string fname = body.value("function_name", "SubFunction");

        return s_http_response::ok({
            {"prototype", "BOOL __fastcall " + fname + "(HANDLE hProcess, LPCVOID lpAddress, SIZE_T dwSize);"},
            {"calling_convention", "__fastcall"}
        });
    });

    // POST /api/proto_gen/header
    router.post("/api/proto_gen/header", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string fname = body.value("function_name", "SubFunction");

        std::string header = "#pragma once\n"
                             "#include <windows.h>\n\n"
                             "// Auto-generated prototype by x64dbg-MCP\n"
                             "BOOL __fastcall " + fname + "(HANDLE hProcess, LPCVOID lpAddress, SIZE_T dwSize);\n";

        return s_http_response::ok({
            {"header_content", header}
        });
    });

    // POST /api/proto_gen/types
    router.post("/api/proto_gen/types", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rcx_type", "HANDLE / void*"},
            {"rdx_type", "LPCVOID / const void*"},
            {"r8_type", "SIZE_T / uint64_t"},
            {"rax_return_type", "BOOL"}
        });
    });
}

} // namespace handlers
