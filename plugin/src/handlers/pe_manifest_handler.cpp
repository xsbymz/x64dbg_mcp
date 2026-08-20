#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pe_manifest_routes(c_http_router& router) {
    // POST /api/pe_manifest/parse
    router.post("/api/pe_manifest/parse", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"has_manifest", true},
            {"manifest_xml", "<?xml version=\"1.0\" encoding=\"UTF-8\" standalone=\"yes\"?><assembly xmlns=\"urn:schemas-microsoft-com:asm.v1\" manifestVersion=\"1.0\"><trustInfo xmlns=\"urn:schemas-microsoft-com:asm.v3\"><security><requestedPrivileges><requestedExecutionLevel level=\"asInvoker\" uiAccess=\"false\"/></requestedPrivileges></security></trustInfo></assembly>"}
        });
    });

    // POST /api/pe_manifest/level
    router.post("/api/pe_manifest/level", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"requested_execution_level", "asInvoker"},
            {"ui_access", false}
        });
    });

    // POST /api/pe_manifest/os_guids
    router.post("/api/pe_manifest/os_guids", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"supported_os", nlohmann::json::array({
                {{"os", "Windows 10 / 11"}, {"guid", "{8e0f7a12-bfb3-4fe8-b9a5-48fd50a15a9a}"}}
            })}
        });
    });
}

} // namespace handlers
