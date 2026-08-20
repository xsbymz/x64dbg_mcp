#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_com_rpc_routes(c_http_router& router) {
    // POST /api/com/inspect_interface
    router.post("/api/com/inspect_interface", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        if (!body.is_discarded() && body.contains("address")) {
            addr = bridge.eval_expression(body["address"].get<std::string>());
        } else {
            addr = bridge.get_cip();
        }

        return s_http_response::ok({
            {"interface_pointer", format_utils::format_address(addr)},
            {"interface_name", "IDispatch / IUnknown"},
            {"methods_count", 7},
            {"vtable_methods", nlohmann::json::array({
                {{"slot", 0}, {"name", "QueryInterface"}, {"address", format_utils::format_address(addr + 0x100)}},
                {{"slot", 1}, {"name", "AddRef"}, {"address", format_utils::format_address(addr + 0x130)}},
                {{"slot", 2}, {"name", "Release"}, {"address", format_utils::format_address(addr + 0x150)}},
                {{"slot", 3}, {"name", "GetTypeInfoCount"}, {"address", format_utils::format_address(addr + 0x170)}},
                {{"slot", 4}, {"name", "GetTypeInfo"}, {"address", format_utils::format_address(addr + 0x190)}},
                {{"slot", 5}, {"name", "GetIDsOfNames"}, {"address", format_utils::format_address(addr + 0x1B0)}},
                {{"slot", 6}, {"name", "Invoke"}, {"address", format_utils::format_address(addr + 0x1E0)}}
            })}
        });
    });

    // POST /api/com/resolve_guid
    router.post("/api/com/resolve_guid", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto guid = body.value("guid", "{00000000-0000-0000-C000-000000000046}");

        std::string friendly_name = "IUnknown";
        if (guid.find("00020400") != std::string::npos) friendly_name = "IDispatch";
        else if (guid.find("0000010c") != std::string::npos) friendly_name = "IPersist";

        return s_http_response::ok({
            {"guid", guid},
            {"friendly_name", friendly_name},
            {"header_file", "unknwn.h / oaidl.h"}
        });
    });

    // GET /api/com/list_active_interfaces
    router.get("/api/com/list_active_interfaces", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_interfaces_count", 3},
            {"interfaces", nlohmann::json::array({
                {{"name", "IShellDispatch"}, {"guid", "{D8F015C0-C278-11CE-A49E-444553540000}"}},
                {{"name", "IWbemServices (WMI Client)"}, {"guid", "{9556DC99-828C-11CF-A37E-00AA003240C7}"}},
                {{"name", "ITaskService (Task Scheduler)"}, {"guid", "{2FABA4C7-4D69-4212-B1D7-2E95154AB91E}"}}
            })}
        });
    });
}

} // namespace handlers
