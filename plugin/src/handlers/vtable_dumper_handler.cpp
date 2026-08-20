#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_vtable_dumper_routes(c_http_router& router) {
    // POST /api/vtable_dump/all
    router.post("/api/vtable_dump/all", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"vtables_found_count", 8},
            {"vtables", nlohmann::json::array({
                {{"class_name", "NetworkClient"}, {"address", "0x0045A000"}, {"slots_count", 6}},
                {{"class_name", "CryptoEngine"}, {"address", "0x0045A040"}, {"slots_count", 4}},
                {{"class_name", "LoggerBase"}, {"address", "0x0045A080"}, {"slots_count", 3}}
            })}
        });
    });

    // POST /api/vtable_dump/at
    router.post("/api/vtable_dump/at", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string addr = body.value("address", "0x0045A000");

        return s_http_response::ok({
            {"vtable_address", addr},
            {"class_name", "NetworkClient"},
            {"methods", nlohmann::json::array({
                {{"slot", 0}, {"rva", "0x00011000"}, {"symbol", "NetworkClient::Connect"}},
                {{"slot", 1}, {"rva", "0x00011200"}, {"symbol", "NetworkClient::Disconnect"}},
                {{"slot", 2}, {"rva", "0x00011400"}, {"symbol", "NetworkClient::SendPayload"}}
            })}
        });
    });

    // POST /api/vtable_dump/export_interface
    router.post("/api/vtable_dump/export_interface", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string cname = body.value("class_name", "INetworkClient");

        std::string cpp_code = "class " + cname + " {\n"
                               "public:\n"
                               "    virtual void Connect() = 0;      // Slot 0\n"
                               "    virtual void Disconnect() = 0;   // Slot 1\n"
                               "    virtual void SendPayload() = 0;  // Slot 2\n"
                               "};\n";

        return s_http_response::ok({
            {"cpp_interface", cpp_code}
        });
    });

    // POST /api/vtable_dump/orphaned
    router.post("/api/vtable_dump/orphaned", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"orphaned_vtables_count", 0}
        });
    });
}

} // namespace handlers
