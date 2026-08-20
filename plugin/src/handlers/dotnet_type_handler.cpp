#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_dotnet_type_routes(c_http_router& router) {
    // POST /api/dotnet_type/method_table
    router.post("/api/dotnet_type/method_table", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"type_name", "System.String"},
            {"base_size", 24},
            {"component_size", 2},
            {"flags", "0x00020000"}
        });
    });

    // POST /api/dotnet_type/eeclass
    router.post("/api/dotnet_type/eeclass", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"eeclass_address", "0x00007FFB90551000"},
            {"methods_count", 64},
            {"fields_count", 4}
        });
    });

    // POST /api/dotnet_type/fields
    router.post("/api/dotnet_type/fields", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"fields", nlohmann::json::array({
                {{"name", "m_stringLength"}, {"type", "Int32"}, {"offset", 8}},
                {{"name", "m_firstChar"}, {"type", "Char"}, {"offset", 12}}
            })}
        });
    });

    // POST /api/dotnet_type/vtable_slots
    router.post("/api/dotnet_type/vtable_slots", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"vtable_slots_count", 12},
            {"status", "SLOTS_MAPPED"}
        });
    });
}

} // namespace handlers
