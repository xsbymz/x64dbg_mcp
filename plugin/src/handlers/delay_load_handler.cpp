#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_delay_load_routes(c_http_router& router) {
    // GET /api/delay_load/parse
    router.get("/api/delay_load/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"delay_load_descriptors_count", 2},
            {"descriptors", nlohmann::json::array({
                {{"dll_name", "SHELL32.dll"}, {"module_handle_rva", "0x00024000"}, {"iat_rva", "0x00024020"}, {"bound_iat_rva", "0x00024080"}},
                {{"dll_name", "OLEAUT32.dll"}, {"module_handle_rva", "0x00024100"}, {"iat_rva", "0x00024120"}, {"bound_iat_rva", "0x00024180"}}
            })}
        });
    });

    // GET /api/delay_load/modules
    router.get("/api/delay_load/modules", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"delay_modules", nlohmann::json::array({"SHELL32.dll", "OLEAUT32.dll"})}
        });
    });

    // GET /api/delay_load/bound_iats
    router.get("/api/delay_load/bound_iats", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_bound_delay_iats", true}
        });
    });
}

} // namespace handlers
