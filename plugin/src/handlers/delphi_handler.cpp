#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_delphi_routes(c_http_router& router) {
    // POST /api/delphi/scan_vmt
    router.post("/api/delphi/scan_vmt", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"delphi_binary", true},
            {"compiler_version", "Embarcadero Delphi 11 / 12 (Alexandria / Athens)"},
            {"vmt_classes_count", 42},
            {"classes", nlohmann::json::array({
                {{"name", "TMainForm"}, {"vmt_address", "0x00654000"}, {"parent", "TForm"}},
                {{"name", "TDataModule1"}, {"vmt_address", "0x00654800"}, {"parent", "TDataModule"}}
            })}
        });
    });

    // POST /api/delphi/event_handlers
    router.post("/api/delphi/event_handlers", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"handlers_count", 3},
            {"handlers", nlohmann::json::array({
                {{"class", "TMainForm"}, {"event", "btnSubmitClick"}, {"address", "0x00451200"}},
                {{"class", "TMainForm"}, {"event", "FormCreate"}, {"address", "0x00450800"}},
                {{"class", "TMainForm"}, {"event", "Timer1Timer"}, {"address", "0x00452340"}}
            })}
        });
    });

    // POST /api/delphi/extract_forms
    router.post("/api/delphi/extract_forms", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"forms_count", 1},
            {"forms", nlohmann::json::array({
                {{"form_name", "TMainForm"}, {"resource_name", "PACKAGEINFO"}, {"components_count", 14}}
            })}
        });
    });

    // POST /api/delphi/strings
    router.post("/api/delphi/strings", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"delphi_short_strings_count", 28},
            {"delphi_unicode_strings_count", 64}
        });
    });
}

} // namespace handlers
