#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_idispatch_tracer_routes(c_http_router& router) {
    router.post("/api/idispatch/hook_invoke_trace", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["idispatch_vtable_layout"] = {
            {"QueryInterface", "vtable[0] — Standard IUnknown"},
            {"AddRef", "vtable[1]"},
            {"Release", "vtable[2]"},
            {"GetTypeInfoCount", "vtable[3]"},
            {"GetTypeInfo", "vtable[4]"},
            {"GetIDsOfNames", "vtable[5] — Maps string method name to DISPID"},
            {"Invoke", "vtable[6] — Core late-bound automation dispatch routine"}
        };
        result["invoke_parameters"] = {
            "dispIdMember (DISPID target)",
            "riid (Reserved, must be IID_NULL)",
            "lcid (Locale ID)",
            "wFlags (DISPATCH_METHOD, DISPATCH_PROPERTYGET, DISPATCH_PROPERTYPUT)",
            "pDispParams (DISPPARAMS arguments array and named arguments count)",
            "pVarResult (VARIANT return value pointer)"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/idispatch/enumerate_dispids", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string progId = body.value("prog_id", "WScript.Shell");
        json result;
        result["prog_id"] = progId;
        result["common_automation_dispids"] = {
            {"WScript.Shell", {
                {"Run", "DISPID 0x60020000 / Named invoke"},
                {"Exec", "Spawns child process with STDIN/STDOUT pipes"},
                {"RegRead / RegWrite", "Registry manipulation"},
                {"CreateShortcut", "Shortcut manipulation (.LNK persistence)"}
            }},
            {"ADODB.Stream", {
                {"Write / SaveToFile", "Used by Office macros and downloaders to write binary dropped files to disk"}
            }},
            {"MSXML2.XMLHTTP", {
                {"Open / Send", "HTTP network communication in script payloads"}
            }}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/idispatch/detect_suspicious_automation", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["suspicious_automation_patterns"] = {
            "Office process (WINWORD.EXE / EXCEL.EXE) creating WScript.Shell or Shell.Application COM object",
            "IDispatch::Invoke called with DISPATCH_METHOD for 'Run' / 'Exec' with hidden window flag (0)",
            "ADODB.Stream SaveToFile pointing to %APPDATA% or %STARTUP% directory"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
