#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_dcom_lateral_movement_routes(c_http_router& router) {
    router.post("/api/dcom/enumerate_remote_activations", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["dcom_activation_apis"] = {
            {"CoCreateInstanceEx", "Takes COSERVERINFO specifying remote IP/hostname and COAUTHINFO credentials"},
            {"CoGetClassObjectEx", "Retrieves remote class factory for distributed object creation"}
        };
        result["dcom_lateral_movement_clsids"] = {
            {"MMC20.Application", "{49B2791A-B1AE-4C90-9B8E-E860BA07F889} -> Document.ActiveView.ExecuteShellCommand"},
            {"ShellWindows", "{9BA05972-F6A8-11CF-A442-00A0C90A8F39} -> Item.Document.Application.ShellExecute"},
            {"ShellBrowserWindow", "{C08AFD90-F2A1-11D1-8455-00A0C91F3880} -> Document.Application.ShellExecute"},
            {"Excel.DDE", "{00024500-0000-0000-C000-000000000046} -> DDEInitiate execution"},
            {"ServiceLoader", "{BD96C556-65A3-11D0-983A-00C04FC29E36} -> RDS.DataSpace execution"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/dcom/detect_known_lm_clsids", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["detection_rules"] = {
            "Monitor RPC endpoint mapper (TCP 135) for incoming IRemoteActivation / IObjectExporter interface queries",
            "Track processes spawned by DCOM surrogates (dllhost.exe, mmc.exe, excel.exe) with non-interactive parent tokens",
            "Correlate Windows Event Log 4624 (Logon Type 3: Network) followed immediately by process creation"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/dcom/trace_coserverinfo_connections", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["investigation_workflow"] = "Inspect COSERVERINFO.pwszName to identify remote lateral movement destination hosts and authenticated user identity";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
