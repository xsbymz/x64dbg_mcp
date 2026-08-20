#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_lateral_movement_routes(c_http_router& router) {
    router.post("/api/lateral_move/detect_psexec_indicators", [](const s_http_request& req) {
        json result;
        result["psexec_signatures"] = {
            {"Service_Creation", "Creation of PSEXESVC service via Service Control Manager (SCM RPC over named pipe \\\\.\\pipe\\svcctl)"},
            {"Named_Pipes", "\\\\.\\pipe\\psexecsvc-*, \\\\.\\pipe\\psexec*"},
            {"File_Staging", "PSEXESVC.exe written to %SystemRoot% (C:\\Windows) admin share (ADMIN$)"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/lateral_move/detect_winrm_activity", [](const s_http_request& req) {
        json result;
        result["winrm_powershell_remoting"] = {
            {"Ports", "HTTP 5985 / HTTPS 5986"},
            {"Host_Process", "wsmprovhost.exe spawned by svchost.exe (-k WinRM)"},
            {"User_Context", "Network logon token (Logon Type 3)"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/lateral_move/detect_wmi_execution", [](const s_http_request& req) {
        json result;
        result["wmi_lateral_movement"] = {
            {"WMI_Process_Creation", "WmiPrvSE.exe spawning cmd.exe / powershell.exe via Win32_Process.Create()"},
            {"WMIC_Remote", "wmic.exe /node:\"target\" process call create \"...\""},
            {"Event_Log", "Microsoft-Windows-WMI-Activity/Operational Event ID 5861"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

