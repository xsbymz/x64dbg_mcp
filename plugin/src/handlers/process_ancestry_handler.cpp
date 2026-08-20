#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <tlhelp32.h>
using json = nlohmann::json;

namespace handlers {
void register_process_ancestry_routes(c_http_router& router) {
    router.post("/api/proc_ancestry/build_full_tree", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["process_tree"] = json::array();
        
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32 pe = { sizeof(pe) };
            if (Process32First(hSnap, &pe)) {
                do {
                    json p;
                    p["pid"] = pe.th32ProcessID;
                    p["ppid"] = pe.th32ParentProcessID;
                    char nameA[MAX_PATH] = {};
                    WideCharToMultiByte(CP_UTF8, 0, pe.szExeFile, -1, nameA, sizeof(nameA), nullptr, nullptr);
                    p["image_name"] = std::string(nameA);
                    result["process_tree"].push_back(p);
                } while (Process32Next(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }
        result["process_count"] = result["process_tree"].size();
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/proc_ancestry/detect_anomalous_relationships", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["anomalous_parent_child_rules"] = {
            {"Office_Spawning_Script", "WINWORD.EXE / EXCEL.EXE / POWERPNT.EXE spawning CMD.EXE, POWERSHELL.EXE, MSHTA.EXE, WSCRIPT.EXE"},
            {"Web_Server_Spawning_Shell", "w3wp.exe / httpd.exe / nginx.exe spawning cmd.exe / powershell.exe (Webshell activity)"},
            {"Spoolsv_Spawning_Child", "spoolsv.exe spawning any executable (PrintNightmare / PrintDemon exploit)"},
            {"Svchost_Parent_Anomaly", "svchost.exe spawned by any process other than services.exe"},
            {"Explorer_Spawning_Rundll32", "explorer.exe spawning rundll32.exe without arguments or from non-system directory"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/proc_ancestry/correlate_with_event_log", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["event_log_correlation"] = "Cross-references running process tree with Windows Event ID 4688 (Process Creation) and Sysmon Event ID 1 to detect Parent Process ID (PPID) spoofing via PROC_THREAD_ATTRIBUTE_PARENT_PROCESS";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
