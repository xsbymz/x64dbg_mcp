#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_scheduled_task_routes(c_http_router& router) {
    router.post("/api/sched_task/enumerate_all", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["tasks"] = json::array();
        
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(L"C:\\Windows\\System32\\Tasks\\*", &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                if (!(fd.dwFileAttributes & FILE_ATTRIBUTE_DIRECTORY)) {
                    char nameA[MAX_PATH] = {};
                    WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, nameA, sizeof(nameA), nullptr, nullptr);
                    json t;
                    t["task_name"] = std::string(nameA);
                    t["size"] = (DWORD)fd.nFileSizeLow;
                    result["tasks"].push_back(t);
                }
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        
        result["registry_tree_location"] = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Schedule\\TaskCache\\Tree";
        result["task_count"] = result["tasks"].size();
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/sched_task/parse_task_xml", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string taskName = body.value("task_name", "");
        json result;
        result["task_name"] = taskName;
        result["task_xml_structure"] = {
            {"RegistrationInfo", "Author, Description, URI, Version"},
            {"Triggers", "LogonTrigger, BootTrigger, TimeTrigger, EventTrigger, IdleTrigger"},
            {"Principals", "UserId, RunLevel (HighestAvailable / LeastPrivilege), LogonType"},
            {"Settings", "Hidden, DisallowStartIfOnBatteries, ExecutionTimeLimit"},
            {"Actions", "Exec (Command + Arguments + WorkingDir) or ComHandler (ClassId)"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/sched_task/detect_suspicious_tasks", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["suspicious_task_indicators"] = {
            "1. Task located in Windows root task folder instead of vendor subfolder",
            "2. Hidden=true attribute set in Settings with elevated RunLevel=HighestAvailable",
            "3. Action pointing to LOLBins (mshta, powershell, cmd, certutil, rundll32, regsvr32)",
            "4. Task XML missing Security Descriptor (SD) value in registry TaskCache (T1053.005 task hiding)",
            "5. Task executing from %TEMP%, %APPDATA%, or %PROGRAMDATA% directory"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
