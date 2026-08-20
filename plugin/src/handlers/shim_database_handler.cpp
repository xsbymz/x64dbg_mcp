#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_shim_database_routes(c_http_router& router) {
    router.post("/api/shim/enumerate_installed_databases", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["system_shim_databases"] = {
            {"sysmain.sdb", "%WINDIR%\\AppPatch\\sysmain.sdb (Main application compatibility database)"},
            {"apphelp.sdb", "%WINDIR%\\AppPatch\\apphelp.sdb (AppHelp messaging)"},
            {"drvmain.sdb", "%WINDIR%\\AppPatch\\drvmain.sdb (Driver compatibility fixes)"},
            {"msimain.sdb", "%WINDIR%\\AppPatch\\msimain.sdb (MSI installer shims)"}
        };
        result["custom_shim_registry_paths"] = {
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\Custom",
            "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB"
        };
        
        result["installed_custom_sdbs"] = json::array();
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\AppCompatFlags\\InstalledSDB", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD idx = 0;
            WCHAR sdbGuid[128] = {};
            DWORD sdbGuidLen = 128;
            while (RegEnumKeyExW(hKey, idx++, sdbGuid, &sdbGuidLen, nullptr, nullptr, nullptr, nullptr) == ERROR_SUCCESS) {
                char guidA[128] = {};
                WideCharToMultiByte(CP_UTF8, 0, sdbGuid, -1, guidA, sizeof(guidA), nullptr, nullptr);
                json entry;
                entry["guid"] = std::string(guidA);
                
                HKEY hSub = nullptr;
                if (RegOpenKeyExW(hKey, sdbGuid, 0, KEY_READ, &hSub) == ERROR_SUCCESS) {
                    WCHAR desc[MAX_PATH] = {};
                    DWORD descSz = sizeof(desc);
                    if (RegQueryValueExW(hSub, L"DatabaseDescription", nullptr, nullptr, (LPBYTE)desc, &descSz) == ERROR_SUCCESS) {
                        char descA[MAX_PATH] = {};
                        WideCharToMultiByte(CP_UTF8, 0, desc, -1, descA, sizeof(descA), nullptr, nullptr);
                        entry["description"] = std::string(descA);
                    }
                    WCHAR path[MAX_PATH] = {};
                    DWORD pathSz = sizeof(path);
                    if (RegQueryValueExW(hSub, L"DatabasePath", nullptr, nullptr, (LPBYTE)path, &pathSz) == ERROR_SUCCESS) {
                        char pathA[MAX_PATH] = {};
                        WideCharToMultiByte(CP_UTF8, 0, path, -1, pathA, sizeof(pathA), nullptr, nullptr);
                        entry["path"] = std::string(pathA);
                    }
                    RegCloseKey(hSub);
                }
                result["installed_custom_sdbs"].push_back(entry);
                sdbGuidLen = 128;
            }
            RegCloseKey(hKey);
        }
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/shim/parse_sdb_file", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string sdbPath = body.value("path", "C:\\Windows\\AppPatch\\sysmain.sdb");
        json result;
        result["sdb_path"] = sdbPath;
        result["sdb_binary_format"] = {
            {"INDEX_TAG", "Tag identifying database indexing root"},
            {"TAG_DATABASE", "0x7001 (Container for all shim definitions)"},
            {"TAG_LIBRARY", "0x7002 (Definitions of shim DLLs and fix routines)"},
            {"TAG_SHIM", "0x7004 (Specific shim implementation, e.g. InjectDLL)"},
            {"TAG_EXE", "0x7007 (Target executable matching criteria and applied shims)"},
            {"TAG_MATCHING_FILE", "0x7008 (File size, checksum, PE header attributes for activation)"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/shim/detect_malicious_shims", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["dangerous_shim_types"] = {
            {"InjectDLL", "Forces target process to load arbitrary DLL on initialization (Persistence)"},
            {"RedirectEXE", "Spawns alternate binary when target executable is invoked"},
            {"DisableNX / DisableASLR", "Strips exploit mitigations from targeted binary"},
            {"IgnoreFreeLibrary", "Prevents unloading of injected modules"},
            {"FakeVersionLie", "Spoofs OS version to manipulate application logic"}
        };
        result["mitre_technique"] = "T1546.011 (Event Triggered Execution: Application Shimming)";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
