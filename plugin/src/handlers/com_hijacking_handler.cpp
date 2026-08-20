#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_com_hijacking_routes(c_http_router& router) {
    router.post("/api/com_hijack/scan_hkcu_overrides", [](const s_http_request& req) {
        json result;
        result["overrides"] = json::array();
        // Scan HKCU\Software\Classes\CLSID for COM hijacking entries
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_CURRENT_USER, L"Software\\Classes\\CLSID", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD idx=0; WCHAR name[256]; DWORD nameSz=256;
            while (RegEnumKeyExW(hKey,idx++,name,&(nameSz=256),nullptr,nullptr,nullptr,nullptr)==ERROR_SUCCESS) {
                json entry;
                char clsidA[64]={}; WideCharToMultiByte(CP_UTF8,0,name,-1,clsidA,sizeof(clsidA),nullptr,nullptr);
                entry["clsid"] = std::string(clsidA);
                // Check InprocServer32
                std::wstring subPath = std::wstring(name)+L"\\InprocServer32";
                HKEY hSub=nullptr;
                if (RegOpenKeyExW(hKey,subPath.c_str(),0,KEY_READ,&hSub)==ERROR_SUCCESS) {
                    WCHAR val[MAX_PATH]={}; DWORD valSz=sizeof(val);
                    if (RegQueryValueExW(hSub,nullptr,nullptr,nullptr,(LPBYTE)val,&(valSz=sizeof(val)))==ERROR_SUCCESS) {
                        char dll[MAX_PATH]={}; WideCharToMultiByte(CP_UTF8,0,val,-1,dll,sizeof(dll),nullptr,nullptr);
                        entry["inproc_server"] = std::string(dll);
                        // Check if this CLSID also exists in HKCR
                        HKEY hHkcr=nullptr;
                        std::wstring hkcrPath = L"CLSID\\" + std::wstring(name);
                        bool inHkcr = RegOpenKeyExW(HKEY_CLASSES_ROOT,hkcrPath.c_str(),0,KEY_READ,&hHkcr)==ERROR_SUCCESS;
                        entry["also_in_hkcr"] = inHkcr;
                        if (inHkcr) { RegCloseKey(hHkcr); entry["status"]="HIJACK — HKCU overrides HKCR entry"; }
                        else { entry["status"]="HKCU-only registration"; }
                        result["overrides"].push_back(entry);
                    }
                    RegCloseKey(hSub);
                }
            }
            RegCloseKey(hKey);
        }
        result["count"] = result["overrides"].size();
        result["technique"] = "T1546.015 — COM Object Hijacking (MITRE ATT&CK)";
        result["known_targets"] = {
            "{9BA05972-F6A8-11CF-A442-00A0C90A8F39}","ShellWindows",
            "{C08AFD90-F2A1-11D1-8455-00A0C91F3880}","ShellBrowserWindow"
        };
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/com_hijack/detect_dll_substitutions", [](const s_http_request& req) {
        json result;
        result["detection_logic"] = {
            "For each HKCU override that also has HKCR entry:",
            "1. Compare InprocServer32 DLL paths between HKCU and HKCR",
            "2. Flag if HKCU DLL is in %TEMP%, %APPDATA%, or user-writable path",
            "3. Check if HKCU DLL is signed and by whom",
            "4. Flag if HKCU DLL has different Company/Product from HKCR version"
        };
        result["high_risk_clsids"] = {
            {{"clsid","{D5978630-5B9F-11D1-8DD2-00AA004ABD5E}"},{"name","WBEM Scripting — WMI access"}},
            {{"clsid","{72C24DD5-D70A-438B-8A42-98424B88AFB8}"},{"name","WSH Shell"}},
            {{"clsid","{0D43FE01-F093-11CF-8940-00A0C9054228}"},{"name","FileSystemObject"}},
            {{"clsid","{13709620-C279-11CE-A49E-444553540000}"},{"name","Shell Automation Server"}}
        };
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/com_hijack/compare_hkcu_vs_hkcr", [](const s_http_request& req) {
        json result;
        result["comparison_methodology"] = {
            "Load list of all HKCU\\Software\\Classes\\CLSID entries",
            "For each: query HKCU InprocServer32, LocalServer32, TreatAs, ProgID",
            "Query same from HKCR\\CLSID",
            "Build diff table: same/different/missing — different = potential hijack"
        };
        result["persistence_longevity"] = "HKCU COM hijacking survives user-level AV scans, requires only user write access (no admin), and persists through reboots. Detection requires explicit HKCU vs HKCR comparison.";
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

