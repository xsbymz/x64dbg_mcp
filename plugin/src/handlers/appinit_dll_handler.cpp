#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_appinit_dll_routes(c_http_router& router) {
    router.post("/api/appinit/read_configured_dlls", [](const s_http_request& req) {
        json result;
        result["registry_key"] = "HKLM\\SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows";
        
        HKEY hKey = nullptr;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, L"SOFTWARE\\Microsoft\\Windows NT\\CurrentVersion\\Windows", 0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            DWORD loadAppInit = 0;
            DWORD sz = sizeof(loadAppInit);
            if (RegQueryValueExW(hKey, L"LoadAppInit_DLLs", nullptr, nullptr, (LPBYTE)&loadAppInit, &sz) == ERROR_SUCCESS) {
                result["LoadAppInit_DLLs"] = loadAppInit;
            }
            DWORD requireSigned = 0;
            sz = sizeof(requireSigned);
            if (RegQueryValueExW(hKey, L"RequireSignedAppInit_DLLs", nullptr, nullptr, (LPBYTE)&requireSigned, &sz) == ERROR_SUCCESS) {
                result["RequireSignedAppInit_DLLs"] = requireSigned;
            }
            WCHAR appInitDlls[1024] = {};
            sz = sizeof(appInitDlls);
            if (RegQueryValueExW(hKey, L"AppInit_DLLs", nullptr, nullptr, (LPBYTE)appInitDlls, &sz) == ERROR_SUCCESS) {
                char dllsA[1024] = {};
                WideCharToMultiByte(CP_UTF8, 0, appInitDlls, -1, dllsA, sizeof(dllsA), nullptr, nullptr);
                result["AppInit_DLLs"] = std::string(dllsA);
            }
            RegCloseKey(hKey);
        }
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/appinit/verify_dll_signatures", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        json result;
        result["signature_verification_policy"] = {
            "Windows 8+ enforces RequireSignedAppInit_DLLs=1 when Secure Boot is active",
            "DLLs listed in AppInit_DLLs must have a valid Authenticode signature chaining to a trusted root",
            "Unsigned or self-signed DLLs will be rejected by User32.dll initialization in target processes"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/appinit/assess_load_state", [](const s_http_request& req) {
        json result;
        result["threat_impact"] = {
            "AppInit_DLLs injects specified libraries into every GUI process loading User32.dll",
            "Abused for system-wide API hooking, keystroke logging, credential theft, and persistent execution",
            "MITRE ATT&CK: T1546.010 (Event Triggered Execution: AppInit DLLs)"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

