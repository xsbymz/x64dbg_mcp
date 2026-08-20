#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_uefi_nvram_routes(c_http_router& router) {

    router.post("/api/uefi_nvram/enumerate_variables", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body=json::object(); }
        json result;
        result["variables"] = json::array();
        // Known critical UEFI NVRAM variables
        std::vector<std::pair<std::wstring,std::wstring>> knownVars = {
            {L"SecureBoot", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"},
            {L"SetupMode", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"},
            {L"AuditMode", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"},
            {L"DeployedMode", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"},
            {L"BootOrder", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"},
            {L"BootCurrent", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"},
            {L"OsIndicationsSupported", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"},
            {L"OsIndications", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"},
            {L"PlatformLangCodes", L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}"}
        };
        for (auto& [name, guid] : knownVars) {
            BYTE buf[256] = {};
            DWORD sz = sizeof(buf);
            BOOL ok = GetFirmwareEnvironmentVariableW(name.c_str(), guid.c_str(), buf, sz);
            json var;
            char nameA[128] = {};
            WideCharToMultiByte(CP_UTF8,0,name.c_str(),-1,nameA,sizeof(nameA),nullptr,nullptr);
            var["name"] = std::string(nameA);
            var["accessible"] = (ok != 0);
            if (ok && sz <= 8) {
                DWORD val = 0;
                memcpy(&val, buf, std::min((DWORD)sizeof(val), sz));
                var["value"] = val;
            }
            result["variables"].push_back(var);
        }
        result["setup_mode_note"] = "SetupMode=1 means Secure Boot platform key not enrolled — Secure Boot validation disabled";
        result["db_dbx_note"] = "db=allowed signatures, dbx=forbidden (revocation) list, KEK=key exchange key, PK=platform key";
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/uefi_nvram/read_variable", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body=json::object(); }
        std::string name = body.value("name","SecureBoot");
        std::string guid = body.value("guid","{8be4df61-93ca-11d2-aa0d-00e098032b8c}");
        json result;
        result["name"] = name;
        std::wstring wname(name.begin(),name.end()), wguid(guid.begin(),guid.end());
        BYTE buf[4096] = {};
        DWORD sz = sizeof(buf);
        BOOL ok = GetFirmwareEnvironmentVariableW(wname.c_str(), wguid.c_str(), buf, sz);
        result["success"] = (ok != 0);
        result["last_error"] = ok ? 0 : (int)GetLastError();
        if (ok) {
            result["size"] = sz;
            std::string hex;
            for (DWORD i = 0; i < std::min(sz,(DWORD)64); i++) { char h[3]; snprintf(h,3,"%02X",buf[i]); hex+=h; }
            result["data_hex"] = hex;
        }
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/uefi_nvram/check_secureboot_state", [](const httplib::Request&, httplib::Response& res) {
        json result;
        auto readVar = [](const wchar_t* name, const wchar_t* guid) -> int {
            BYTE buf[4] = {}; DWORD sz = sizeof(buf);
            return GetFirmwareEnvironmentVariableW(name,guid,buf,sz) ? buf[0] : -1;
        };
        const wchar_t* G = L"{8be4df61-93ca-11d2-aa0d-00e098032b8c}";
        int sb  = readVar(L"SecureBoot", G);
        int sm  = readVar(L"SetupMode",  G);
        int am  = readVar(L"AuditMode",  G);
        int dm  = readVar(L"DeployedMode",G);
        result["SecureBoot"]   = sb;
        result["SetupMode"]    = sm;
        result["AuditMode"]    = am;
        result["DeployedMode"] = dm;
        result["secureboot_active"] = (sb == 1 && sm == 0);
        result["attack_surface"] = {
            {"SetupMode_1","Platform key not enrolled — can enroll attacker-controlled PK"},
            {"SecureBoot_0","Boot validation disabled — any bootloader loads"},
            {"AuditMode_1","Audit mode — Secure Boot violations logged but not blocked"},
            {"db_manipulation","If db contains attacker-controlled certificate — can boot malicious EFI application"}
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
