#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <sddl.h>
using json = nlohmann::json;

namespace handlers {

void register_token_chain_routes(c_http_router& router) {

    // Walk the full token impersonation chain across all threads
    router.post("/api/token_chain/walk_impersonation", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["threads"] = json::array();

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
        if (!hProcess) {
            result["error"] = "OpenProcess failed — pid=" + std::to_string(targetPid);
            res.set_content(result.dump(), "application/json");
            return;
        }

        // Enumerate threads
        HANDLE hSnap = CreateToolhelp32Snapshot(TH32CS_SNAPTHREAD, 0);
        if (hSnap != INVALID_HANDLE_VALUE) {
            THREADENTRY32 te = {sizeof(te)};
            if (Thread32First(hSnap, &te)) {
                do {
                    if (te.th32OwnerProcessID != targetPid) continue;

                    json tinfo;
                    tinfo["thread_id"] = te.th32ThreadID;

                    HANDLE hThread = OpenThread(THREAD_QUERY_INFORMATION, FALSE, te.th32ThreadID);
                    if (!hThread) { tinfo["error"] = "OpenThread failed"; result["threads"].push_back(tinfo); continue; }

                    HANDLE hToken = nullptr;
                    // Try to get impersonation token first
                    if (OpenThreadToken(hThread, TOKEN_QUERY, FALSE, &hToken)) {
                        tinfo["has_impersonation_token"] = true;

                        TOKEN_IMPERSONATION_LEVEL impLevel;
                        DWORD returned = 0;
                        if (GetTokenInformation(hToken, TokenImpersonationLevel, &impLevel, sizeof(impLevel), &returned)) {
                            static const char* levels[] = {"Anonymous","Identification","Impersonation","Delegation"};
                            tinfo["impersonation_level"] = (impLevel >= 0 && impLevel <= 3) ? levels[impLevel] : "Unknown";
                            tinfo["delegation_level"] = (impLevel >= SecurityDelegation);
                            if (impLevel >= SecurityDelegation) tinfo["flag"] = "HIGH RISK: Delegation-level impersonation — full Kerberos double-hop possible";
                        }

                        // Get impersonated user
                        DWORD siLen = 0;
                        GetTokenInformation(hToken, TokenUser, nullptr, 0, &siLen);
                        if (siLen > 0) {
                            std::vector<BYTE> siData(siLen);
                            if (GetTokenInformation(hToken, TokenUser, siData.data(), siLen, &siLen)) {
                                auto* tu = reinterpret_cast<TOKEN_USER*>(siData.data());
                                LPSTR sidStr = nullptr;
                                if (ConvertSidToStringSidA(tu->User.Sid, &sidStr)) {
                                    tinfo["impersonated_sid"] = std::string(sidStr);
                                    LocalFree(sidStr);
                                }
                                char userName[256] = {}, domainName[256] = {};
                                DWORD unLen = 256, dnLen = 256;
                                SID_NAME_USE snu;
                                if (LookupAccountSidA(nullptr, tu->User.Sid, userName, &unLen, domainName, &dnLen, &snu)) {
                                    tinfo["impersonated_user"] = std::string(domainName) + "\\" + std::string(userName);
                                }
                            }
                        }
                        CloseHandle(hToken);
                    } else {
                        tinfo["has_impersonation_token"] = false;
                    }

                    CloseHandle(hThread);
                    result["threads"].push_back(tinfo);
                } while (Thread32Next(hSnap, &te));
            }
            CloseHandle(hSnap);
        }
        CloseHandle(hProcess);
        res.set_content(result.dump(), "application/json");
    });

    // Map token ancestry DAG for the process
    router.post("/api/token_chain/map_ancestry_dag", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
        if (!hProcess) { result["error"] = "OpenProcess failed"; res.set_content(result.dump(), "application/json"); return; }

        HANDLE hProcToken = nullptr;
        if (OpenProcessToken(hProcess, TOKEN_QUERY | TOKEN_QUERY_SOURCE, &hProcToken)) {
            // Token type
            TOKEN_TYPE tokenType;
            DWORD returned = 0;
            if (GetTokenInformation(hProcToken, TokenType, &tokenType, sizeof(tokenType), &returned)) {
                result["token_type"] = (tokenType == TokenPrimary) ? "Primary" : "Impersonation";
            }

            // Token user
            DWORD siLen = 0;
            GetTokenInformation(hProcToken, TokenUser, nullptr, 0, &siLen);
            if (siLen > 0) {
                std::vector<BYTE> siData(siLen);
                if (GetTokenInformation(hProcToken, TokenUser, siData.data(), siLen, &siLen)) {
                    auto* tu = reinterpret_cast<TOKEN_USER*>(siData.data());
                    char userName[256] = {}, domainName[256] = {};
                    DWORD unLen = 256, dnLen = 256;
                    SID_NAME_USE snu;
                    if (LookupAccountSidA(nullptr, tu->User.Sid, userName, &unLen, domainName, &dnLen, &snu)) {
                        result["process_user"] = std::string(domainName) + "\\" + std::string(userName);
                    }
                }
            }

            // Token statistics (includes AuthenticationId / LUID)
            TOKEN_STATISTICS stats = {};
            if (GetTokenInformation(hProcToken, TokenStatistics, &stats, sizeof(stats), &returned)) {
                result["token_id_luid"] = (uint64_t)stats.TokenId.LowPart | ((uint64_t)stats.TokenId.HighPart << 32);
                result["auth_id_luid"] = (uint64_t)stats.AuthenticationId.LowPart | ((uint64_t)stats.AuthenticationId.HighPart << 32);
                result["token_created_time"] = stats.ExpirationTime.QuadPart;
                result["modified_id_luid"] = (uint64_t)stats.ModifiedId.LowPart | ((uint64_t)stats.ModifiedId.HighPart << 32);
            }

            // Integrity level
            DWORD ilLen = 0;
            GetTokenInformation(hProcToken, TokenIntegrityLevel, nullptr, 0, &ilLen);
            if (ilLen > 0) {
                std::vector<BYTE> ilData(ilLen);
                if (GetTokenInformation(hProcToken, TokenIntegrityLevel, ilData.data(), ilLen, &ilLen)) {
                    auto* tml = reinterpret_cast<TOKEN_MANDATORY_LABEL*>(ilData.data());
                    DWORD rid = *GetSidSubAuthority(tml->Label.Sid, *GetSidSubAuthorityCount(tml->Label.Sid) - 1);
                    result["integrity_level_rid"] = rid;
                    result["integrity_level"] = (rid >= 0x4000) ? "System" : (rid >= 0x3000) ? "High" :
                        (rid >= 0x2000) ? "Medium" : (rid >= 0x1000) ? "Low" : "Untrusted";
                }
            }

            CloseHandle(hProcToken);
        }
        CloseHandle(hProcess);

        result["dag_note"] = "Full ancestry DAG (AuthenticationId chain across parent processes) requires walking all process tokens and correlating LUID logon sessions — use /api/lsass/list_sessions for full chain reconstruction.";
        res.set_content(result.dump(), "application/json");
    });

    // Detect privilege escalation paths
    router.post("/api/token_chain/detect_escalation_paths", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["escalation_paths"] = json::array();

        HANDLE hProcess = OpenProcess(PROCESS_QUERY_INFORMATION, FALSE, targetPid);
        if (!hProcess) { result["error"] = "OpenProcess failed"; res.set_content(result.dump(), "application/json"); return; }

        HANDLE hToken = nullptr;
        if (!OpenProcessToken(hProcess, TOKEN_QUERY, &hToken)) {
            CloseHandle(hProcess);
            result["error"] = "OpenProcessToken failed";
            res.set_content(result.dump(), "application/json");
            return;
        }

        // Check for elevatable (present but disabled) privileges
        struct EscPriv { DWORD luid_low; const char* name; const char* escalation; };
        EscPriv escalatable[] = {
            {0x14,"SeDebugPrivilege","Open handles to any process — read LSASS, inject code"},
            {0x07,"SeTakeOwnershipPrivilege","Take ownership of any object"},
            {0x0B,"SeLoadDriverPrivilege","Load arbitrary kernel driver — kernel code execution"},
            {0x0C,"SeSystemProfilePrivilege","System-level profiling — potential info leak"},
            {0x0F,"SeBackupPrivilege","Read any file bypassing ACLs"},
            {0x12,"SeImpersonatePrivilege","Impersonate any token — RottenPotato/PrintSpoofer EoP"},
            {0x20,"SeAssignPrimaryTokenPrivilege","Replace process token — spawn SYSTEM process"},
            {0x23,"SeTcbPrivilege","Act as part of OS — create arbitrary tokens"},
            {0x01C,"SeCreateTokenPrivilege","Create arbitrary access tokens"}
        };

        DWORD tpLen = 0;
        GetTokenInformation(hToken, TokenPrivileges, nullptr, 0, &tpLen);
        if (tpLen > 0) {
            std::vector<BYTE> tpData(tpLen);
            if (GetTokenInformation(hToken, TokenPrivileges, tpData.data(), tpLen, &tpLen)) {
                auto* tp = reinterpret_cast<TOKEN_PRIVILEGES*>(tpData.data());
                for (DWORD i = 0; i < tp->PrivilegeCount; i++) {
                    auto& p = tp->Privileges[i];
                    for (auto& ep : escalatable) {
                        if (p.Luid.LowPart == ep.luid_low) {
                            bool enabled = (p.Attributes & SE_PRIVILEGE_ENABLED) != 0;
                            bool present = true;
                            if (present) {
                                json path;
                                path["privilege"] = ep.name;
                                path["enabled"] = enabled;
                                path["present_but_disabled"] = (!enabled);
                                path["escalation_technique"] = ep.escalation;
                                path["risk"] = (!enabled) ? "Medium — can be enabled with AdjustTokenPrivileges" : "High — immediately usable";
                                result["escalation_paths"].push_back(path);
                            }
                        }
                    }
                }
            }
        }

        CloseHandle(hToken);
        CloseHandle(hProcess);
        result["count"] = result["escalation_paths"].size();
        result["note"] = "Privileges listed as Present-but-Disabled can often be re-enabled by the process itself via AdjustTokenPrivileges(TOKEN_ADJUST_PRIVILEGES) without elevation — critical EoP finding.";
        res.set_content(result.dump(), "application/json");
    });
}

} // namespace handlers
