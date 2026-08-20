#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_named_pipe_c2_routes(c_http_router& router) {
    router.post("/api/pipe_c2/enumerate_all_pipes", [](const s_http_request& req) {
        json result;
        result["pipes"] = json::array();
        
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(L"\\\\.\\pipe\\*", &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                char nameA[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, nameA, sizeof(nameA), nullptr, nullptr);
                json p;
                p["pipe_name"] = std::string(nameA);
                result["pipes"].push_back(p);
            } while (FindNextFileW(h, &fd));
            FindClose(h);
        }
        result["pipe_count"] = result["pipes"].size();
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/pipe_c2/match_known_c2_patterns", [](const s_http_request& req) {
        json result;
        result["known_c2_pipe_signatures"] = {
            {"Cobalt_Strike_Default", "msagent_* / MSSE-*-server / postex_* / status_*"},
            {"Metasploit", "meterpreter_* / msf-pipe-*"},
            {"Empire", "empire_*"},
            {"Brute_Ratel", "b4* / badger_*"},
            {"Sliver", "sliver-pipe-* / pipe_srv_*"},
            {"Havoc_Demon", "demon_* / havoc_*"}
        };
        result["matching_logic"] = "Scan enumerated pipes against regular expressions for default C2 profile pipe names and malleable C2 SMB templates";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/pipe_c2/analyze_pipe_connections", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string pipeName = body.value("pipe_name", "");
        json result;
        result["pipe_name"] = pipeName;
        result["analysis_fields"] = {
            "Client process ID and security context",
            "Server process ID and DACL / SACL configuration",
            "Pipe mode (PIPE_TYPE_BYTE vs PIPE_TYPE_MESSAGE)",
            "Max instances and current open handle count",
            "Impersonation level granted to server (SecurityIdentification vs SecurityImpersonation)"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

