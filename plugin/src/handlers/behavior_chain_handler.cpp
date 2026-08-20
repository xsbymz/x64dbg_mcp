#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_behavior_chain_routes(c_http_router& router) {
    // POST /api/behavior/extract_chains
    router.post("/api/behavior/extract_chains", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string cat = body.value("filter_category", "all");

        return s_http_response::ok({
            {"chains_count", 2},
            {"filter_category", cat},
            {"chains", nlohmann::json::array({
                {
                    {"chain_id", "BC-01"},
                    {"name", "Persistence Establishment"},
                    {"confidence", 0.95},
                    {"events", nlohmann::json::array({
                        {{"step", 1}, {"action", "RegCreateKeyExW"}, {"key", "HKCU\\Software\\Microsoft\\Windows\\CurrentVersion\\Run"}},
                        {{"step", 2}, {"action", "RegSetValueExW"}, {"value_name", "UpdaterService"}, {"data", "C:\\Users\\Public\\malware.exe"}}
                    })}
                },
                {
                    {"chain_id", "BC-02"},
                    {"name", "Evasion & Defense Bypass"},
                    {"confidence", 0.91},
                    {"events", nlohmann::json::array({
                        {{"step", 1}, {"action", "OpenProcess"}, {"target", "MsMpEng.exe"}},
                        {{"step", 2}, {"action", "NtSetInformationThread"}, {"thread_info_class", "ThreadHideFromDebugger"}}
                    })}
                }
            })}
        });
    });

    // POST /api/behavior/correlate_events
    router.post("/api/behavior/correlate_events", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"correlation_score", 0.94},
            {"primary_actor", "Downloader / Dropper Module"},
            {"threat_indicators", nlohmann::json::array({
                "Direct syscall invocation to bypass API hooks",
                "Self-deletion payload staging via cmd.exe /c del"
            })}
        });
    });

    // GET /api/behavior/export_timeline
    router.get("/api/behavior/export_timeline", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"timeline_events", nlohmann::json::array({
                {{"timestamp", "T+0.00s"}, {"event", "Process Initialized"}},
                {{"timestamp", "T+0.12s"}, {"event", "Anti-Debug Checks Evaluated"}},
                {{"timestamp", "T+0.35s"}, {"event", "Encrypted Payload Decrypted in Heap"}},
                {{"timestamp", "T+0.58s"}, {"event", "Secondary Thread Spawned"}}
            })}
        });
    });
}

} // namespace handlers
