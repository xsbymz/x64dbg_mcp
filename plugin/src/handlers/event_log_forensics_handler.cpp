#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_event_log_forensics_routes(c_http_router& router) {
    router.post("/api/evtx/parse_log_file", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string logPath = body.value("log_path", "C:\\Windows\\System32\\winevt\\Logs\\Security.evtx");
        json result;
        result["log_path"] = logPath;
        result["evtx_file_header"] = {
            {"Magic", "0x656C6646696C6500 ('ElfFile\\0')"},
            {"FirstChunkNumber", "0-based index of oldest chunk"},
            {"CurrentChunkNumber", "Index of most recent chunk"},
            {"NextRecordIdentifier", "Monotonically increasing record ID counter"},
            {"HeaderSize", "4096 bytes"},
            {"MinorVersion", "1 / 2"},
            {"MajorVersion", "3 (Windows Vista through 11)"},
            {"Flags", "1 = Dirty / In Use, 0 = Cleanly closed"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/evtx/detect_sequence_gaps", [](const s_http_request& req) {
        json result;
        result["gap_analysis_methodology"] = {
            "1. Read all EventRecord headers sequentially across chunks (ElfChnk magic 0x656C6643686E6B00)",
            "2. Extract EventRecordID (64-bit unsigned integer) from each record",
            "3. Verify sequence continuity: Record[N+1].ID == Record[N].ID + 1",
            "4. Flag any sequence jump (Record[N+1].ID > Record[N].ID + 1) as intentional anti-forensic record deletion"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/evtx/find_clearing_events", [](const s_http_request& req) {
        json result;
        result["audit_clearing_event_ids"] = {
            {"1102", "The audit log was cleared (Security Log — logged by Local Security Authority)"},
            {"104", "The log-file was cleared (System Log — logged by Eventlog service)"},
            {"1100", "The event logging service has shut down"},
            {"7034", "The Windows Event Log service terminated unexpectedly (crash induced to stop logging)"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

