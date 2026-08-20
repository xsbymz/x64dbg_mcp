#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "util/trace_state.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

// Escape a string for safe inclusion in an x64dbg command line between double-quotes.
// Replaces '"' with '\"' so the command parser sees the correct token boundary.
static std::string escape_cmd_string(const std::string& s) {
    std::string out;
    out.reserve(s.size() + 4);
    for (char c : s) {
        if (c == '"') out += "\\";
        out += c;
    }
    return out;
}

void register_tracing_routes(c_http_router& router) {
    // GET /api/trace/status - Whether a run-trace is active (driven by the
    // CB_STARTTRACE / CB_STOPTRACE callbacks) and the file it writes to.
    router.get("/api/trace/status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok(mcp::trace_status());
    });

    // POST /api/trace/into - Trace into (conditional)
    router.post("/api/trace/into", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto condition = body.value("condition", "");
        auto max_steps = body.value("max_steps", "");
        auto log_text = body.value("log_text", "");

        std::string cmd = "TraceIntoConditional";
        if (!condition.empty()) {
            cmd += " " + condition;
        }
        if (!max_steps.empty()) {
            cmd += ", " + max_steps;
        }
        if (!log_text.empty()) {
            cmd += ", " + log_text;
        }

        auto success = bridge.exec_command_async(cmd);

        return s_http_response::ok({
            {"success", success},
            {"command", cmd},
            {"message", "Trace into started (async)"}
        });
    });

    // POST /api/trace/over - Trace over (conditional)
    router.post("/api/trace/over", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto condition = body.value("condition", "");
        auto max_steps = body.value("max_steps", "");
        auto log_text = body.value("log_text", "");

        std::string cmd = "TraceOverConditional";
        if (!condition.empty()) {
            cmd += " " + condition;
        }
        if (!max_steps.empty()) {
            cmd += ", " + max_steps;
        }
        if (!log_text.empty()) {
            cmd += ", " + log_text;
        }

        auto success = bridge.exec_command_async(cmd);

        return s_http_response::ok({
            {"success", success},
            {"command", cmd},
            {"message", "Trace over started (async)"}
        });
    });

    // POST /api/trace/run - Run to user code (RunToParty 0)
    router.post("/api/trace/run", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto party = body.value("party", "0"); // 0=user, 1=system

        auto cmd = "RunToParty " + party;
        auto success = bridge.exec_command_async(cmd);

        return s_http_response::ok({
            {"success", success},
            {"command", cmd},
            {"message", "Run to party started (async)"}
        });
    });

    // POST /api/trace/stop - Stop trace recording
    router.post("/api/trace/stop", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto success = bridge.exec_command("StopRunTrace");

        return s_http_response::ok({
            {"success", success},
            {"message", "Trace stopped"}
        });
    });

    // GET /api/trace/record/hitcount?address= - Get trace record hit count
    router.get("/api/trace/record/hitcount", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        auto hit_count = DbgFunctions()->GetTraceRecordHitCount(address);

        return s_http_response::ok({
            {"address",   format_utils::format_address(address)},
            {"hit_count", hit_count}
        });
    });

    // GET /api/trace/record/type?address= - Get trace record byte type
    router.get("/api/trace/record/type", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        auto byte_type = DbgFunctions()->GetTraceRecordByteType(address);

        std::string type_str;
        switch (byte_type) {
            case InstructionBody:      type_str = "InstructionBody"; break;
            case InstructionHeading:   type_str = "InstructionHeading"; break;
            case InstructionTailing:   type_str = "InstructionTailing"; break;
            case InstructionOverlapped: type_str = "InstructionOverlapped"; break;
            case DataByte:             type_str = "DataByte"; break;
            case DataWord:             type_str = "DataWord"; break;
            case DataDWord:            type_str = "DataDWord"; break;
            case DataQWord:            type_str = "DataQWord"; break;
            case DataFloat:            type_str = "DataFloat"; break;
            case DataDouble:           type_str = "DataDouble"; break;
            case DataLongDouble:       type_str = "DataLongDouble"; break;
            case DataXMM:              type_str = "DataXMM"; break;
            case DataYMM:              type_str = "DataYMM"; break;
            case DataMMX:              type_str = "DataMMX"; break;
            case DataMixed:            type_str = "DataMixed"; break;
            case InstructionDataMixed: type_str = "InstructionDataMixed"; break;
            default:                   type_str = "Unknown"; break;
        }

        return s_http_response::ok({
            {"address",   format_utils::format_address(address)},
            {"type",      type_str},
            {"type_id",   static_cast<int>(byte_type)}
        });
    });

    // POST /api/trace/record/set_type - Set trace record type for a page
    router.post("/api/trace/record/set_type", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address")) {
            return s_http_response::bad_request("Missing 'address' field");
        }

        auto address = bridge.eval_expression(body["address"].get<std::string>());
        auto type_id = body.value("type", 0);

        auto success = DbgFunctions()->SetTraceRecordType(address, static_cast<TRACERECORDTYPE>(type_id));

        return s_http_response::ok({
            {"success", success},
            {"address", format_utils::format_address(address)},
            {"type",    type_id}
        });
    });

    // POST /api/trace/animate - Animate command
    router.post("/api/trace/animate", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("command")) {
            return s_http_response::bad_request("Missing 'command' field");
        }

        auto command = body["command"].get<std::string>();
        auto success = DbgFunctions()->AnimateCommand(command.c_str());

        return s_http_response::ok({
            {"success", success},
            {"command", command}
        });
    });

    // POST /api/trace/conditional_run - Start a conditional trace run
    router.post("/api/trace/conditional_run", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto break_condition = body.value("break_condition", "");
        auto log_text = body.value("log_text", "");
        auto log_condition = body.value("log_condition", "");
        auto cmd_text = body.value("command_text", "");
        auto cmd_condition = body.value("command_condition", "");
        auto trace_type = body.value("type", "into"); // into or over

        // Apply the per-step log and command settings BEFORE starting the trace,
        // so they actually take effect (previously these were parsed and dropped).
        if (!log_text.empty()) {
            std::string log_cmd = "TraceSetLog \"" + escape_cmd_string(log_text) + "\"";
            if (!log_condition.empty()) {
                log_cmd += ", " + log_condition;
            }
            bridge.exec_command(log_cmd);
        }
        if (!cmd_text.empty()) {
            std::string trace_cmd = "TraceSetCommand \"" + escape_cmd_string(cmd_text) + "\"";
            if (!cmd_condition.empty()) {
                trace_cmd += ", " + cmd_condition;
            }
            bridge.exec_command(trace_cmd);
        }

        std::string cmd = (trace_type == "over") ? "TraceOverConditional" : "TraceIntoConditional";
        if (!break_condition.empty()) {
            cmd += " " + break_condition;
        }

        auto success = bridge.exec_command_async(cmd);

        return s_http_response::ok({
            {"success", success},
            {"command", cmd},
            {"type", trace_type},
            {"log_text", log_text},
            {"command_text", cmd_text},
            {"message", "Conditional trace started (async)"}
        });
    });

    // POST /api/trace/log - Setup trace logging
    router.post("/api/trace/log", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto file = body.value("file", "");
        auto text = body.value("text", "");
        auto condition = body.value("condition", "");

        if (file.empty()) {
            return s_http_response::bad_request("Missing 'file' field for trace log output");
        }

        // Configure trace logging: where the log goes, and what/when to log.
        // 'condition' is now honored (previously parsed and dropped).
        auto file_cmd = "TraceSetLogFile \"" + escape_cmd_string(file) + "\"";
        auto file_ok = bridge.exec_command(file_cmd);

        std::string log_cmd = "TraceSetLog";
        if (!text.empty()) {
            log_cmd += " \"" + escape_cmd_string(text) + "\"";
            if (!condition.empty()) {
                log_cmd += ", " + condition;
            }
        }
        auto log_ok = bridge.exec_command(log_cmd);

        return s_http_response::ok({
            {"success",   file_ok && log_ok},
            {"file",      file},
            {"text",      text},
            {"condition", condition},
            {"message",   "Trace log configured. Run a conditional trace to start logging."}
        });
    });

    // POST /api/telemetry/enable - Enable categorized API monitoring breakpoints
    router.post("/api/telemetry/enable", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto category = (!body.is_discarded()) ? body.value("category", "all") : "all";
        bool break_on_call = (!body.is_discarded()) ? body.value("break_on_call", false) : false;

        struct api_target {
            const char* category;
            const char* api_name;
        };

        const api_target targets[] = {
            {"file_io",    "kernel32.CreateFileW"},
            {"file_io",    "kernel32.CreateFileA"},
            {"file_io",    "kernel32.WriteFile"},
            {"file_io",    "kernel32.DeleteFileW"},
            {"registry",   "advapi32.RegOpenKeyExW"},
            {"registry",   "advapi32.RegSetValueExW"},
            {"registry",   "advapi32.RegQueryValueExW"},
            {"injection",  "kernel32.VirtualAllocEx"},
            {"injection",  "kernel32.WriteProcessMemory"},
            {"injection",  "kernel32.CreateRemoteThread"},
            {"injection",  "ntdll.NtQueueApcThread"},
            {"network",    "wininet.InternetOpenW"},
            {"network",    "wininet.HttpSendRequestW"},
            {"network",    "ws2_32.connect"},
            {"network",    "ws2_32.send"},
            {"anti_debug", "kernel32.IsDebuggerPresent"},
            {"anti_debug", "kernel32.CheckRemoteDebuggerPresent"},
            {"anti_debug", "ntdll.NtQueryInformationProcess"}
        };

        auto hooked = nlohmann::json::array();

        for (const auto& target : targets) {
            if (category != "all" && category != target.category) continue;

            std::string bp_cmd = std::string("bp ") + target.api_name;
            bridge.exec_command(bp_cmd);

            // Set log text
            std::string log_cmd = std::string("SetBreakpointLog ") + target.api_name + ", \"[TELEMETRY] " + target.api_name + " called from {cip}\"";
            bridge.exec_command(log_cmd);

            // If not breaking on call, set fast resume / silent
            if (!break_on_call) {
                std::string resume_cmd = std::string("SetBreakpointFastResume ") + target.api_name + ", 1";
                bridge.exec_command(resume_cmd);
                std::string silent_cmd = std::string("SetBreakpointSilent ") + target.api_name + ", 1";
                bridge.exec_command(silent_cmd);
            }

            hooked.push_back({
                {"category", target.category},
                {"api",      target.api_name}
            });
        }

        return s_http_response::ok({
            {"category",      category},
            {"break_on_call", break_on_call},
            {"hooked_count",  hooked.size()},
            {"hooks",         hooked}
        });
    });

    // POST /api/telemetry/disable - Remove telemetry breakpoints
    router.post("/api/telemetry/disable", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto category = (!body.is_discarded()) ? body.value("category", "all") : "all";

        const char* apis[] = {
            "kernel32.CreateFileW", "kernel32.CreateFileA", "kernel32.WriteFile", "kernel32.DeleteFileW",
            "advapi32.RegOpenKeyExW", "advapi32.RegSetValueExW", "advapi32.RegQueryValueExW",
            "kernel32.VirtualAllocEx", "kernel32.WriteProcessMemory", "kernel32.CreateRemoteThread", "ntdll.NtQueueApcThread",
            "wininet.InternetOpenW", "wininet.HttpSendRequestW", "ws2_32.connect", "ws2_32.send",
            "kernel32.IsDebuggerPresent", "kernel32.CheckRemoteDebuggerPresent", "ntdll.NtQueryInformationProcess"
        };

        for (const auto* api : apis) {
            bridge.exec_command(std::string("bc ") + api);
        }

        return s_http_response::ok({
            {"category", category},
            {"message",  "Telemetry breakpoints cleared"}
        });
    });
}

} // namespace handlers
