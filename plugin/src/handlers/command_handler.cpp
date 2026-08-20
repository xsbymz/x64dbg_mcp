#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "util/input_sanitizer.h"
#include "http/audit_logger.h"

#include <nlohmann/json.hpp>
#include "_dbgfunctions.h"

namespace handlers {

void register_command_routes(c_http_router& router) {
    // POST /api/command/exec - Execute x64dbg command
    router.post("/api/command/exec", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto& audit = get_audit_logger();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("command")) {
            return s_http_response::bad_request("Missing 'command' field");
        }

        auto command = body["command"].get<std::string>();
        
        if (!c_input_sanitizer::is_safe_command(command)) {
            audit.log_request(req, 400, req.client_ip);
            return s_http_response::bad_request("Command rejected: contains unsafe characters or whitelisted command violation");
        }

        auto success = bridge.exec_command(command);
        audit.log_request(req, success ? 200 : 500, req.client_ip);

        return s_http_response::ok({
            {"command", command},
            {"success", success}
        });
    });

    // POST /api/command/eval - Evaluate expression
    router.post("/api/command/eval", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto& audit = get_audit_logger();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("expression")) {
            return s_http_response::bad_request("Missing 'expression' field");
        }

        auto expression = body["expression"].get<std::string>();

        if (!c_input_sanitizer::is_safe_expression(expression)) {
            audit.log_request(req, 400, req.client_ip);
            return s_http_response::bad_request("Expression rejected: contains unsafe characters");
        }

        if (!bridge.is_valid_expression(expression)) {
            return s_http_response::bad_request("Invalid expression: " + expression);
        }

        auto value = bridge.eval_expression(expression);
        audit.log_request(req, 200, req.client_ip);

        return s_http_response::ok({
            {"expression", expression},
            {"value",      format_utils::format_address(value)},
            {"decimal",    value}
        });
    });

    // POST /api/command/batch - Execute multiple commands sequentially
    router.post("/api/command/batch", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto& audit = get_audit_logger();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("commands") || !body["commands"].is_array()) {
            return s_http_response::bad_request("Missing 'commands' array");
        }

        auto results = nlohmann::json::array();
        for (const auto& cmd_val : body["commands"]) {
            if (!cmd_val.is_string()) continue;
            auto cmd = cmd_val.get<std::string>();
            bool ok = false;
            if (c_input_sanitizer::is_safe_command(cmd)) {
                ok = bridge.exec_command(cmd);
            }
            results.push_back({
                {"command", cmd},
                {"success", ok}
            });
        }
        audit.log_request(req, 200, req.client_ip);
        return s_http_response::ok({{"results", results}});
    });

    // GET /api/command/history - Get command history
    router.get("/api/command/history", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({{"history", nlohmann::json::array()}});
    });

    // POST /api/command/execute_silent
    router.post("/api/command/execute_silent", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto& audit = get_audit_logger();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("command")) {
            return s_http_response::bad_request("Missing 'command' field");
        }
        auto cmd = body["command"].get<std::string>();
        bool ok = false;
        if (c_input_sanitizer::is_safe_command(cmd)) {
            ok = bridge.exec_command(cmd);
        }
        audit.log_request(req, ok ? 200 : 500, req.client_ip);
        return s_http_response::ok({{"command", cmd}, {"success", ok}});
    });

    // GET /api/command/db_hash - Get database hash
    router.get("/api/command/db_hash", [](const s_http_request&) -> s_http_response {
        auto hash = DbgFunctions()->DbGetHash();

        return s_http_response::ok({
            {"hash", format_utils::format_address(hash)}
        });
    });

    // POST /api/command/format - Format string using x64dbg expression engine
    router.post("/api/command/format", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("format")) {
            return s_http_response::bad_request("Missing 'format' field");
        }

        auto fmt = body["format"].get<std::string>();
        char result[1024] = {};
        auto success = DbgFunctions()->StringFormatInline(fmt.c_str(), sizeof(result), result);

        return s_http_response::ok({
            {"success", success},
            {"format",  fmt},
            {"result",  std::string(result)}
        });
    });

    // GET /api/command/events - Get debug event count
    router.get("/api/command/events", [](const s_http_request&) -> s_http_response {
        auto events = DbgFunctions()->GetDbgEvents();

        return s_http_response::ok({
            {"event_count", events}
        });
    });

    // POST /api/command/init_script - Set debuggee init script
    router.post("/api/command/init_script", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("file")) {
            return s_http_response::bad_request("Missing 'file' field");
        }

        auto file = body["file"].get<std::string>();
        DbgFunctions()->DbgSetDebuggeeInitScript(file.c_str());

        return s_http_response::ok({
            {"file", file},
            {"message", "Init script set"}
        });
    });

    // GET /api/command/init_script - Get debuggee init script
    router.get("/api/command/init_script", [](const s_http_request&) -> s_http_response {
        auto* script = DbgFunctions()->DbgGetDebuggeeInitScript();

        return s_http_response::ok({
            {"file", script ? std::string(script) : ""}
        });
    });

    // GET /api/command/hash - Get database hash
    router.get("/api/command/hash", [](const s_http_request&) -> s_http_response {
        auto hash = DbgFunctions()->DbGetHash();

        return s_http_response::ok({
            {"hash", format_utils::format_address(hash)}
        });
    });

    // POST /api/command/script - Execute batch of commands
    router.post("/api/command/script", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto& audit = get_audit_logger();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("commands")) {
            return s_http_response::bad_request("Missing 'commands' field (array of strings)");
        }

        auto commands = body["commands"];
        if (!commands.is_array()) {
            return s_http_response::bad_request("'commands' must be an array of strings");
        }

        auto results = nlohmann::json::array();
        int succeeded = 0;
        int failed = 0;

        for (const auto& cmd : commands) {
            auto cmd_str = cmd.get<std::string>();
            bool success = false;
            std::string error = "";
            
            if (!c_input_sanitizer::is_safe_command(cmd_str)) {
                error = "Unsafe command rejected";
            } else {
                success = bridge.exec_command(cmd_str);
                if (!success) error = "Command execution failed";
            }

            results.push_back({
                {"command", cmd_str},
                {"success", success},
                {"error", error}
            });

            if (success) ++succeeded;
            else ++failed;
        }

        audit.log_request(req, failed == 0 ? 200 : 400, req.client_ip);

        return s_http_response::ok({
            {"results",   results},
            {"total",     commands.size()},
            {"succeeded", succeeded},
            {"failed",    failed}
        });
    });

    // POST /api/command/evaluate_all - Evaluate multiple expressions in one call.
    router.post("/api/command/evaluate_all", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto& audit = get_audit_logger();

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("expressions") || !body["expressions"].is_object()) {
            return s_http_response::bad_request("Missing 'expressions' object field");
        }

        auto results = nlohmann::json::object();
        bool all_valid = true;
        for (const auto& [name, expr_val] : body["expressions"].items()) {
            if (!expr_val.is_string()) {
                results[name] = {{"error", "expression must be a string"}};
                all_valid = false;
                continue;
            }
            auto expr = expr_val.get<std::string>();
            if (!c_input_sanitizer::is_safe_expression(expr)) {
                results[name] = {
                    {"expression", expr},
                    {"error",      "expression rejected: contains unsafe characters"}
                };
                all_valid = false;
            } else if (!bridge.is_valid_expression(expr)) {
                results[name] = {
                    {"expression", expr},
                    {"error",      "invalid expression"}
                };
                all_valid = false;
            } else {
                auto value = bridge.eval_expression(expr);
                results[name] = {
                    {"expression", expr},
                    {"value",      format_utils::format_address(value)},
                    {"decimal",    value}
                };
            }
        }

        audit.log_request(req, all_valid ? 200 : 400, req.client_ip);

        return s_http_response::ok({{"results", results}});
    });

    // GET /api/command/log - Get debug event count & last command status
    router.get("/api/command/log", [](const s_http_request&) -> s_http_response {
        auto events = DbgFunctions()->GetDbgEvents();
        auto& bridge = get_bridge();

        return s_http_response::ok({
            {"event_count", events},
            {"state",       bridge.get_state_string()},
            {"is_running",  bridge.is_running()},
            {"is_debugging", bridge.is_debugging()}
        });
    });
}

} // namespace handlers
