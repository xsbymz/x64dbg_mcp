#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <string>
#include <vector>
#include <thread>
#include <chrono>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_plugins.h"

namespace handlers {

// ---------------------------------------------------------------------------
// Script engine — interpret a JSON array of steps as a debugging script.
// Supported ops:
//   bp        { address }                         — set software breakpoint
//   bp_hw     { address, type: "x|r|w" }          — hardware breakpoint
//   bp_clear  { address }                         — remove breakpoint
//   run       { wait_ms? }                        — run + wait for pause
//   step_into { count? }                          — step into N times
//   step_over { count? }                          — step over N times
//   step_out  {}                                  — step out of function
//   eval      { name, expression }               — evaluate expression, save as var
//   log       { message? | expr? }               — log to x64dbg log
//   comment   { address, text }                  — set comment at address
//   label     { address, text }                  — set label at address
//   assert    { expression, op, value, msg? }    — fail script if false
//   loop      { count, steps[] }                 — repeat steps N times
//   if_eq     { left, right, then[] }            — conditional block
//   sleep     { ms }                             — wait
//   command   { cmd }                            — raw x64dbg command (whitelist only)
// ---------------------------------------------------------------------------

struct script_context {
    std::unordered_map<std::string, duint> vars;
    nlohmann::json log = nlohmann::json::array();
    int            step_index = 0;
    bool           aborted    = false;
    std::string    abort_reason;
};

static void log_step(script_context& ctx, int idx, const std::string& op,
                     bool ok, const std::string& detail = "") {
    ctx.log.push_back({
        {"step",   idx},
        {"op",     op},
        {"ok",     ok},
        {"detail", detail}
    });
}

// Safely execute a whitelisted x64dbg command from a script step
static bool safe_exec(c_bridge_executor& bridge, const std::string& cmd) {
    static const std::string SAFE[] = {
        "AnalyzeModule", "AnalyzeModuleEx", "Analyze",
        "bp", "bphws", "bphwc", "bphwd", "bpc",
        "SetBreakpointName", "SetBreakpointCondition",
        "run", "pause", "StepInto", "StepOver", "StepOut", "restart"
    };
    auto space = cmd.find(' ');
    auto verb  = (space == std::string::npos) ? cmd : cmd.substr(0, space);
    for (const auto& s : SAFE) {
        if (_stricmp(s.c_str(), verb.c_str()) == 0) {
            return bridge.exec_command(cmd);
        }
    }
    return false;
}

// Execute a single step object; return false to abort script.
static bool exec_step(c_bridge_executor& bridge, const nlohmann::json& step,
                      script_context& ctx, int idx);

// Execute a steps array (used for loop/if bodies).
static bool exec_steps(c_bridge_executor& bridge, const nlohmann::json& steps,
                       script_context& ctx) {
    if (!steps.is_array()) return true;
    for (size_t i = 0; i < steps.size(); ++i) {
        if (!exec_step(bridge, steps[i], ctx, static_cast<int>(i))) return false;
        if (ctx.aborted) return false;
    }
    return true;
}

static bool exec_step(c_bridge_executor& bridge, const nlohmann::json& step,
                      script_context& ctx, int idx) {
    if (!step.is_object() || !step.contains("op")) {
        log_step(ctx, idx, "?", false, "Missing 'op' field");
        return false;
    }

    auto op = step["op"].get<std::string>();

    // ---- bp ----------------------------------------------------------------
    if (op == "bp") {
        if (!step.contains("address")) { log_step(ctx, idx, op, false, "Missing address"); return true; }
        auto addr = step["address"].get<std::string>();
        bool ss   = step.value("single_shot", false);
        auto cmd  = std::string("bp ") + addr + (ss ? ", ss" : "");
        bool ok   = bridge.exec_command(cmd);
        log_step(ctx, idx, op, ok, addr);
        return true;
    }

    // ---- bp_hw -------------------------------------------------------------
    if (op == "bp_hw") {
        if (!step.contains("address")) { log_step(ctx, idx, op, false, "Missing address"); return true; }
        auto addr = step["address"].get<std::string>();
        auto type = step.value("hw_type", "x");
        auto cmd  = std::string("bphws ") + addr + ", " + type + ", 1";
        bool ok   = bridge.exec_command(cmd);
        log_step(ctx, idx, op, ok, addr + " type=" + type);
        return true;
    }

    // ---- bp_clear ----------------------------------------------------------
    if (op == "bp_clear") {
        if (!step.contains("address")) { log_step(ctx, idx, op, false, "Missing address"); return true; }
        auto addr = step["address"].get<std::string>();
        bool ok   = bridge.exec_command("bpc " + addr);
        log_step(ctx, idx, op, ok, addr);
        return true;
    }

    // ---- run ---------------------------------------------------------------
    if (op == "run") {
        int wait_ms = step.value("wait_ms", 10000);
        if (wait_ms < 0)     wait_ms = 0;
        if (wait_ms > 60000) wait_ms = 60000;
        bridge.exec_command("run");
        bool ok = bridge.wait_for_pause(wait_ms);
        auto cip = format_utils::format_address(bridge.eval_expression("cip"));
        log_step(ctx, idx, op, ok, ok ? ("paused at " + cip) : "timeout");
        return true;
    }

    // ---- step_into ---------------------------------------------------------
    if (op == "step_into") {
        int count = step.value("count", 1);
        if (count < 1) count = 1;
        if (count > 10000) count = 10000;
        bool ok = true;
        for (int i = 0; i < count && ok; ++i) {
            ok = bridge.exec_command_and_wait("StepInto", 5000);
        }
        auto cip = format_utils::format_address(bridge.eval_expression("cip"));
        log_step(ctx, idx, op, ok, "count=" + std::to_string(count) + " cip=" + cip);
        return true;
    }

    // ---- step_over ---------------------------------------------------------
    if (op == "step_over") {
        int count = step.value("count", 1);
        if (count < 1) count = 1;
        if (count > 10000) count = 10000;
        bool ok = true;
        for (int i = 0; i < count && ok; ++i) {
            ok = bridge.exec_command_and_wait("StepOver", 5000);
        }
        auto cip = format_utils::format_address(bridge.eval_expression("cip"));
        log_step(ctx, idx, op, ok, "count=" + std::to_string(count) + " cip=" + cip);
        return true;
    }

    // ---- step_out ----------------------------------------------------------
    if (op == "step_out") {
        bool ok = bridge.exec_command_and_wait("StepOut", 30000);
        auto cip = format_utils::format_address(bridge.eval_expression("cip"));
        log_step(ctx, idx, op, ok, "cip=" + cip);
        return true;
    }

    // ---- eval --------------------------------------------------------------
    if (op == "eval") {
        if (!step.contains("name") || !step.contains("expression")) {
            log_step(ctx, idx, op, false, "Missing name/expression");
            return true;
        }
        auto name = step["name"].get<std::string>();
        auto expr = step["expression"].get<std::string>();
        auto val  = bridge.eval_expression(expr);
        ctx.vars[name] = val;
        log_step(ctx, idx, op, true,
                 name + " = " + format_utils::format_address(val) +
                 " (" + std::to_string(val) + ")");
        return true;
    }

    // ---- log ---------------------------------------------------------------
    if (op == "log") {
        std::string msg;
        if (step.contains("expr")) {
            auto expr = step["expr"].get<std::string>();
            auto val  = bridge.eval_expression(expr);
            msg = expr + " = " + format_utils::format_address(val);
        } else {
            msg = step.value("message", "(no message)");
        }
        _plugin_logprintf("[Script] %s\n", msg.c_str());
        log_step(ctx, idx, op, true, msg);
        return true;
    }

    // ---- comment -----------------------------------------------------------
    if (op == "comment") {
        if (!step.contains("address") || !step.contains("text")) {
            log_step(ctx, idx, op, false, "Missing address/text"); return true;
        }
        auto addr = bridge.eval_expression(step["address"].get<std::string>());
        auto text = step["text"].get<std::string>();
        bool ok   = bridge.set_comment_at(addr, text);
        log_step(ctx, idx, op, ok, format_utils::format_address(addr));
        return true;
    }

    // ---- label -------------------------------------------------------------
    if (op == "label") {
        if (!step.contains("address") || !step.contains("text")) {
            log_step(ctx, idx, op, false, "Missing address/text"); return true;
        }
        auto addr = bridge.eval_expression(step["address"].get<std::string>());
        auto text = step["text"].get<std::string>();
        bool ok   = bridge.set_label_at(addr, text);
        log_step(ctx, idx, op, ok, format_utils::format_address(addr));
        return true;
    }

    // ---- assert ------------------------------------------------------------
    if (op == "assert") {
        if (!step.contains("expression")) { log_step(ctx, idx, op, false, "Missing expression"); return true; }
        auto expr = step["expression"].get<std::string>();
        auto expected = step.value("value", 0ULL);
        auto actual   = bridge.eval_expression(expr);
        auto op_str   = step.value("op", "eq");
        bool passed   = (op_str == "eq")  ? (actual == expected) :
                        (op_str == "ne")  ? (actual != expected) :
                        (op_str == "gt")  ? (actual >  expected) :
                        (op_str == "lt")  ? (actual <  expected) : false;
        auto msg = step.value("msg", expr + " " + op_str + " " + std::to_string(expected));
        log_step(ctx, idx, op, passed, msg);
        if (!passed) {
            ctx.aborted     = true;
            ctx.abort_reason = "Assertion failed: " + msg + " (actual=" + std::to_string(actual) + ")";
        }
        return passed;
    }

    // ---- loop --------------------------------------------------------------
    if (op == "loop") {
        int count = step.value("count", 1);
        if (count < 1) count = 1;
        if (count > 100000) count = 100000;
        auto body = step.value("steps", nlohmann::json::array());
        int completed = 0;
        for (int i = 0; i < count && !ctx.aborted; ++i) {
            if (!exec_steps(bridge, body, ctx)) break;
            completed++;
        }
        log_step(ctx, idx, op, !ctx.aborted,
                 "count=" + std::to_string(count) + " completed=" + std::to_string(completed));
        return !ctx.aborted;
    }

    // ---- if_eq -------------------------------------------------------------
    if (op == "if_eq" || op == "if") {
        auto left  = bridge.eval_expression(step.value("left", "0"));
        auto right = step.value("right", 0ULL);
        bool cond  = (left == right);
        log_step(ctx, idx, op, true,
                 "left=" + std::to_string(left) +
                 " right=" + std::to_string(right) +
                 " branch=" + (cond ? "then" : "else"));
        if (cond && step.contains("then")) {
            exec_steps(bridge, step["then"], ctx);
        } else if (!cond && step.contains("else")) {
            exec_steps(bridge, step["else"], ctx);
        }
        return !ctx.aborted;
    }

    // ---- sleep -------------------------------------------------------------
    if (op == "sleep") {
        int ms = step.value("ms", 0);
        if (ms > 0 && ms <= 30000) {
            std::this_thread::sleep_for(std::chrono::milliseconds(ms));
        }
        log_step(ctx, idx, op, true, "ms=" + std::to_string(ms));
        return true;
    }

    // ---- command -----------------------------------------------------------
    if (op == "command") {
        if (!step.contains("cmd")) { log_step(ctx, idx, op, false, "Missing cmd"); return true; }
        auto cmd = step["cmd"].get<std::string>();
        bool ok  = safe_exec(bridge, cmd);
        log_step(ctx, idx, op, ok, cmd);
        return true;
    }

    log_step(ctx, idx, op, false, "Unknown op: " + op);
    return true;
}

// ---------------------------------------------------------------------------

void register_script_engine_routes(c_http_router& router) {

    // POST /api/script/run
    // Body: { "steps": [...], "stop_on_error": false }
    router.post("/api/script/run", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("steps") || !body["steps"].is_array()) {
            return s_http_response::bad_request("Missing 'steps' array");
        }

        const auto& steps = body["steps"];
        if (steps.size() > 1000) {
            return s_http_response::bad_request("Too many steps (max 1000)");
        }

        script_context ctx;
        auto start = std::chrono::steady_clock::now();

        for (size_t i = 0; i < steps.size(); ++i) {
            if (ctx.aborted) break;
            exec_step(bridge, steps[i], ctx, static_cast<int>(i));
        }

        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - start).count();

        // Collect final variable values
        auto final_vars = nlohmann::json::object();
        for (const auto& [k, v] : ctx.vars) {
            final_vars[k] = {
                {"hex",     format_utils::format_address(v)},
                {"decimal", v}
            };
        }

        // Final register snapshot if paused
        nlohmann::json reg_snap = nullptr;
        if (bridge.is_debugging() && !bridge.is_running()) {
            reg_snap = {
                {"cip", format_utils::format_address(bridge.eval_expression("cip"))},
                {"rax", format_utils::format_address(bridge.eval_expression("rax"))},
                {"rsp", format_utils::format_address(bridge.eval_expression("rsp"))}
            };
        }

        return s_http_response::ok({
            {"completed",    !ctx.aborted},
            {"steps_run",    ctx.log.size()},
            {"aborted",      ctx.aborted},
            {"abort_reason", ctx.abort_reason},
            {"elapsed_ms",   elapsed},
            {"log",          ctx.log},
            {"variables",    final_vars},
            {"registers",    reg_snap}
        });
    });

    // GET /api/script/builtins — list all supported ops
    router.get("/api/script/builtins", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"ops", nlohmann::json::array({
                "bp", "bp_hw", "bp_clear",
                "run", "step_into", "step_over", "step_out",
                "eval", "log", "comment", "label",
                "assert", "loop", "if_eq", "if",
                "sleep", "command"
            })},
            {"max_steps", 1000},
            {"max_loop_count", 100000}
        });
    });
}

} // namespace handlers
