#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <string>
#include <vector>
#include <unordered_set>
#include <algorithm>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"

namespace handlers {

// ---------------------------------------------------------------------------
// Helpers
// ---------------------------------------------------------------------------

static std::string safe_snippet(const char* s, size_t max_len = 48) {
    std::string out;
    for (size_t i = 0; s[i] && i < max_len; ++i) {
        char c = s[i];
        out += (c >= 0x20 && c < 0x7F) ? c : '_';
    }
    return out;
}

// Derive an alphanumeric-safe label fragment from a string snippet.
static std::string label_from_string(const std::string& s) {
    std::string out;
    for (char c : s) {
        if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
            (c >= '0' && c <= '9') || c == '_') {
            out += c;
        } else {
            out += '_';
        }
        if (out.size() >= 24) break;
    }
    return out;
}

// ---------------------------------------------------------------------------

void register_autoannotate_routes(c_http_router& router) {

    // POST /api/annotate/function
    // One-shot: walk every instruction in a function and:
    //   - label call targets with their symbol name
    //   - comment LEA/MOV imm instructions that point to strings
    //   - label unnamed jump targets as jXX_<addr>
    //   - comment vtable indirect calls
    // Body: { "address": "0x...", "overwrite": false }
    router.post("/api/annotate/function", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body      = nlohmann::json::parse(req.body, nullptr, false);
        auto addr_str  = body.is_discarded() ? "cip" : body.value("address", "cip");
        bool overwrite = body.is_discarded() ? false : body.value("overwrite", false);

        auto address = bridge.eval_expression(addr_str);
        auto bounds  = bridge.get_function_bounds(address);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + addr_str +
                " — run 'analyze' first");
        }

        auto func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        auto func_end   = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        int calls_labelled  = 0;
        int strings_noted   = 0;
        int jumps_labelled  = 0;
        int vtable_noted    = 0;

        auto cur = func_start;
        while (cur <= func_end) {
            BASIC_INSTRUCTION_INFO bi{};
            DbgDisasmFastAt(cur, &bi);
            if (bi.size == 0) break;

            DISASM_INSTR di{};
            DbgDisasmAt(cur, &di);

            std::string instr_lower = di.instruction;
            std::transform(instr_lower.begin(), instr_lower.end(),
                           instr_lower.begin(), ::tolower);

            // ---- Call sites: label target with its symbol ----
            if (bi.call && bi.branch) {
                auto target = bi.addr;
                if (target != 0) {
                    char sym[MAX_LABEL_SIZE] = {};
                    bool has_sym = DbgGetLabelAt(target, SEG_DEFAULT, sym) && sym[0] != '\0';

                    if (!has_sym) {
                        // Try module.export
                        char mod[MAX_MODULE_SIZE] = {};
                        if (DbgGetModuleAt(target, mod) && mod[0] != '\0') {
                            auto sym_str = std::string(mod) + "_" +
                                           format_utils::format_address(target);
                            if (overwrite || bridge.get_label_at(target).empty()) {
                                bridge.set_label_at(target, sym_str);
                                calls_labelled++;
                            }
                        }
                    }

                    // Add comment at call site showing the called symbol
                    if (has_sym && (overwrite || bridge.get_comment_at(cur).empty())) {
                        bridge.set_comment_at(cur, std::string("call → ") + sym);
                        calls_labelled++;
                    }
                }
            }

            // ---- Branches / conditional jumps: label unnamed targets ----
            if (bi.branch && !bi.call) {
                auto target = bi.addr;
                if (target != 0 && target >= func_start && target <= func_end) {
                    if (overwrite || bridge.get_label_at(target).empty()) {
                        char existing[MAX_LABEL_SIZE] = {};
                        bool has = DbgGetLabelAt(target, SEG_DEFAULT, existing) && existing[0] != '\0';
                        if (!has) {
                            auto lbl = "j_" + format_utils::format_address(target);
                            bridge.set_label_at(target, lbl);
                            jumps_labelled++;
                        }
                    }
                }
            }

            // ---- Indirect calls (call [reg] / call [mem]) — vtable heuristic ----
            if (instr_lower.find("call") != std::string::npos && bi.addr == 0) {
                if (overwrite || bridge.get_comment_at(cur).empty()) {
                    bridge.set_comment_at(cur, "vtbl_call_" +
                        format_utils::format_address(cur));
                    vtable_noted++;
                }
            }

            // ---- LEA / MOV with immediate that points to a string ----
            bool is_lea = (instr_lower.find("lea ") == 0);
            bool is_mov = (instr_lower.find("mov ") == 0);

            if ((is_lea || is_mov) && di.arg[1].value != 0) {
                auto ptr = static_cast<duint>(di.arg[1].value);
                char str_buf[MAX_STRING_SIZE] = {};
                if (DbgGetStringAt(ptr, str_buf) && str_buf[0] != '\0') {
                    auto snippet = safe_snippet(str_buf);
                    if (overwrite || bridge.get_comment_at(cur).empty()) {
                        bridge.set_comment_at(cur, "\"" + snippet + "\"");
                        strings_noted++;
                    }
                }
            }

            cur += bi.size;
        }

        return s_http_response::ok({
            {"function_start",  bounds.value()["start"]},
            {"function_end",    bounds.value()["end"]},
            {"calls_labelled",  calls_labelled},
            {"strings_noted",   strings_noted},
            {"jumps_labelled",  jumps_labelled},
            {"vtable_noted",    vtable_noted},
            {"total",           calls_labelled + strings_noted + jumps_labelled + vtable_noted}
        });
    });

    // POST /api/annotate/module
    // Annotate all functions in the module at the current CIP (or specified module).
    // Body: { "module": "target.exe", "overwrite": false, "max_functions": 5000 }
    router.post("/api/annotate/module", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body    = nlohmann::json::parse(req.body, nullptr, false);
        auto module  = body.is_discarded() ? "" : body.value("module", "");
        bool overwrite = body.is_discarded() ? false : body.value("overwrite", false);
        int  max_fn  = body.is_discarded() ? 5000 : body.value("max_functions", 5000);
        if (max_fn > 50000) max_fn = 50000;

        if (module.empty()) {
            module = bridge.get_module_at(bridge.eval_expression("cip"));
        }
        if (module.empty()) return s_http_response::bad_request("Could not determine target module");

        auto base = bridge.get_module_base(module);
        if (base == 0) return s_http_response::not_found("Module not found: " + module);
        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));

        // Use x64dbg's function list
        BridgeList<FUNCTION_LOOP_INFO> fn_list;
        // Enumerate functions via Script API
        int funcs_done = 0;
        int total_annotations = 0;

        // Walk module scanning for function entries
        // (Iterate known xrefs as function entry proxies — full function DB walk via
        //  DbgFunctionEnum is the ideal path; fall back to scanning for known entries)
        // Simple approach: walk .text and find all function start boundaries
        auto cur = base;
        std::unordered_set<duint> visited_funcs;

        while (cur < base + size && funcs_done < max_fn) {
            duint fstart = 0, fend = 0;
            if (!DbgFunctionGet(cur, &fstart, &fend)) {
                cur++;
                continue;
            }
            if (visited_funcs.count(fstart)) {
                cur = fend + 1;
                continue;
            }
            visited_funcs.insert(fstart);

            // Annotate this function inline
            auto fn_cur = fstart;
            while (fn_cur <= fend) {
                BASIC_INSTRUCTION_INFO bi{};
                DbgDisasmFastAt(fn_cur, &bi);
                if (bi.size == 0) break;

                DISASM_INSTR di{};
                DbgDisasmAt(fn_cur, &di);

                if (bi.call && bi.branch && bi.addr != 0) {
                    char sym[MAX_LABEL_SIZE] = {};
                    DbgGetLabelAt(bi.addr, SEG_DEFAULT, sym);
                    if (sym[0] != '\0' && (overwrite || bridge.get_comment_at(fn_cur).empty())) {
                        bridge.set_comment_at(fn_cur, std::string("→ ") + sym);
                        total_annotations++;
                    }
                }

                bool is_lea = (di.instruction[0] == 'l' && di.instruction[1] == 'e' && di.instruction[2] == 'a');
                if (is_lea && di.arg[1].value != 0) {
                    char str_buf[MAX_STRING_SIZE] = {};
                    if (DbgGetStringAt(static_cast<duint>(di.arg[1].value), str_buf) && str_buf[0] != '\0') {
                        if (overwrite || bridge.get_comment_at(fn_cur).empty()) {
                            bridge.set_comment_at(fn_cur, "\"" + safe_snippet(str_buf) + "\"");
                            total_annotations++;
                        }
                    }
                }

                fn_cur += bi.size;
            }

            funcs_done++;
            cur = fend + 1;
        }

        return s_http_response::ok({
            {"module",            module},
            {"functions_scanned", funcs_done},
            {"total_annotations", total_annotations}
        });
    });

    // POST /api/annotate/clear
    // Remove all auto-generated comments matching a prefix.
    // Body: { "module": "...", "prefix": "\"" }  (default: clear all comments)
    router.post("/api/annotate/clear", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body   = nlohmann::json::parse(req.body, nullptr, false);
        auto module = body.is_discarded() ? "" : body.value("module", "");
        auto prefix = body.is_discarded() ? "" : body.value("prefix", "");

        if (module.empty()) {
            module = bridge.get_module_at(bridge.eval_expression("cip"));
        }
        if (module.empty()) return s_http_response::bad_request("Could not determine target module");

        auto base = bridge.get_module_base(module);
        if (base == 0) return s_http_response::not_found("Module not found: " + module);
        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));

        int cleared = 0;
        for (duint addr = base; addr < base + size; addr++) {
            auto cmt = bridge.get_comment_at(addr);
            if (!cmt.empty()) {
                bool should_clear = prefix.empty() || cmt.find(prefix) == 0;
                if (should_clear) {
                    bridge.set_comment_at(addr, "");
                    cleared++;
                }
            }
        }

        return s_http_response::ok({{"module", module}, {"cleared", cleared}});
    });

    // GET /api/annotate/export?module=&format=json|x64dbg_script
    // Export all labels and comments in a module.
    router.get("/api/annotate/export", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto module = req.get_query("module", "");
        auto fmt    = req.get_query("format", "json");

        if (module.empty()) {
            module = bridge.get_module_at(bridge.eval_expression("cip"));
        }
        if (module.empty()) return s_http_response::bad_request("Could not determine target module");

        auto base = bridge.get_module_base(module);
        if (base == 0) return s_http_response::not_found("Module not found: " + module);
        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));

        auto annotations = nlohmann::json::array();
        std::string script_output;

        for (duint addr = base; addr < base + size; addr++) {
            auto lbl = bridge.get_label_at(addr);
            auto cmt = bridge.get_comment_at(addr);

            if (!lbl.empty() || !cmt.empty()) {
                if (fmt == "json") {
                    annotations.push_back({
                        {"address", format_utils::format_address(addr)},
                        {"label",   lbl},
                        {"comment", cmt}
                    });
                } else {
                    // x64dbg script format
                    auto hex_addr = format_utils::format_address(addr);
                    if (!lbl.empty()) {
                        script_output += "SetLabel " + hex_addr + ", \"" + lbl + "\"\n";
                    }
                    if (!cmt.empty()) {
                        script_output += "SetComment " + hex_addr + ", \"" + cmt + "\"\n";
                    }
                }
            }
        }

        if (fmt == "json") {
            return s_http_response::ok({
                {"module",      module},
                {"format",      "json"},
                {"annotations", annotations},
                {"count",       annotations.size()}
            });
        } else {
            return s_http_response::ok({
                {"module", module},
                {"format", "x64dbg_script"},
                {"script", script_output},
                {"lines",  std::count(script_output.begin(), script_output.end(), '\n')}
            });
        }
    });
}

} // namespace handlers
