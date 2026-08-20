#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_thread_routes(c_http_router& router) {
    // GET /api/threads/list - List all threads
    router.get("/api/threads/list", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto result = bridge.get_thread_list();
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        return s_http_response::ok(result.value());
    });

    // GET /api/threads/current - Current thread info
    router.get("/api/threads/current", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto result = bridge.get_thread_list();
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        auto current_idx = result.value()["current_thread"].get<int>();
        const auto& threads = result.value()["threads"];

        for (const auto& t : threads) {
            if (t["number"].get<int>() == current_idx) {
                return s_http_response::ok(t);
            }
        }

        // Fallback: return first thread
        if (!threads.empty()) {
            return s_http_response::ok(threads[0]);
        }

        return s_http_response::not_found("No current thread");
    });

    // GET /api/threads/get?id=N - Specific thread by ID
    router.get("/api/threads/get", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto id_str = req.get_query("id");
        if (id_str.empty()) {
            return s_http_response::bad_request("Missing 'id' query parameter");
        }

        auto tid = std::stoul(id_str);
        auto result = bridge.get_thread_list();
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        for (const auto& t : result.value()["threads"]) {
            if (t["id"].get<DWORD>() == tid) {
                return s_http_response::ok(t);
            }
        }

        return s_http_response::not_found("Thread not found: " + id_str);
    });

    // POST /api/threads/switch - Switch active thread
    router.post("/api/threads/switch", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("id")) {
            return s_http_response::bad_request("Missing 'id' field");
        }

        auto tid = body["id"].get<DWORD>();
        auto cmd = "switchthread " + std::to_string(tid);
        bridge.exec_command(cmd);

        return s_http_response::ok({
            {"switched_to", tid},
            {"message",     "Switched to thread " + std::to_string(tid)}
        });
    });

    // POST /api/threads/suspend - Suspend thread
    router.post("/api/threads/suspend", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("id")) {
            return s_http_response::bad_request("Missing 'id' field");
        }

        auto tid = body["id"].get<DWORD>();
        auto cmd = "suspendthread " + std::to_string(tid);
        bridge.exec_command(cmd);

        return s_http_response::ok({{"id", tid}, {"suspended", true}});
    });

    // POST /api/threads/resume - Resume thread
    router.post("/api/threads/resume", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("id")) {
            return s_http_response::bad_request("Missing 'id' field");
        }

        auto tid = body["id"].get<DWORD>();
        auto cmd = "resumethread " + std::to_string(tid);
        bridge.exec_command(cmd);

        return s_http_response::ok({{"id", tid}, {"resumed", true}});
    });

    // GET /api/threads/count - Thread count
    router.get("/api/threads/count", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto result = bridge.get_thread_list();
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        return s_http_response::ok({{"count", result.value()["count"]}});
    });

    // GET /api/threads/teb?tid= - Get TEB address for thread
    router.get("/api/threads/teb", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto tid_str = req.get_query("tid");
        if (tid_str.empty()) {
            return s_http_response::bad_request("Missing 'tid' query parameter");
        }

        auto tid = static_cast<DWORD>(std::stoul(tid_str));
        auto teb = DbgGetTebAddress(tid);

        return s_http_response::ok({
            {"tid", tid},
            {"teb", format_utils::format_address(teb)},
            {"found", teb != 0}
        });
    });

    // GET /api/threads/name?tid= - Get thread name
    router.get("/api/threads/name", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto tid_str = req.get_query("tid");
        if (tid_str.empty()) {
            return s_http_response::bad_request("Missing 'tid' query parameter");
        }

        auto tid = static_cast<DWORD>(std::stoul(tid_str));
        char name[MAX_THREAD_NAME_SIZE] = {};
        auto found = DbgFunctions()->ThreadGetName(tid, name);

        return s_http_response::ok({
            {"tid", tid},
            {"name", std::string(name)},
            {"found", found}
        });
    });

    // GET /api/threads/contexts_all - Complete snapshot of all threads with CIP, TEB, Name, and Status
    router.get("/api/threads/contexts_all", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto list = bridge.get_thread_list();
        if (!list.has_value()) {
            return s_http_response::internal_error(list.error());
        }

        auto current_idx = list.value().value("current_thread", 0);
        auto thread_array = list.value().value("threads", nlohmann::json::array());

        auto enriched = nlohmann::json::array();
        for (const auto& t : thread_array) {
            DWORD tid = t.value("id", static_cast<DWORD>(0));
            auto teb = DbgGetTebAddress(tid);
            char name[MAX_THREAD_NAME_SIZE] = {};
            DbgFunctions()->ThreadGetName(tid, name);

            auto item = t;
            item["teb"] = format_utils::format_address(teb);
            item["name"] = std::string(name);
            item["is_current"] = (t.value("number", -1) == current_idx);
            enriched.push_back(item);
        }

        return s_http_response::ok({
            {"count",          enriched.size()},
            {"current_thread", current_idx},
            {"threads",        enriched}
        });
    });

    // GET /api/threads/context?tid= - Full thread context (GPRs, flags, debug regs)
    router.get("/api/threads/context", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto tid_str = req.get_query("tid", "");
        DWORD target_tid = 0;
        if (!tid_str.empty()) {
            target_tid = static_cast<DWORD>(std::stoul(tid_str));
        }

        auto reg_res = bridge.get_register_dump();
        auto flags = bridge.eval_expression("eflags");

        nlohmann::json context = {
            {"tid", target_tid ? target_tid : static_cast<DWORD>(bridge.eval_expression("$tid"))},
            {"eflags", format_utils::format_address(flags)}
        };

        if (reg_res.has_value()) {
            const auto& r = reg_res.value();
            context["rip"] = format_utils::format_address(r.regcontext.cip);
            context["rsp"] = format_utils::format_address(r.regcontext.csp);
            context["rbp"] = format_utils::format_address(r.regcontext.cbp);
            context["rax"] = format_utils::format_address(r.regcontext.cax);
            context["rbx"] = format_utils::format_address(r.regcontext.cbx);
            context["rcx"] = format_utils::format_address(r.regcontext.ccx);
            context["rdx"] = format_utils::format_address(r.regcontext.cdx);
            context["rsi"] = format_utils::format_address(r.regcontext.csi);
            context["rdi"] = format_utils::format_address(r.regcontext.cdi);
#ifdef _WIN64
            context["r8"]  = format_utils::format_address(r.regcontext.r8);
            context["r9"]  = format_utils::format_address(r.regcontext.r9);
            context["r10"] = format_utils::format_address(r.regcontext.r10);
            context["r11"] = format_utils::format_address(r.regcontext.r11);
            context["r12"] = format_utils::format_address(r.regcontext.r12);
            context["r13"] = format_utils::format_address(r.regcontext.r13);
            context["r14"] = format_utils::format_address(r.regcontext.r14);
            context["r15"] = format_utils::format_address(r.regcontext.r15);
#endif
            context["cs"] = r.regcontext.cs;
            context["ds"] = r.regcontext.ds;
            context["es"] = r.regcontext.es;
            context["fs"] = r.regcontext.fs;
            context["gs"] = r.regcontext.gs;
            context["ss"] = r.regcontext.ss;
        }

        return s_http_response::ok(context);
    });

    // POST /api/threads/context_set - Set thread context registers
    router.post("/api/threads/context_set", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            return s_http_response::bad_request("Invalid JSON body");
        }

        if (body.contains("tid")) {
            auto tid = body["tid"].get<DWORD>();
            auto cmd = "switchthread " + std::to_string(tid);
            bridge.exec_command(cmd);
        }

        const char* allowed_regs[] = {"rax", "rbx", "rcx", "rdx", "rsi", "rdi", "rbp", "rsp",
                                       "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15",
                                       "rip", "eflags", nullptr};
        nlohmann::json changed;

        for (int i = 0; allowed_regs[i]; ++i) {
            if (body.contains(allowed_regs[i])) {
                auto val = body[allowed_regs[i]].get<std::string>();
                auto addr = bridge.eval_expression(val);
                std::string cmd = std::string("set ") + allowed_regs[i] + " " + val;
                bridge.exec_command(cmd);
                changed[allowed_regs[i]] = format_utils::format_address(addr);
            }
        }

        return s_http_response::ok({
            {"success", true},
            {"changed", changed},
            {"message", "Registers updated"}
        });
    });
}

} // namespace handlers
