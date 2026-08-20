#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"
#include "util/path_sanitizer.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

#include <fstream>
#include <sstream>

namespace handlers {

static std::string resolve_session_path(const std::string& name, const std::string& optional_file = "") {
    std::string dump_dir = c_path_sanitizer::get_dump_directory();

    if (!optional_file.empty()) {
        const auto direct = c_path_sanitizer::sanitize_path(optional_file, dump_dir);
        if (!direct.empty()) {
            return direct;
        }

        const auto safe_name = c_path_sanitizer::get_safe_filename(optional_file);
        if (!safe_name.empty()) {
            return dump_dir + "\\" + safe_name;
        }
    }

    const auto safe_name = c_path_sanitizer::get_safe_filename(name);
    if (safe_name.empty()) {
        return "";
    }

    return dump_dir + "\\session_" + safe_name + ".json";
}

static bool restore_breakpoints_from_session(c_bridge_executor& bridge, const nlohmann::json& session) {
    if (!session.contains("breakpoints") || !session["breakpoints"].is_array()) {
        return true;
    }

    for (const auto& bp : session["breakpoints"]) {
        if (!bp.is_object()) continue;

        auto address_it = bp.find("address");
        if (address_it == bp.end() || !address_it->is_string()) continue;

        std::string address = address_it->get<std::string>();
        if (address.empty()) continue;

        auto resolved = bridge.eval_expression(address);
        if (resolved == 0) continue;

        std::string command = "bp " + address;
        if (bp.contains("type") && bp["type"].is_string()) {
            const std::string type = bp["type"].get<std::string>();
            if (type == "hardware") command = "bphws " + address + ", x, 1";
            else if (type == "memory") command = "bpm " + address + ", a";
        }

        bridge.exec_command(command);

        if (bp.contains("name") && bp["name"].is_string()) {
            const auto name = bp["name"].get<std::string>();
            if (!name.empty()) {
                bridge.exec_command("SetBreakpointName " + address + ", \"" + name + "\"");
            }
        }

        if (bp.contains("break_condition") && bp["break_condition"].is_string()) {
            const auto cond = bp["break_condition"].get<std::string>();
            if (!cond.empty()) {
                bridge.exec_command("SetBreakpointCondition " + address + ", \"" + cond + "\"");
            }
        }

        if (bp.contains("log_text") && bp["log_text"].is_string()) {
            const auto log = bp["log_text"].get<std::string>();
            if (!log.empty()) {
                bridge.exec_command("SetBreakpointLog " + address + ", \"" + log + "\"");
            }
        }

        if (bp.contains("silent") && bp["silent"].is_boolean()) {
            bridge.exec_command("SetBreakpointSilent " + address + ", " + (bp["silent"].get<bool>() ? "1" : "0"));
        }

        if (bp.contains("fast_resume") && bp["fast_resume"].is_boolean()) {
            bridge.exec_command("SetBreakpointFastResume " + address + ", " + (bp["fast_resume"].get<bool>() ? "1" : "0"));
        }

        if (bp.contains("command_text") && bp["command_text"].is_string()) {
            const auto cmd = bp["command_text"].get<std::string>();
            if (!cmd.empty()) {
                bridge.exec_command("SetBreakpointCommand " + address + ", \"" + cmd + "\"");
            }
        }

        if (bp.contains("command_condition") && bp["command_condition"].is_string()) {
            const auto cmd_cond = bp["command_condition"].get<std::string>();
            if (!cmd_cond.empty()) {
                bridge.exec_command("SetBreakpointCommandCondition " + address + ", \"" + cmd_cond + "\"");
            }
        }
    }

    return true;
}

static bool restore_annotations_from_session(c_bridge_executor& bridge, const nlohmann::json& session) {
    if (session.contains("labels") && session["labels"].is_array()) {
        for (const auto& label : session["labels"]) {
            if (!label.is_object()) continue;
            if (!label.contains("address") || !label["address"].is_string()) continue;
            if (!label.contains("text") || !label["text"].is_string()) continue;
            const auto address = bridge.eval_expression(label["address"].get<std::string>());
            if (address != 0) {
                bridge.set_label_at(address, label["text"].get<std::string>());
            }
        }
    }

    if (session.contains("comments") && session["comments"].is_array()) {
        for (const auto& comment : session["comments"]) {
            if (!comment.is_object()) continue;
            if (!comment.contains("address") || !comment["address"].is_string()) continue;
            if (!comment.contains("text") || !comment["text"].is_string()) continue;
            const auto address = bridge.eval_expression(comment["address"].get<std::string>());
            if (address != 0) {
                bridge.set_comment_at(address, comment["text"].get<std::string>());
            }
        }
    }

    if (session.contains("bookmarks") && session["bookmarks"].is_array()) {
        for (const auto& bookmark : session["bookmarks"]) {
            if (!bookmark.is_object()) continue;
            if (!bookmark.contains("address") || !bookmark["address"].is_string()) continue;
            const auto address = bridge.eval_expression(bookmark["address"].get<std::string>());
            if (address != 0) {
                bridge.set_bookmark_at(address, bookmark.value("enabled", true));
            }
        }
    }

    return true;
}

void register_session_routes(c_http_router& router) {
    router.post("/api/session/save", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("name")) {
            return s_http_response::bad_request("Missing 'name' field");
        }

        std::string name = body["name"].get<std::string>();
        if (name.empty()) {
            return s_http_response::bad_request("Session name cannot be empty");
        }

        auto safe_name = c_path_sanitizer::get_safe_filename(name);
        if (safe_name.empty()) {
            return s_http_response::bad_request("Invalid session name");
        }

        std::string dump_dir = c_path_sanitizer::get_dump_directory();
        std::string session_path = dump_dir + "\\session_" + safe_name + ".json";

        auto bp_res = bridge.get_breakpoint_list(BPXTYPE::bp_normal);
        auto reg_res = bridge.get_register_dump();
        auto map_res = bridge.get_memory_map();

        nlohmann::json reg_json = nlohmann::json::object();
        if (reg_res.has_value()) {
            reg_json["cip"] = format_utils::format_address(reg_res.value().regcontext.cip);
            reg_json["cax"] = format_utils::format_address(reg_res.value().regcontext.cax);
            reg_json["csp"] = format_utils::format_address(reg_res.value().regcontext.csp);
        }

        nlohmann::json session = {
            {"name", safe_name},
            {"timestamp", std::chrono::system_clock::now().time_since_epoch().count()},
            {"breakpoints", bp_res.has_value() ? bp_res.value() : nlohmann::json::array()},
            {"registers", reg_json},
            {"modules", map_res.has_value() ? map_res.value() : nlohmann::json::array()}
        };

        FILE* f = nullptr;
        if (fopen_s(&f, session_path.c_str(), "wb") != 0 || f == nullptr) {
            return s_http_response::internal_error("Failed to create session file");
        }

        std::string json_str = session.dump(2);
        fwrite(json_str.data(), 1, json_str.size(), f);
        fclose(f);

        return s_http_response::ok({
            {"name", safe_name},
            {"path", session_path},
            {"size", json_str.size()},
            {"message", "Session saved"}
        });
    });

    router.post("/api/session/restore", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || (!body.contains("name") && !body.contains("file"))) {
            return s_http_response::bad_request("Missing 'name' and/or 'file' field");
        }

        const std::string name = body.value("name", "");
        const std::string file = body.value("file", "");
        const std::string session_path = resolve_session_path(name, file);
        if (session_path.empty()) {
            return s_http_response::bad_request("Invalid session path");
        }

        std::ifstream input(session_path, std::ios::binary);
        if (!input.is_open()) {
            return s_http_response::not_found("Session not found: " + session_path);
        }

        std::stringstream buffer;
        buffer << input.rdbuf();

        try {
            const auto session = nlohmann::json::parse(buffer.str());
            restore_breakpoints_from_session(bridge, session);
            restore_annotations_from_session(bridge, session);

            return s_http_response::ok({
                {"restored", true},
                {"path", session_path},
                {"name", session.value("name", name.empty() ? "restored" : name)},
                {"message", "Session restored"}
            });
        } catch (const std::exception&) {
            return s_http_response::bad_request("Invalid session file");
        }
    });

    router.get("/api/session/list", [](const s_http_request&) -> s_http_response {
        std::string dump_dir = c_path_sanitizer::get_dump_directory();
        std::string search_pattern = dump_dir + "\\session_*.json";

        WIN32_FIND_DATAA fd{};
        HANDLE hFind = FindFirstFileA(search_pattern.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            return s_http_response::ok({
                {"sessions", nlohmann::json::array()},
                {"count", 0}
            });
        }

        auto sessions = nlohmann::json::array();
        do {
            std::string filename = fd.cFileName;
            auto dot_pos = filename.find_last_of('.');
            if (dot_pos != std::string::npos) {
                std::string name = filename.substr(7, dot_pos - 7);
                sessions.push_back({
                    {"name", name},
                    {"filename", filename},
                    {"size", static_cast<uint64_t>(fd.nFileSizeLow) | (static_cast<uint64_t>(fd.nFileSizeHigh) << 32)}
                });
            }
        } while (FindNextFileA(hFind, &fd));

        FindClose(hFind);

        return s_http_response::ok({
            {"sessions", sessions},
            {"count", sessions.size()}
        });
    });

    router.post("/api/session/delete", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("name")) {
            return s_http_response::bad_request("Missing 'name' field");
        }

        std::string name = body["name"].get<std::string>();
        auto safe_name = c_path_sanitizer::get_safe_filename(name);
        if (safe_name.empty()) {
            return s_http_response::bad_request("Invalid session name");
        }

        std::string dump_dir = c_path_sanitizer::get_dump_directory();
        std::string session_path = dump_dir + "\\session_" + safe_name + ".json";

        if (DeleteFileA(session_path.c_str())) {
            return s_http_response::ok({
                {"deleted", true},
                {"name", safe_name},
                {"path", session_path}
            });
        }

        return s_http_response::not_found("Session not found: " + safe_name);
    });
}

} // namespace handlers
