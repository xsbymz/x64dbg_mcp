#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <string>
#include <vector>
#include <unordered_map>
#include <mutex>
#include <chrono>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_plugins.h"

namespace handlers {

// ---------------------------------------------------------------------------
// In-process watch store
// ---------------------------------------------------------------------------

enum class watch_type { hex, decimal, string_utf8, string_utf16, float_val };

struct s_watch_entry {
    std::string name;
    std::string expression;
    watch_type  type   = watch_type::hex;
    std::string last_value;
    uint64_t    hit_count = 0;
    bool        changed   = false;
};

static std::mutex                                      g_watch_mutex;
static std::unordered_map<std::string, s_watch_entry> g_watches;

static watch_type parse_watch_type(const std::string& s) {
    if (s == "decimal")      return watch_type::decimal;
    if (s == "string")       return watch_type::string_utf8;
    if (s == "string_utf8")  return watch_type::string_utf8;
    if (s == "string_utf16") return watch_type::string_utf16;
    if (s == "float")        return watch_type::float_val;
    return watch_type::hex;
}

static std::string type_to_string(watch_type t) {
    switch (t) {
        case watch_type::decimal:      return "decimal";
        case watch_type::string_utf8:  return "string_utf8";
        case watch_type::string_utf16: return "string_utf16";
        case watch_type::float_val:    return "float";
        default:                       return "hex";
    }
}

// Evaluate one watch entry against the live debugger state.
static std::string evaluate_watch(c_bridge_executor& bridge, const s_watch_entry& w) {
    auto raw = bridge.eval_expression(w.expression);

    switch (w.type) {
        case watch_type::decimal:
            return std::to_string(raw);

        case watch_type::string_utf8: {
            // raw is a VA — read up to 256 bytes and return as UTF-8 string
            auto mem = bridge.read_memory(static_cast<duint>(raw), 256);
            if (!mem.has_value()) return "<unreadable>";
            std::string s;
            for (auto b : mem.value()) {
                if (b == 0) break;
                if (b >= 0x20 && b < 0x7F) s += static_cast<char>(b);
                else s += '.';
            }
            return s.empty() ? "<empty>" : s;
        }

        case watch_type::string_utf16: {
            auto mem = bridge.read_memory(static_cast<duint>(raw), 512);
            if (!mem.has_value()) return "<unreadable>";
            std::string s;
            const auto& bytes = mem.value();
            for (size_t i = 0; i + 1 < bytes.size(); i += 2) {
                uint16_t ch = static_cast<uint16_t>(bytes[i]) |
                              (static_cast<uint16_t>(bytes[i + 1]) << 8);
                if (ch == 0) break;
                s += (ch < 0x80) ? static_cast<char>(ch) : '?';
            }
            return s.empty() ? "<empty>" : s;
        }

        case watch_type::float_val: {
            float fval;
            std::memcpy(&fval, &raw, sizeof(float));
            char buf[32];
            std::snprintf(buf, sizeof(buf), "%.6f", static_cast<double>(fval));
            return buf;
        }

        default:
            return format_utils::format_address(raw);
    }
}

static nlohmann::json watch_to_json(const s_watch_entry& w) {
    return nlohmann::json{
        {"name",       w.name},
        {"expression", w.expression},
        {"type",       type_to_string(w.type)},
        {"value",      w.last_value},
        {"hit_count",  w.hit_count},
        {"changed",    w.changed}
    };
}

// ---------------------------------------------------------------------------
// Route registration
// ---------------------------------------------------------------------------

void register_watch_routes(c_http_router& router) {

    // POST /api/watch/add
    // Body: { "name": "my_var", "expression": "rax", "type": "hex" }
    router.post("/api/watch/add", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("name") || !body.contains("expression")) {
            return s_http_response::bad_request("Missing 'name' and/or 'expression' fields");
        }

        auto name = body["name"].get<std::string>();
        auto expr = body["expression"].get<std::string>();
        auto type_str = body.value("type", "hex");

        if (name.empty() || name.size() > 64) {
            return s_http_response::bad_request("'name' must be 1-64 characters");
        }
        if (expr.empty() || expr.size() > 256) {
            return s_http_response::bad_request("'expression' must be 1-256 characters");
        }

        std::lock_guard<std::mutex> lock(g_watch_mutex);
        if (g_watches.size() >= 128) {
            return s_http_response::bad_request("Watch limit reached (max 128)");
        }

        s_watch_entry entry;
        entry.name       = name;
        entry.expression = expr;
        entry.type       = parse_watch_type(type_str);
        g_watches[name]  = entry;

        return s_http_response::ok({
            {"added", true},
            {"name",  name},
            {"expression", expr},
            {"type", type_str}
        });
    });

    // POST /api/watch/remove
    // Body: { "name": "my_var" }
    router.post("/api/watch/remove", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("name")) {
            return s_http_response::bad_request("Missing 'name' field");
        }

        auto name = body["name"].get<std::string>();
        std::lock_guard<std::mutex> lock(g_watch_mutex);
        auto it = g_watches.find(name);
        if (it == g_watches.end()) {
            return s_http_response::not_found("Watch not found: " + name);
        }
        g_watches.erase(it);
        return s_http_response::ok({{"removed", true}, {"name", name}});
    });

    // GET /api/watch/list
    // Returns all watches with their last evaluated values
    router.get("/api/watch/list", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        std::lock_guard<std::mutex> lock(g_watch_mutex);

        auto arr = nlohmann::json::array();
        bool can_eval = bridge.is_debugging() && !bridge.is_running();

        for (auto& [name, w] : g_watches) {
            if (can_eval) {
                auto new_val = evaluate_watch(bridge, w);
                w.changed = (new_val != w.last_value && !w.last_value.empty());
                if (new_val != w.last_value) w.hit_count++;
                w.last_value = new_val;
            }
            arr.push_back(watch_to_json(w));
        }

        return s_http_response::ok({
            {"watches",  arr},
            {"count",    arr.size()},
            {"can_eval", can_eval}
        });
    });

    // GET /api/watch/snapshot
    // Evaluate all watches right now and return a timestamped snapshot.
    router.get("/api/watch/snapshot", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused to snapshot watches");
        }

        bool log_to_dbg = (req.get_query("log", "false") == "true");

        std::lock_guard<std::mutex> lock(g_watch_mutex);

        auto snapshot = nlohmann::json::array();
        for (auto& [name, w] : g_watches) {
            auto val = evaluate_watch(bridge, w);
            w.changed    = (val != w.last_value && !w.last_value.empty());
            w.last_value = val;
            w.hit_count++;

            auto entry = watch_to_json(w);
            snapshot.push_back(entry);

            if (log_to_dbg) {
                _plugin_logprintf("[Watch] %s = %s\n", name.c_str(), val.c_str());
            }
        }

        auto now_ts = std::chrono::system_clock::now().time_since_epoch().count();

        return s_http_response::ok({
            {"timestamp", now_ts},
            {"watches",   snapshot},
            {"count",     snapshot.size()}
        });
    });

    // GET /api/watch/diff
    // Returns only watches whose value changed since last evaluation.
    router.get("/api/watch/diff", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        std::lock_guard<std::mutex> lock(g_watch_mutex);
        auto changed = nlohmann::json::array();

        for (auto& [name, w] : g_watches) {
            auto prev = w.last_value;
            auto val  = evaluate_watch(bridge, w);
            if (val != prev) {
                w.changed    = true;
                w.hit_count++;
                changed.push_back({
                    {"name",       w.name},
                    {"expression", w.expression},
                    {"before",     prev},
                    {"after",      val}
                });
                w.last_value = val;
            } else {
                w.changed = false;
            }
        }

        return s_http_response::ok({
            {"changed", changed},
            {"count",   changed.size()}
        });
    });

    // POST /api/watch/clear
    router.post("/api/watch/clear", [](const s_http_request&) -> s_http_response {
        std::lock_guard<std::mutex> lock(g_watch_mutex);
        auto cnt = g_watches.size();
        g_watches.clear();
        return s_http_response::ok({{"cleared", true}, {"removed_count", cnt}});
    });
}

} // namespace handlers
