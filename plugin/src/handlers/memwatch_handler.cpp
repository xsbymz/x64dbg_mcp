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

namespace handlers {

// ---------------------------------------------------------------------------
// Memory snapshot store
// ---------------------------------------------------------------------------

struct s_mem_snapshot {
    std::string  name;
    duint        address;
    size_t       size;
    std::vector<uint8_t> data;
    int64_t      timestamp;  // system_clock ticks
};

static std::mutex                                        g_snap_mutex;
static std::unordered_map<std::string, s_mem_snapshot>  g_snapshots;

static constexpr size_t MAX_SNAPSHOT_SIZE  = 64 * 1024 * 1024; // 64 MB total per snapshot
static constexpr size_t MAX_SNAPSHOT_COUNT = 32;

// ---------------------------------------------------------------------------

void register_memwatch_routes(c_http_router& router) {

    // POST /api/memwatch/snapshot
    // Body: { "name": "before", "address": "0x...", "size": N }
    router.post("/api/memwatch/snapshot", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("name") ||
            !body.contains("address") || !body.contains("size")) {
            return s_http_response::bad_request("Missing 'name', 'address', and/or 'size' fields");
        }

        auto name    = body["name"].get<std::string>();
        auto addr    = bridge.eval_expression(body["address"].get<std::string>());
        auto sz_raw  = body["size"].get<size_t>();

        if (name.empty() || name.size() > 64) {
            return s_http_response::bad_request("'name' must be 1-64 characters");
        }
        if (sz_raw == 0 || sz_raw > MAX_SNAPSHOT_SIZE) {
            return s_http_response::bad_request(
                "Invalid size (1 to " + std::to_string(MAX_SNAPSHOT_SIZE) + " bytes)");
        }

        std::lock_guard<std::mutex> lock(g_snap_mutex);
        if (g_snapshots.size() >= MAX_SNAPSHOT_COUNT && g_snapshots.find(name) == g_snapshots.end()) {
            return s_http_response::bad_request("Snapshot limit reached (max " +
                                                std::to_string(MAX_SNAPSHOT_COUNT) + ")");
        }

        auto result = bridge.read_memory(addr, sz_raw);
        if (!result.has_value()) {
            return s_http_response::internal_error("Failed to read memory: " + result.error());
        }

        s_mem_snapshot snap;
        snap.name      = name;
        snap.address   = addr;
        snap.size      = sz_raw;
        snap.data      = std::move(result.value());
        snap.timestamp = std::chrono::system_clock::now().time_since_epoch().count();

        g_snapshots[name] = std::move(snap);

        return s_http_response::ok({
            {"name",    name},
            {"address", format_utils::format_address(addr)},
            {"size",    sz_raw},
            {"saved",   true}
        });
    });

    // GET /api/memwatch/list
    router.get("/api/memwatch/list", [](const s_http_request&) -> s_http_response {
        std::lock_guard<std::mutex> lock(g_snap_mutex);
        auto arr = nlohmann::json::array();
        for (const auto& [name, snap] : g_snapshots) {
            arr.push_back({
                {"name",      snap.name},
                {"address",   format_utils::format_address(snap.address)},
                {"size",      snap.size},
                {"timestamp", snap.timestamp}
            });
        }
        return s_http_response::ok({{"snapshots", arr}, {"count", arr.size()}});
    });

    // POST /api/memwatch/diff
    // Body: { "a": "before", "b": "after", "limit": 1000 }
    // Returns byte-level diff between two snapshots (must have same address and size).
    router.post("/api/memwatch/diff", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("a") || !body.contains("b")) {
            return s_http_response::bad_request("Missing 'a' and/or 'b' snapshot names");
        }

        auto name_a = body["a"].get<std::string>();
        auto name_b = body["b"].get<std::string>();
        int  limit  = body.value("limit", 1000);
        if (limit < 1) limit = 1;
        if (limit > 100000) limit = 100000;

        std::lock_guard<std::mutex> lock(g_snap_mutex);

        auto it_a = g_snapshots.find(name_a);
        auto it_b = g_snapshots.find(name_b);
        if (it_a == g_snapshots.end()) return s_http_response::not_found("Snapshot not found: " + name_a);
        if (it_b == g_snapshots.end()) return s_http_response::not_found("Snapshot not found: " + name_b);

        const auto& sa = it_a->second;
        const auto& sb = it_b->second;

        if (sa.address != sb.address) {
            return s_http_response::bad_request(
                "Snapshots have different base addresses: " +
                format_utils::format_address(sa.address) + " vs " +
                format_utils::format_address(sb.address));
        }

        size_t cmp_size = std::min(sa.size, sb.size);
        auto changes    = nlohmann::json::array();
        size_t found    = 0;

        // Merge consecutive changed bytes into regions for compactness
        size_t region_start = std::string::npos;
        std::vector<uint8_t> region_before, region_after;

        auto flush_region = [&]() {
            if (region_start == std::string::npos) return;
            if (static_cast<int>(found) < limit) {
                changes.push_back({
                    {"offset",  region_start},
                    {"address", format_utils::format_address(sa.address + region_start)},
                    {"before",  format_utils::format_bytes_hex(region_before.data(), region_before.size())},
                    {"after",   format_utils::format_bytes_hex(region_after.data(), region_after.size())},
                    {"size",    region_before.size()}
                });
                found++;
            }
            region_start = std::string::npos;
            region_before.clear();
            region_after.clear();
        };

        for (size_t i = 0; i < cmp_size; ++i) {
            if (sa.data[i] != sb.data[i]) {
                if (region_start == std::string::npos) {
                    region_start = i;
                }
                region_before.push_back(sa.data[i]);
                region_after.push_back(sb.data[i]);
            } else {
                flush_region();
            }
        }
        flush_region();

        return s_http_response::ok({
            {"snapshot_a",     name_a},
            {"snapshot_b",     name_b},
            {"base_address",   format_utils::format_address(sa.address)},
            {"compared_bytes", cmp_size},
            {"changed_regions",changes},
            {"region_count",   found},
            {"truncated",      (static_cast<int>(found) >= limit)}
        });
    });

    // POST /api/memwatch/watch_region
    // One-shot: snapshot BEFORE, run until pause, snapshot AFTER, return diff.
    // Body: { "name": "my_region", "address": "0x...", "size": N,
    //         "trigger": "run|step_into|step_over", "wait_ms": 10000 }
    router.post("/api/memwatch/watch_region", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address") || !body.contains("size")) {
            return s_http_response::bad_request("Missing 'address' and/or 'size' fields");
        }

        auto name    = body.value("name", "watch_region");
        auto addr    = bridge.eval_expression(body["address"].get<std::string>());
        auto sz      = body["size"].get<size_t>();
        auto trigger = body.value("trigger", "step_over");
        auto wait_ms = body.value("wait_ms", 10000);

        if (sz == 0 || sz > MAX_SNAPSHOT_SIZE) {
            return s_http_response::bad_request("Invalid size");
        }
        if (wait_ms < 0) wait_ms = 0;
        if (wait_ms > 60000) wait_ms = 60000;

        // 1. Snapshot before
        auto mem_before = bridge.read_memory(addr, sz);
        if (!mem_before.has_value()) {
            return s_http_response::internal_error("Failed to read memory (before): " + mem_before.error());
        }

        // 2. Execute trigger
        bool exec_ok = false;
        if (trigger == "step_into")      exec_ok = bridge.exec_command_and_wait("StepInto",  wait_ms);
        else if (trigger == "step_over") exec_ok = bridge.exec_command_and_wait("StepOver",  wait_ms);
        else {  // "run"
            bridge.exec_command("run");
            exec_ok = bridge.wait_for_pause(wait_ms);
        }

        if (!exec_ok) {
            return s_http_response::internal_error("Execution trigger timed out");
        }

        // 3. Snapshot after
        auto mem_after = bridge.read_memory(addr, sz);
        if (!mem_after.has_value()) {
            return s_http_response::internal_error("Failed to read memory (after): " + mem_after.error());
        }

        // 4. Inline diff
        const auto& da = mem_before.value();
        const auto& db = mem_after.value();
        auto changes = nlohmann::json::array();
        size_t cmp   = std::min(da.size(), db.size());

        size_t region_start = std::string::npos;
        std::vector<uint8_t> rb, ra;

        auto flush = [&]() {
            if (region_start == std::string::npos) return;
            changes.push_back({
                {"offset",  region_start},
                {"address", format_utils::format_address(addr + region_start)},
                {"before",  format_utils::format_bytes_hex(rb.data(), rb.size())},
                {"after",   format_utils::format_bytes_hex(ra.data(), ra.size())},
                {"size",    rb.size()}
            });
            region_start = std::string::npos;
            rb.clear(); ra.clear();
        };

        for (size_t i = 0; i < cmp; ++i) {
            if (da[i] != db[i]) {
                if (region_start == std::string::npos) region_start = i;
                rb.push_back(da[i]);
                ra.push_back(db[i]);
            } else {
                flush();
            }
        }
        flush();

        auto cip_after = format_utils::format_address(bridge.eval_expression("cip"));

        return s_http_response::ok({
            {"name",           name},
            {"address",        format_utils::format_address(addr)},
            {"size",           sz},
            {"trigger",        trigger},
            {"cip_after",      cip_after},
            {"changed_regions",changes},
            {"region_count",   changes.size()},
            {"any_changes",    !changes.empty()}
        });
    });

    // POST /api/memwatch/delete
    // Body: { "name": "my_snapshot" }
    router.post("/api/memwatch/delete", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("name")) {
            return s_http_response::bad_request("Missing 'name' field");
        }
        auto name = body["name"].get<std::string>();
        std::lock_guard<std::mutex> lock(g_snap_mutex);
        auto it = g_snapshots.find(name);
        if (it == g_snapshots.end()) return s_http_response::not_found("Snapshot not found: " + name);
        g_snapshots.erase(it);
        return s_http_response::ok({{"deleted", true}, {"name", name}});
    });
}

} // namespace handlers
