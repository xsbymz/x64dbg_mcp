#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <string>
#include <vector>
#include <unordered_set>
#include <unordered_map>
#include <mutex>
#include <atomic>
#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

// ---------------------------------------------------------------------------
// In-process coverage store
// ---------------------------------------------------------------------------

static std::mutex                   g_cov_mutex;
static std::unordered_set<duint>    g_hit_addrs;
static std::atomic<bool>            g_cov_active{false};
static std::chrono::steady_clock::time_point g_cov_start;

// Snapshot (named, for diffing)
static std::unordered_map<std::string, std::unordered_set<duint>> g_snapshots;

// ---------------------------------------------------------------------------
// drcov export helpers
//
// The drcov binary format (used by Lighthouse / IDA / Binja) consists of:
//   "DRCOV VERSION: 2\n"
//   "DRCOV FLAVOR: drcov\n"
//   "Module Table: version 2, count N\n"
//   "Columns: id, base, end, entry, checksum, timestamp, path\n"
//   <module rows>\n
//   "BB Table: N bbs\n"
//   <packed array of { uint32 start_offset, uint16 size, uint16 module_id }>
// ---------------------------------------------------------------------------

struct drcov_bb {
    uint32_t start;   // offset from module base
    uint16_t size;
    uint16_t mod_id;
};

static std::string build_drcov(const std::unordered_set<duint>& hits,
                                c_bridge_executor& bridge) {
    // Build module list from memory map
    MEMMAP memmap{};
    if (!DbgMemMap(&memmap)) return "";

    struct mod_info { duint base; duint size; std::string path; int id; };
    std::vector<mod_info> modules;

    for (int i = 0; i < memmap.count; ++i) {
        const auto& page = memmap.page[i];
        if (page.mbi.State != MEM_COMMIT) continue;
        std::string info = page.info;
        if (info.size() > 4) {
            std::string low = info;
            std::transform(low.begin(), low.end(), low.begin(), ::tolower);
            if (low.ends_with(".exe") || low.ends_with(".dll") || low.ends_with(".sys")) {
                auto base = reinterpret_cast<duint>(page.mbi.BaseAddress);
                bool dup  = false;
                for (const auto& m : modules) { if (m.base == base) { dup = true; break; } }
                if (!dup) {
                    modules.push_back({base, static_cast<duint>(page.mbi.RegionSize),
                                       info, static_cast<int>(modules.size())});
                }
            }
        }
    }
    if (memmap.page) BridgeFree(memmap.page);

    // Helper: find module for an address
    auto find_mod = [&](duint addr) -> const mod_info* {
        for (const auto& m : modules) {
            if (addr >= m.base && addr < m.base + m.size) return &m;
        }
        return nullptr;
    };

    // Build BB table (1 BB per hit address — worst case but correct for coverage)
    std::vector<drcov_bb> bbs;
    bbs.reserve(hits.size());
    for (auto addr : hits) {
        const auto* m = find_mod(addr);
        if (!m) continue;
        drcov_bb bb{};
        bb.start  = static_cast<uint32_t>(addr - m->base);
        bb.mod_id = static_cast<uint16_t>(m->id);

        // Get instruction size to fill the BB size field
        BASIC_INSTRUCTION_INFO info{};
        DbgDisasmFastAt(addr, &info);
        bb.size = static_cast<uint16_t>(info.size > 0 ? info.size : 1);
        bbs.push_back(bb);
    }

    // Build the text header into a std::string
    std::string header;
    header += "DRCOV VERSION: 2\n";
    header += "DRCOV FLAVOR: drcov\n";
    header += "Module Table: version 2, count " + std::to_string(modules.size()) + "\n";
    header += "Columns: id, base, end, entry, checksum, timestamp, path\n";
    for (const auto& m : modules) {
        char row[1024];
        std::snprintf(row, sizeof(row), "%d, 0x%016llX, 0x%016llX, 0x%016llX, 0x00000000, 0x00000000, %s\n",
                      m.id,
                      static_cast<unsigned long long>(m.base),
                      static_cast<unsigned long long>(m.base + m.size),
                      static_cast<unsigned long long>(m.base),
                      m.path.c_str());
        header += row;
    }
    header += "BB Table: " + std::to_string(bbs.size()) + " bbs\n";

    // Combine header + raw binary BB data into one string
    std::string result = header;
    result.append(reinterpret_cast<const char*>(bbs.data()), bbs.size() * sizeof(drcov_bb));
    return result;
}

// ---------------------------------------------------------------------------

void register_coverage_routes(c_http_router& router) {

    // POST /api/coverage/start
    router.post("/api/coverage/start", [](const s_http_request&) -> s_http_response {
        bool expected = false;
        if (!g_cov_active.compare_exchange_strong(expected, true)) {
            return s_http_response::conflict("Coverage recording already active");
        }
        std::lock_guard<std::mutex> lock(g_cov_mutex);
        g_hit_addrs.clear();
        g_cov_start = std::chrono::steady_clock::now();
        return s_http_response::ok({
            {"recording", true},
            {"message",   "Coverage recording started. Step/trace the target, then call /api/coverage/stop."}
        });
    });

    // POST /api/coverage/stop
    router.post("/api/coverage/stop", [](const s_http_request&) -> s_http_response {
        bool expected = true;
        if (!g_cov_active.compare_exchange_strong(expected, false)) {
            return s_http_response::conflict("Coverage recording is not active");
        }
        std::lock_guard<std::mutex> lock(g_cov_mutex);
        auto elapsed = std::chrono::duration_cast<std::chrono::milliseconds>(
            std::chrono::steady_clock::now() - g_cov_start).count();
        return s_http_response::ok({
            {"recording",   false},
            {"hit_count",   g_hit_addrs.size()},
            {"elapsed_ms",  elapsed}
        });
    });

    // POST /api/coverage/mark_hit
    // Called by the client after each step to register the current CIP.
    // For full automation: call after step_into/step_over to build coverage.
    router.post("/api/coverage/mark_hit", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);

        // Accept explicit address list or current CIP
        std::lock_guard<std::mutex> lock(g_cov_mutex);
        size_t added = 0;

        if (!body.is_discarded() && body.contains("addresses") && body["addresses"].is_array()) {
            for (const auto& a : body["addresses"]) {
                if (a.is_string()) {
                    g_hit_addrs.insert(bridge.eval_expression(a.get<std::string>()));
                    added++;
                }
            }
        } else {
            // Default: mark current CIP
            auto cip = bridge.eval_expression("cip");
            g_hit_addrs.insert(cip);
            added = 1;
        }

        return s_http_response::ok({
            {"added",     added},
            {"total_hits", g_hit_addrs.size()}
        });
    });

    // GET /api/coverage/hits
    // Returns up to 50000 hit addresses as a hex array
    router.get("/api/coverage/hits", [](const s_http_request& req) -> s_http_response {
        auto limit_str = req.get_query("limit", "50000");
        int limit = std::atoi(limit_str.c_str());
        if (limit < 1)     limit = 1;
        if (limit > 500000) limit = 500000;

        std::lock_guard<std::mutex> lock(g_cov_mutex);
        auto arr = nlohmann::json::array();
        int count = 0;
        for (auto addr : g_hit_addrs) {
            if (count++ >= limit) break;
            arr.push_back(format_utils::format_address(addr));
        }

        return s_http_response::ok({
            {"hits",      arr},
            {"count",     arr.size()},
            {"total",     g_hit_addrs.size()},
            {"recording", g_cov_active.load()}
        });
    });

    // POST /api/coverage/snapshot
    // Save current hit set as a named snapshot for later diffing.
    router.post("/api/coverage/snapshot", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("name")) {
            return s_http_response::bad_request("Missing 'name' field");
        }
        auto name = body["name"].get<std::string>();
        std::lock_guard<std::mutex> lock(g_cov_mutex);
        g_snapshots[name] = g_hit_addrs;
        return s_http_response::ok({
            {"saved",     true},
            {"name",      name},
            {"hit_count", g_hit_addrs.size()}
        });
    });

    // POST /api/coverage/diff
    // Body: { "a": "snap1", "b": "snap2" }   — diff two named snapshots
    // Returns: only_in_a, only_in_b, in_both
    router.post("/api/coverage/diff", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("a") || !body.contains("b")) {
            return s_http_response::bad_request("Missing 'a' and/or 'b' snapshot names");
        }
        auto name_a = body["a"].get<std::string>();
        auto name_b = body["b"].get<std::string>();

        std::lock_guard<std::mutex> lock(g_cov_mutex);
        auto it_a = g_snapshots.find(name_a);
        auto it_b = g_snapshots.find(name_b);

        if (it_a == g_snapshots.end()) return s_http_response::not_found("Snapshot not found: " + name_a);
        if (it_b == g_snapshots.end()) return s_http_response::not_found("Snapshot not found: " + name_b);

        const auto& sa = it_a->second;
        const auto& sb = it_b->second;

        auto only_a = nlohmann::json::array();
        auto only_b = nlohmann::json::array();
        auto shared = nlohmann::json::array();

        for (auto addr : sa) {
            if (sb.count(addr)) shared.push_back(format_utils::format_address(addr));
            else                only_a.push_back(format_utils::format_address(addr));
        }
        for (auto addr : sb) {
            if (!sa.count(addr)) only_b.push_back(format_utils::format_address(addr));
        }

        return s_http_response::ok({
            {"only_in_a",    only_a},
            {"only_in_b",    only_b},
            {"in_both",      shared},
            {"only_a_count", only_a.size()},
            {"only_b_count", only_b.size()},
            {"shared_count", shared.size()}
        });
    });

    // POST /api/coverage/export
    // Body: { "format": "drcov|json|lcov", "file": "optional_output.cov" }
    router.post("/api/coverage/export", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body    = nlohmann::json::parse(req.body, nullptr, false);
        auto fmt     = body.is_discarded() ? "json" : body.value("format", "json");
        auto outfile = body.is_discarded() ? "" : body.value("file", "");

        std::lock_guard<std::mutex> lock(g_cov_mutex);

        if (fmt == "drcov") {
            auto data = build_drcov(g_hit_addrs, bridge);
            if (!outfile.empty()) {
                std::ofstream f(outfile, std::ios::binary);
                if (f.is_open()) f.write(data.data(), static_cast<std::streamsize>(data.size()));
            }
            return s_http_response::ok({
                {"format",    "drcov"},
                {"bytes",     data.size()},
                {"hit_count", g_hit_addrs.size()},
                {"file",      outfile.empty() ? "(not saved)" : outfile},
                {"note",      "Load .cov file into Lighthouse (IDA/Binary Ninja) for visualization"}
            });
        }

        // JSON export — simple array of hex addresses
        auto arr = nlohmann::json::array();
        for (auto addr : g_hit_addrs) arr.push_back(format_utils::format_address(addr));

        if (!outfile.empty()) {
            std::ofstream f(outfile);
            if (f.is_open()) f << arr.dump(2);
        }

        return s_http_response::ok({
            {"format",    "json"},
            {"hits",      arr},
            {"hit_count", arr.size()},
            {"file",      outfile.empty() ? "(not saved)" : outfile}
        });
    });

    // POST /api/coverage/reset
    router.post("/api/coverage/reset", [](const s_http_request&) -> s_http_response {
        g_cov_active.store(false);
        std::lock_guard<std::mutex> lock(g_cov_mutex);
        auto prev = g_hit_addrs.size();
        g_hit_addrs.clear();
        g_snapshots.clear();
        return s_http_response::ok({{"reset", true}, {"cleared_hits", prev}});
    });
}

} // namespace handlers
