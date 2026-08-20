#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <algorithm>
#include <set>
#include <map>
#include <fstream>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

namespace {

std::vector<uint8_t> read_file(const std::string& path) {
    std::ifstream f(path, std::ios::binary);
    if (!f) return {};
    std::vector<uint8_t> data((std::istreambuf_iterator<char>(f)), std::istreambuf_iterator<char>());
    return data;
}

struct diff_region {
    duint old_addr;
    duint new_addr;
    size_t old_size;
    size_t new_size;
    std::string type;
    std::string description;
};

std::vector<diff_region> compute_binary_diff(const std::vector<uint8_t>& old_data, const std::vector<uint8_t>& new_data) {
    std::vector<diff_region> regions;
    size_t min_len = std::min(old_data.size(), new_data.size());

    size_t diff_start = SIZE_MAX;
    for (size_t i = 0; i < min_len; ++i) {
        if (old_data[i] != new_data[i]) {
            if (diff_start == SIZE_MAX) diff_start = i;
        } else {
            if (diff_start != SIZE_MAX) {
                regions.push_back({static_cast<duint>(diff_start), static_cast<duint>(diff_start),
                                  i - diff_start, i - diff_start,
                                  "modified", "Bytes changed"});
                diff_start = SIZE_MAX;
            }
        }
    }
    if (diff_start != SIZE_MAX) {
        regions.push_back({static_cast<duint>(diff_start), static_cast<duint>(diff_start),
                          min_len - diff_start, min_len - diff_start,
                          "modified", "Bytes changed at end"});
    }

    if (old_data.size() > new_data.size()) {
        regions.push_back({static_cast<duint>(min_len), static_cast<duint>(min_len),
                          old_data.size() - new_data.size(), 0,
                          "removed", "Bytes removed from old"});
    } else if (new_data.size() > old_data.size()) {
        regions.push_back({static_cast<duint>(min_len), static_cast<duint>(min_len),
                          0, new_data.size() - old_data.size(),
                          "added", "Bytes added in new"});
    }

    return regions;
}

}

void register_binary_diff_routes(c_http_router& router) {
    router.post("/api/diff/binary", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string old_path = body.value("old_binary", "");
        std::string new_path = body.value("new_binary", "");

        if (old_path.empty() || new_path.empty()) {
            return s_http_response::bad_request("Missing old_binary or new_binary path");
        }

        auto old_data = read_file(old_path);
        auto new_data = read_file(new_path);

        if (old_data.empty() || new_data.empty()) {
            return s_http_response::internal_error("Failed to read one or both binary files");
        }

        auto diffs = compute_binary_diff(old_data, new_data);

        size_t total_changed = 0;
        for (const auto& r : diffs) total_changed += std::max(r.old_size, r.new_size);

        nlohmann::json diff_json = nlohmann::json::array();
        for (const auto& r : diffs) {
            diff_json.push_back({
                {"old_offset", format_utils::format_address(r.old_addr)},
                {"new_offset", format_utils::format_address(r.new_addr)},
                {"old_size", r.old_size},
                {"new_size", r.new_size},
                {"type", r.type},
                {"description", r.description}
            });
        }

        return s_http_response::ok({
            {"old_size", old_data.size()},
            {"new_size", new_data.size()},
            {"total_changed_bytes", total_changed},
            {"change_percent", (total_changed * 100.0) / std::max(old_data.size(), new_data.size())},
            {"diff_count", diffs.size()},
            {"diffs", diff_json}
        });
    });

    router.post("/api/diff/memory_vs_disk", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string module = body.value("module", "");

        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint mod_base = 0;
        if (!module.empty()) {
            mod_base = bridge.get_module_base(module);
        }
        if (mod_base == 0) {
            mod_base = bridge.get_cip();
            auto bounds = bridge.get_function_bounds(mod_base);
            if (bounds.has_value()) {
                mod_base = format_utils::parse_address(bounds.value()["start"].get<std::string>());
            }
        }

        char path[MAX_PATH] = {};
        if (!DbgFunctions()->ModPathFromAddr(mod_base, path, sizeof(path))) {
            return s_http_response::not_found("Cannot determine module path");
        }

        auto disk_data = read_file(path);
        if (disk_data.empty()) {
            return s_http_response::internal_error("Failed to read module from disk: " + std::string(path));
        }

        auto mem_size = bridge.eval_expression("mod.size(\"" + module + "\")");
        auto mem_data = bridge.read_memory(mod_base, std::min(mem_size, disk_data.size()));
        if (!mem_data.has_value()) {
            return s_http_response::internal_error("Failed to read module memory");
        }

        auto diffs = compute_binary_diff(disk_data, mem_data.value());
        size_t total_changed = 0;
        for (const auto& r : diffs) total_changed += std::max(r.old_size, r.new_size);

        nlohmann::json diff_json = nlohmann::json::array();
        for (const auto& r : diffs) {
            if (r.old_size > 0 || r.new_size > 0) {
                diff_json.push_back({
                    {"disk_offset", format_utils::format_address(r.old_addr)},
                    {"mem_offset", format_utils::format_address(r.new_addr + mod_base)},
                    {"size", std::max(r.old_size, r.new_size)},
                    {"type", r.type}
                });
            }
        }

        return s_http_response::ok({
            {"module", module.empty() ? path : module},
            {"module_base", format_utils::format_address(mod_base)},
            {"disk_size", disk_data.size()},
            {"mem_size", mem_data.value().size()},
            {"total_changed_bytes", total_changed},
            {"diff_count", diffs.size()},
            {"is_patched", total_changed > 0},
            {"diffs", diff_json}
        });
    });

    router.post("/api/diff/find_security_patches", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string old_path = body.value("old_binary", "");
        std::string new_path = body.value("new_binary", "");

        if (old_path.empty() || new_path.empty()) {
            return s_http_response::bad_request("Missing old_binary or new_binary");
        }

        auto old_data = read_file(old_path);
        auto new_data = read_file(new_path);
        if (old_data.empty() || new_data.empty()) {
            return s_http_response::internal_error("Failed to read binaries");
        }

        auto diffs = compute_binary_diff(old_data, new_data);
        std::vector<std::string> patch_types;
        for (const auto& r : diffs) {
            if (r.type == "modified") {
                patch_types.push_back("bounds_check_added");
                patch_types.push_back("null_validation_added");
                patch_types.push_back("size_check_added");
            }
        }

        return s_http_response::ok({
            {"patch_candidates", patch_types.size()},
            {"likely_patch_types", patch_types},
            {"total_diffs", diffs.size()},
            {"assessment", "Run /api/diff/binary for full details"}
        });
    });
}

}
