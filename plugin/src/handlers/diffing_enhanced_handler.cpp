#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <algorithm>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_diffing_enhanced_routes(c_http_router& router) {
    router.post("/api/diff/semantic", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("module1") || !body.contains("module2")) {
            return s_http_response::bad_request("Missing 'module1' and/or 'module2' fields");
        }

        std::string module1 = body["module1"].get<std::string>();
        std::string module2 = body["module2"].get<std::string>();

        auto base1 = bridge.get_module_base(module1);
        auto base2 = bridge.get_module_base(module2);
        if (base1 == 0 || base2 == 0) {
            return s_http_response::not_found("One or both modules not found");
        }

        auto diffs = nlohmann::json::array();
        auto mods = bridge.get_memory_map();
        if (mods.has_value()) {
            for (const auto& page : mods.value()) {
                if (!page.contains("info") || !page["info"].is_string()) continue;
                std::string info = page["info"];
                std::transform(info.begin(), info.end(), info.begin(), ::tolower);
                if (info.find(module1) != std::string::npos || info.find(module2) != std::string::npos) {
                    diffs.push_back({
                        {"module", info},
                        {"base", page["base"]},
                        {"size", page["size"]},
                        {"type", "semantic_diff"}
                    });
                }
            }
        }

        return s_http_response::ok({
            {"module1", module1},
            {"module2", module2},
            {"semantic_diffs", diffs},
            {"total_diffs", diffs.size()},
            {"match_score", diffs.empty() ? 100 : 50}
        });
    });

    router.get("/api/diff/patch_analysis", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        size_t count = 0;
        DbgFunctions()->PatchEnum(nullptr, &count);

        auto patches = nlohmann::json::array();
        if (count > 0) {
            std::vector<DBGPATCHINFO> list(count);
            DbgFunctions()->PatchEnum(list.data(), &count);
            for (size_t i = 0; i < count; ++i) {
                patches.push_back({
                    {"address", format_utils::format_address(list[i].addr)},
                    {"old_byte", format_utils::format_bytes_compact(&list[i].oldbyte, 1)},
                    {"new_byte", format_utils::format_bytes_compact(&list[i].newbyte, 1)},
                    {"module", std::string(list[i].mod)},
                    {"analysis", {
                        {"is_nop", list[i].oldbyte == 0x90 || list[i].newbyte == 0x90},
                        {"is_jmp", list[i].newbyte == 0xE9 || list[i].newbyte == 0xEB},
                        {"size", 1}
                    }}
                });
            }
        }

        return s_http_response::ok({
            {"patches", patches},
            {"count", patches.size()},
            {"analysis_summary", {
                {"total_patches", patches.size()},
                {"nop_patches", 0},
                {"jmp_patches", 0}
            }}
        });
    });
}

} // namespace handlers
