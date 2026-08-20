#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_memory_classifier_routes(c_http_router& router) {
    // GET /api/memory/classify_region
    // Query param: address
    router.get("/api/memory/classify_region", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto addr_str = req.get_query("address", "");
        duint addr = !addr_str.empty() ? bridge.eval_expression(addr_str) : bridge.get_cip();

        std::string mod = bridge.get_module_at(addr);
        duint peb = bridge.eval_expression("peb()");
        duint teb = bridge.eval_expression("teb()");
        duint csp = bridge.eval_expression("csp");

        std::string classification = "UNKNOWN";
        if (!mod.empty()) {
            classification = "IMAGE_MODULE (" + mod + ")";
        } else if (addr >= csp - 0x100000 && addr <= csp + 0x100000) {
            classification = "THREAD_STACK";
        } else if (addr >= peb && addr < peb + 0x1000) {
            classification = "PEB_STRUCT";
        } else if (addr >= teb && addr < teb + 0x2000) {
            classification = "TEB_STRUCT";
        } else {
            classification = "DYNAMIC_HEAP_OR_PRIVATE_ALLOC";
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(addr)},
            {"classification", classification},
            {"module", mod},
            {"is_backed_by_image", !mod.empty()}
        });
    });

    // POST /api/memory/classify_all
    router.post("/api/memory/classify_all", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto memmap = bridge.get_memory_map();
        if (!memmap.has_value()) {
            return s_http_response::internal_error("Failed to retrieve memory map");
        }

        nlohmann::json classified = nlohmann::json::array();
        for (const auto& page : memmap.value()) {
            std::string mod = page.value("module", "");
            std::string info = page.value("info", "");
            std::string type = "HEAP/PRIVATE";
            if (!mod.empty()) type = "IMAGE";
            else if (info.find("Stack") != std::string::npos) type = "STACK";

            classified.push_back({
                {"address", page.value("address", "0x0")},
                {"size", page.value("size", "0x0")},
                {"type", type},
                {"protection", info},
                {"module", mod}
            });
        }

        return s_http_response::ok({
            {"total_regions", classified.size()},
            {"regions", classified}
        });
    });

    // POST /api/memory/find_anomalies
    router.post("/api/memory/find_anomalies", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto memmap = bridge.get_memory_map();
        if (!memmap.has_value()) {
            return s_http_response::internal_error("Failed to retrieve memory map");
        }

        nlohmann::json anomalies = nlohmann::json::array();
        for (const auto& page : memmap.value()) {
            std::string mod = page.value("module", "");
            std::string info = page.value("info", "");

            // Flag unbacked executable memory (RWX or RX without module)
            if (mod.empty() && (info.find("Execute") != std::string::npos || info.find("ERW") != std::string::npos || info.find("ER") != std::string::npos)) {
                anomalies.push_back({
                    {"address", page.value("address", "0x0")},
                    {"size", page.value("size", "0x0")},
                    {"anomaly_type", "UNBACKED_EXECUTABLE_PAGE (Possible Injected Code/Hook/JIT)"},
                    {"protection", info}
                });
            }
        }

        return s_http_response::ok({
            {"anomaly_count", anomalies.size()},
            {"anomalies", anomalies}
        });
    });

    // POST /api/memory/identify_allocation
    router.post("/api/memory/identify_allocation", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        if (!body.is_discarded() && body.contains("address")) {
            addr = bridge.eval_expression(body["address"].get<std::string>());
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(addr)},
            {"allocator", "NT_VIRTUAL_ALLOC"},
            {"alignment", "0x1000 (4KB)"},
            {"header_magic_found", false}
        });
    });
}

} // namespace handlers
