#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <cstdint>
#include <cstring>
#include "_dbgfunctions.h"

namespace handlers {

static std::expected<std::vector<uint8_t>, std::string> read_memory_n(auto& bridge, duint addr, size_t size) {
    auto mem = bridge.read_memory(addr, size);
    if (!mem.has_value()) {
        return std::unexpected(mem.error());
    }
    return mem.value();
}

static std::vector<nlohmann::json> check_patch(auto& bridge, const std::string& symbol, const std::vector<uint8_t>& clean_prologue) {
    std::vector<nlohmann::json> patches;
    duint addr = bridge.eval_expression(symbol);
    if (addr == 0) return patches;

    auto mem = bridge.read_memory(addr, 16);
    if (!mem.has_value() || mem->size() < clean_prologue.size()) return patches;

    const auto& bytes = mem.value();
    for (size_t i = 0; i < clean_prologue.size(); ++i) {
        if (bytes[i] != clean_prologue[i]) {
            patches.push_back({
                {"address", format_utils::format_address(addr + i)},
                {"old_byte", format_utils::format_bytes_compact(&clean_prologue[i], 1)},
                {"new_byte", format_utils::format_bytes_compact(&bytes[i], 1)}
            });
        }
    }
    return patches;
}

static std::vector<nlohmann::json> check_short_patch(auto& bridge, const std::string& symbol, uint8_t expected) {
    std::vector<nlohmann::json> patches;
    duint addr = bridge.eval_expression(symbol);
    if (addr == 0) return patches;

    auto mem = bridge.read_memory(addr, 1);
    if (!mem.has_value() || mem->empty()) return patches;

    uint8_t b = mem.value()[0];
    if (b != expected) {
        patches.push_back({
            {"address", format_utils::format_address(addr)},
            {"old_byte", format_utils::format_bytes_compact(&expected, 1)},
            {"new_byte", format_utils::format_bytes_compact(&b, 1)}
        });
    }
    return patches;
}

void register_etw_amsi_routes(c_http_router& router) {
    router.get("/api/etw_amsi/detect", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        nlohmann::json patches = nlohmann::json::array();
        bool amsi_patched = false;
        bool etw_disabled = false;

        auto amsi_patches = check_patch(bridge, "amsi:AmsiScanBuffer", {0x4C, 0x8B, 0xD1});
        for (const auto& p : amsi_patches) patches.push_back(p);
        if (!amsi_patches.empty()) amsi_patched = true;

        auto nt_trace_patches = check_patch(bridge, "ntdll:NtTraceEvent", {0x4C, 0x8B, 0xD1});
        for (const auto& p : nt_trace_patches) patches.push_back(p);
        if (!nt_trace_patches.empty()) etw_disabled = true;

        std::vector<std::string> etw_funcs = {
            "ntdll:EtwpEventWriteFull",
            "ntdll:EtwpWriteTransfer",
            "ntdll:EtwpSendNotification"
        };
        for (const auto& func : etw_funcs) {
            auto p = check_short_patch(bridge, func, 0xCC);
            for (const auto& patch : p) patches.push_back(patch);
            if (!p.empty()) etw_disabled = true;
        }

        return s_http_response::ok({
            {"amsi_patched", amsi_patched},
            {"etw_disabled", etw_disabled},
            {"patches", patches}
        });
    });
}

} // namespace handlers
