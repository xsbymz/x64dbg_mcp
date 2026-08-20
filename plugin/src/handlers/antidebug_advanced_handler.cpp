#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <algorithm>
#include <chrono>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static std::vector<std::pair<duint, std::string>> find_instructions(
    c_bridge_executor& bridge, duint start, size_t count, const std::vector<std::string>& mnemonics)
{
    std::vector<std::pair<duint, std::string>> results;
    duint addr = start;
    for (size_t i = 0; i < count && addr != 0; ++i) {
        DISASM_INSTR instr{};
        DbgDisasmAt(addr, &instr);
        if (instr.instr_size == 0) { addr++; continue; }

        std::string mnem = instr.instruction;
        std::transform(mnem.begin(), mnem.end(), mnem.begin(), ::tolower);
        for (const auto& search : mnemonics) {
            if (mnem.starts_with(search)) {
                results.emplace_back(addr, instr.instruction);
                break;
            }
        }
        addr += instr.instr_size;
    }
    return results;
}

void register_antidebug_advanced_routes(c_http_router& router) {
    router.get("/api/antidebug/timing_checks", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module = req.get_query("module", "main.exe");
        auto base = bridge.get_module_base(module);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module);
        }

        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));
        if (size == 0) size = 0x100000;

        std::vector<std::string> timing_mnemonics = {"rdtsc", "rdtscp", "queryperformancecounter", "gettickcount", "timegettime"};
        auto results = find_instructions(bridge, base, size > 0x100000 ? 0x100000 : size, timing_mnemonics);

        auto checks = nlohmann::json::array();
        for (const auto& [addr, text] : results) {
            std::string api_name = "unknown";
            std::string mnem_lower = text;
            std::transform(mnem_lower.begin(), mnem_lower.end(), mnem_lower.begin(), ::tolower);
            if (mnem_lower.starts_with("rdtsc")) api_name = "RDTSC";
            else if (mnem_lower.starts_with("call")) api_name = "QueryPerformanceCounter / GetTickCount";

            checks.push_back({
                {"address", format_utils::format_address(addr)},
                {"instruction", text},
                {"api_name", api_name},
                {"bypass_suggestion", "Patch conditional jump after timing check or return expected delta"}
            });
        }

        return s_http_response::ok({
            {"module", module},
            {"timing_checks", checks},
            {"count", checks.size()}
        });
    });

    router.get("/api/antidebug/hardware_bp_detection", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto checks = nlohmann::json::array();

        auto regs = bridge.get_register_dump();
        if (regs.has_value()) {
            const auto& r = regs.value();
            checks.push_back({
                {"address", "current_thread_context"},
                {"technique", "DR0-DR7 inspection"},
                {"description", "Hardware debug registers on current thread"},
                {"dr0", format_utils::format_address(r.regcontext.dr0)},
                {"dr1", format_utils::format_address(r.regcontext.dr1)},
                {"dr2", format_utils::format_address(r.regcontext.dr2)},
                {"dr3", format_utils::format_address(r.regcontext.dr3)},
                {"dr7", format_utils::format_address(r.regcontext.dr7)}
            });
        }

        std::vector<std::string> ctx_mnemonics = {"getthreadcontext", "setthreadcontext", "wow64getthreadcontext", "wow64setthreadcontext"};
        auto mods = bridge.get_memory_map();
        if (mods.has_value()) {
            for (const auto& page : mods.value()) {
                if (!page.contains("info") || !page["info"].is_string()) continue;
                std::string info = page["info"];
                std::transform(info.begin(), info.end(), info.begin(), ::tolower);
                if (info.size() > 4 && (info.ends_with(".dll") || info.ends_with(".exe"))) {
                    auto base = bridge.get_module_base(page["info"]);
                    if (base == 0) continue;
                    auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + page["info"].get<std::string>() + ")"));
                    if (size == 0) continue;
                    auto hits = find_instructions(bridge, base, size > 0x10000 ? 0x10000 : size, ctx_mnemonics);
                    for (const auto& [addr, text] : hits) {
                        checks.push_back({
                            {"address", format_utils::format_address(addr)},
                            {"technique", "Thread context API call"},
                            {"description", text},
                            {"module", page["info"]}
                        });
                    }
                }
            }
        }

        return s_http_response::ok({
            {"hardware_bp_checks", checks},
            {"count", checks.size()}
        });
    });

    router.get("/api/antidebug/ntquery_hooks", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        nlohmann::json hooks = nlohmann::json::array();
        const char* ntdll_names[] = {"NtQueryInformationProcess", "NtQuerySystemInformation", "NtQueryInformationThread"};
        const DWORD classes[] = {7, 30, 9};

        for (size_t i = 0; i < 3; ++i) {
            duint addr = bridge.eval_expression("ntdll." + std::string(ntdll_names[i]));
            if (addr == 0) continue;

            auto mem = bridge.read_memory(addr, 16);
            bool is_hooked = false;
            std::string hook_type = "clean";
            if (mem.has_value() && mem->size() >= 2) {
                if (mem->data()[0] == 0xFF && mem->data()[1] == 0x25) hook_type = "inline_jmp";
                else if (mem->data()[0] == 0xCC) hook_type = "int3";
                else if (mem->data()[0] == 0xE9) hook_type = "inline_jmp";
                else {
                    uint8_t expected[] = {0x4C, 0x8B, 0xD1, 0xB8};
                    bool matches = (mem->size() >= 5 && std::equal(expected, expected + 4, mem->data()));
                    if (!matches) is_hooked = true;
                }
            }

            if (is_hooked || hook_type != "clean") {
                hooks.push_back({
                    {"process_information_class", classes[i]},
                    {"name", ntdll_names[i]},
                    {"address", format_utils::format_address(addr)},
                    {"is_hooked", is_hooked},
                    {"hook_type", hook_type}
                });
            }
        }

        return s_http_response::ok({
            {"hooked", !hooks.empty()},
            {"hooks", hooks}
        });
    });

    router.get("/api/antidebug/exception_handlers", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto checks = nlohmann::json::array();

        duint seh_head = bridge.eval_expression("fs:[0]");
        if (seh_head != 0) {
            checks.push_back({
                {"address", format_utils::format_address(seh_head)},
                {"technique", "SEH chain inspection"},
                {"description", "SEH frame pointer at fs:[0]"}
            });
        }

        std::vector<std::string> int3_mnemonics = {"int3"};
        auto mods = bridge.get_memory_map();
        if (mods.has_value()) {
            for (const auto& page : mods.value()) {
                if (!page.contains("info") || !page["info"].is_string()) continue;
                std::string info = page["info"];
                std::transform(info.begin(), info.end(), info.begin(), ::tolower);
                if (info.size() > 4 && (info.ends_with(".dll") || info.ends_with(".exe"))) {
                    auto base = bridge.get_module_base(page["info"]);
                    if (base == 0) continue;
                    auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + page["info"].get<std::string>() + ")"));
                    if (size == 0) continue;
                    auto hits = find_instructions(bridge, base, size > 0x10000 ? 0x10000 : size, int3_mnemonics);
                    if (!hits.empty()) {
                        checks.push_back({
                            {"address", format_utils::format_address(base)},
                            {"technique", "INT3 instructions"},
                            {"description", std::to_string(hits.size()) + " INT3 instructions found in " + page["info"].get<std::string>()},
                            {"count", hits.size()}
                        });
                    }
                }
            }
        }

        return s_http_response::ok({
            {"exception_checks", checks},
            {"count", checks.size()}
        });
    });
}

} // namespace handlers
