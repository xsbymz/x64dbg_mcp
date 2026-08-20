#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <algorithm>
#include <cctype>
#include <cstring>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_plugin_types.h"
#include "bridgegraph.h"

namespace handlers {

void register_control_flow_routes(c_http_router& router) {
    // GET /api/cfg/flattening?address= - Detect control flow flattening
    router.get("/api/cfg/flattening", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto address = bridge.eval_expression(address_str);

        BridgeCFGraphList graph_list{};
        if (!DbgAnalyzeFunction(address, &graph_list)) {
            return s_http_response::not_found("Failed to analyze function at " + address_str);
        }

        BridgeCFGraph graph(&graph_list, true);

        size_t node_count = graph.nodes.size();
        if (node_count < 3) {
            return s_http_response::ok({
                {"is_flattened", false},
                {"state_variable", ""},
                {"dispatch_address", ""},
                {"case_count", 0},
                {"confidence", 0},
                {"reason", "Function too small to exhibit flattening"}
            });
        }

        duint dispatch_addr = 0;
        int max_exits = 0;
        int state_var_nodes = 0;

        for (const auto& [start, node] : graph.nodes) {
            int exit_count = static_cast<int>(node.exits.size());
            if (exit_count > max_exits) {
                max_exits = exit_count;
                dispatch_addr = node.start;
            }

            // Look for nodes that compute a variable and jump to many targets
            if (exit_count >= 3) {
                state_var_nodes++;
            }
        }

        // Heuristics for flattened CFG:
        // - Many nodes with multiple exits (dispatch node)
        // - Most nodes have 1-2 exits but one node has many
        // - Entry node doesn't branch directly to all others
        bool is_flattened = (state_var_nodes >= 1 && max_exits >= 4) || (node_count > 8 && max_exits >= 6);
        int confidence = 0;
        std::string state_var = "";

        if (is_flattened) {
            confidence += 30;
        }
        if (max_exits >= 4) confidence += 30;
        if (node_count > 8) confidence += 20;
        confidence = std::clamp(confidence, 0, 100);

        if (is_flattened) {
            auto first_node_it = graph.nodes.begin();
            if (first_node_it != graph.nodes.end()) {
                for (const auto& instr : first_node_it->second.instrs) {
                    DISASM_INSTR dis{};
                    DbgDisasmAt(instr.addr, &dis);
                    std::string ins_text(dis.instruction);
                    std::string lower = ins_text;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                    if (lower.find("mov [") != std::string::npos && lower.find("eax") != std::string::npos) {
                        state_var = "eax";
                        break;
                    }
                    if (lower.find("mov [") != std::string::npos && lower.find("rbx") != std::string::npos) {
                        state_var = "rbx";
                        break;
                    }
                }
            }
        }

        return s_http_response::ok({
            {"is_flattened", is_flattened},
            {"state_variable", state_var},
            {"dispatch_address", format_utils::format_address(dispatch_addr)},
            {"case_count", max_exits},
            {"confidence", confidence}
        });
    });
    router.get("/api/cfg/loops", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto address = bridge.eval_expression(address_str);

        auto loops = nlohmann::json::array();
        for (int depth = 0; depth < 20; ++depth) {
            duint loop_start = 0, loop_end = 0;
            if (!DbgLoopGet(depth, address, &loop_start, &loop_end)) {
                break;
            }
            if (loop_start == 0 && loop_end == 0) break;

            // Determine loop condition from disassembly at loop end
            std::string condition = "unknown";
            bool is_infinite = false;
            int iterations_estimate = -1;

            auto disasm = bridge.disassemble_at(loop_end, 5);
            if (disasm.has_value()) {
                for (const auto& instr : disasm.value()) {
                    std::string text = instr.value("instruction", "");
                    std::string lower = text;
                    std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);
                    if (lower.find("jmp") != std::string::npos && lower.find(loop_start) != std::string::npos) {
                        condition = "unconditional jump back to start";
                        is_infinite = true;
                        iterations_estimate = -1;
                        break;
                    }
                    if (lower.find("cmp") != std::string::npos || lower.find("dec") != std::string::npos) {
                        condition = text;
                        break;
                    }
                }
            }

            loops.push_back({
                {"start", format_utils::format_address(loop_start)},
                {"end", format_utils::format_address(loop_end)},
                {"condition", condition},
                {"back_edge", true},
                {"iterations_estimate", iterations_estimate},
                {"is_infinite", is_infinite}
            });
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(address)},
            {"loops", loops},
            {"count", loops.size()}
        });
    });

    // GET /api/cfg/branch_analysis?address= - Analyze branch patterns
    router.get("/api/cfg/branch_analysis", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto address = bridge.eval_expression(address_str);

        auto bounds = bridge.get_function_bounds(address);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + address_str);
        }

        auto func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        auto func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        auto branches = nlohmann::json::array();
        duint scan = func_start;

        while (scan < func_end) {
            BASIC_INSTRUCTION_INFO info{};
            DbgDisasmFastAt(scan, &info);
            if (info.size == 0) { scan++; continue; }

            std::string text = info.instruction;
            std::string lower = text;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            if (info.branch) {
                std::string type = "conditional";
                bool is_constant = false;
                bool is_dead_code = false;
                std::string constant_value = "N/A";

                // Detect unconditional jumps
                if (lower.rfind("jmp ", 0) == 0) {
                    type = "unconditional";
                    is_dead_code = true;
                } else if (lower.rfind("call ", 0) == 0) {
                    type = "call";
                } else {
                    type = "conditional";
                    // Check if condition compares with 0/1 (potential constant)
                    if (lower.find("cmp") != std::string::npos && lower.find("0") != std::string::npos) {
                        is_constant = true;
                        constant_value = "0";
                    }
                    if (lower.find("cmp") != std::string::npos && lower.find("1") != std::string::npos) {
                        is_constant = true;
                        constant_value = "1";
                    }
                }

                branches.push_back({
                    {"address", format_utils::format_address(scan)},
                    {"type", type},
                    {"is_constant", is_constant},
                    {"constant_value", constant_value},
                    {"is_dead_code", is_dead_code}
                });
            }

            scan += info.size;
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(address)},
            {"function_start", format_utils::format_address(func_start)},
            {"function_end", format_utils::format_address(func_end)},
            {"branches", branches},
            {"count", branches.size()}
        });
    });

    // GET /api/cfg/indirect_calls?module= - Enumerate indirect calls/jumps
    router.get("/api/cfg/indirect_calls", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto module_name = req.get_query("module", "");
        duint base = 0;
        size_t scan_size = 0;

        if (!module_name.empty()) {
            base = bridge.get_module_base(module_name);
            if (base == 0) {
                return s_http_response::not_found("Module not found: " + module_name);
            }
            scan_size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module_name + ")"));
            if (scan_size == 0 || scan_size > 64 * 1024 * 1024) {
                scan_size = 64 * 1024 * 1024;
            }
        } else {
            // Scan all executable memory
            MEMMAP memmap{};
            if (!DbgMemMap(&memmap)) {
                return s_http_response::internal_error("Failed to get memory map");
            }

            // Use a reasonable scan region - first 64MB of executable pages
            for (int i = 0; i < memmap.count && scan_size == 0; ++i) {
                const auto& page = memmap.page[i];
                DWORD prot = page.mbi.Protect;
                bool is_exec = (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ ||
                                prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
                if (page.mbi.State == MEM_COMMIT && is_exec) {
                    base = reinterpret_cast<duint>(page.mbi.BaseAddress);
                    scan_size = static_cast<size_t>(page.mbi.RegionSize);
                    break;
                }
            }
            if (memmap.page) BridgeFree(memmap.page);
        }

        if (base == 0 || scan_size == 0) {
            return s_http_response::not_found("No executable memory to scan");
        }

        constexpr size_t kChunk = 4 * 1024 * 1024;
        auto indirect_targets = nlohmann::json::array();

        for (size_t off = 0; off < scan_size; off += kChunk) {
            size_t len = std::min(kChunk, scan_size - off);
            auto mem = bridge.read_memory(base + off, len);
            if (!mem.has_value()) continue;

            const auto& b = *mem;
            for (size_t i = 0; i < b.size(); ++i) {
                // Look for indirect call/jump patterns:
                // FF 15 [rel32] - call qword ptr [addr]
                // FF 25 [rel32] - jmp qword ptr [addr]
                // FF E0 / FF E1 / FF E2 - jmp eax/ecx/edx
                // 41 FF E0 - jmp r8 (x64)

                if (b[i] == 0xFF && i + 2 < b.size()) {
                    uint8_t modrm = b[i + 1];
                    if (modrm == 0x15 || modrm == 0x25) {
                        int32_t rel = 0;
                        std::memcpy(&rel, &b[i + 2], 4);
                        duint target_addr = base + off + i + 6 + static_cast<duint>(rel);
                        std::string instr_text = (modrm == 0x15) ? "call qword ptr [addr]" : "jmp qword ptr [addr]";

                        // Try to read the actual target from memory
                        std::string jump_table_base = "";
                        duint actual_target = 0;
                        auto target_mem = bridge.read_memory(target_addr, sizeof(duint));
                        if (target_mem.has_value() && target_mem->size() >= sizeof(duint)) {
                            std::memcpy(&actual_target, target_mem->data(), sizeof(duint));
                            jump_table_base = format_utils::format_address(target_addr);
                        }

                        indirect_targets.push_back({
                            {"address", format_utils::format_address(base + off + i)},
                            {"instruction", instr_text},
                            {"jump_table_base", jump_table_base},
                            {"possible_targets", nlohmann::json::array({format_utils::format_address(actual_target)})}
                        });
                    }
                } else if (b[i] == 0x41 && i + 1 < b.size() && b[i + 1] == 0xFF) {
                    // 41 FF E0 - jmp r8 (x64)
                    if (i + 2 < b.size() && (b[i + 2] == 0xE0 || b[i + 2] == 0xE1 || b[i + 2] == 0xE2 || b[i + 2] == 0xE3)) {
                        std::string reg = "unknown";
                        if (b[i + 2] == 0xE0) reg = "r8";
                        else if (b[i + 2] == 0xE1) reg = "r9";
                        else if (b[i + 2] == 0xE2) reg = "r10";
                        else if (b[i + 2] == 0xE3) reg = "r11";

                        indirect_targets.push_back({
                            {"address", format_utils::format_address(base + off + i)},
                            {"instruction", "jmp " + reg},
                            {"jump_table_base", ""},
                            {"possible_targets", nlohmann::json::array()}
                        });
                    }
                }
            }
        }

        return s_http_response::ok({
            {"indirect_targets", indirect_targets},
            {"count", indirect_targets.size()},
            {"module", module_name.empty() ? "all_executable" : module_name}
        });
    });
}

} // namespace handlers
