#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <algorithm>
#include <cmath>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_scriptapi_assembler.h"

namespace handlers {

static double calc_entropy(const uint8_t* data, size_t size) {
    if (size == 0) return 0.0;
    int freq[256] = {0};
    for (size_t i = 0; i < size; ++i) freq[data[i]]++;
    double ent = 0.0;
    for (int i = 0; i < 256; ++i) {
        if (freq[i] > 0) {
            double p = static_cast<double>(freq[i]) / size;
            ent -= p * std::log2(p);
        }
    }
    return ent;
}

void register_unpacker_routes(c_http_router& router) {
    router.post("/api/unpacker/auto", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string module_name = (!body.is_discarded() && body.contains("module")) ? body["module"].get<std::string>() : "";
        int max_iter = body.value("max_iterations", 5);
        duint oep_hint = 0;
        if (!body.is_discarded() && body.contains("oep_hint")) {
            oep_hint = body["oep_hint"].get<duint>();
        }

        if (module_name.empty()) {
            module_name = "main.exe";
        }

        auto base = bridge.get_module_base(module_name);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module_name);
        }

        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module_name + ")"));
        if (size == 0) size = 0x100000;

        auto mem = bridge.read_memory(base, size > 0x100000 ? 0x100000 : size);
        double entropy_before = 0.0;
        if (mem.has_value()) {
            entropy_before = calc_entropy(mem->data(), mem->size());
        }

        nlohmann::json oep_candidates = nlohmann::json::array();
        int iterations = 0;

        for (int iter = 0; iter < max_iter; ++iter) {
            iterations = iter + 1;

            auto disasm = bridge.disassemble_at(bridge.eval_expression("cip"), 30);
            if (!disasm.has_value()) break;

            bool found_tail_jump = false;
            duint jump_target = 0;
            for (const auto& instr : disasm.value()) {
                if (instr.contains("jmp") || instr.contains("call")) {
                    auto target = bridge.eval_expression("dis.branchtarget(" + instr["address"].get<std::string>() + ")");
                    if (target != 0 && target > base + size * 0.8) {
                        found_tail_jump = true;
                        jump_target = target;
                        break;
                    }
                }
            }

            if (found_tail_jump && jump_target != 0) {
                oep_candidates.push_back({
                    {"address", format_utils::format_address(jump_target)},
                    {"reason", "tail_jump_to_high_address"},
                    {"iteration", iter + 1}
                });

                std::string set_cip = "setcip " + format_utils::format_address(jump_target);
                bridge.exec_command(set_cip);
            }

            if (oep_hint != 0 && bridge.eval_expression("cip") == oep_hint) {
                oep_candidates.push_back({
                    {"address", format_utils::format_address(oep_hint)},
                    {"reason", "reached_oep_hint"},
                    {"iteration", iter + 1}
                });
                break;
            }
        }

        auto final_mem = bridge.read_memory(base, size > 0x100000 ? 0x100000 : size);
        double entropy_after = 0.0;
        if (final_mem.has_value()) {
            entropy_after = calc_entropy(final_mem->data(), final_mem->size());
        }

        return s_http_response::ok({
            {"module", module_name},
            {"iterations", iterations},
            {"oep_candidates", oep_candidates},
            {"entropy_before", entropy_before},
            {"entropy_after", entropy_after},
            {"success", !oep_candidates.empty()},
            {"message", oep_candidates.empty() ? "No OEP candidates found" : "OEP candidates identified"}
        });
    });

    router.get("/api/unpacker/entry_candidates", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module = req.get_query("module", "");
        if (module.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        auto base = bridge.get_module_base(module);
        if (base == 0) {
            return s_http_response::not_found("Module not found: " + module);
        }

        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));
        if (size == 0) size = 0x100000;

        auto candidates = nlohmann::json::array();
        auto scan_size = size > 0x100000 ? 0x100000 : size;
        duint scan_end = base + scan_size;

        for (duint addr = base; addr < scan_end - 16; ) {
            DISASM_INSTR instr{};
            DbgDisasmAt(addr, &instr);
            if (instr.instr_size == 0) { addr++; continue; }

            std::string mnemonic = instr.instruction;
            std::transform(mnemonic.begin(), mnemonic.end(), mnemonic.begin(), ::tolower);

            if (mnemonic.starts_with("jmp") || mnemonic.starts_with("call")) {
                auto target = bridge.eval_expression("dis.branchtarget(" + format_utils::format_address(addr) + ")");
                if (target != 0 && target >= scan_end * 0.8) {
                    candidates.push_back({
                        {"address", format_utils::format_address(addr)},
                        {"target", format_utils::format_address(target)},
                        {"target_module", bridge.get_module_at(target)},
                        {"reason", "tail_jump_to_high_address"},
                        {"instruction", instr.instruction}
                    });
                }
            }

            addr += instr.instr_size;
            if (candidates.size() >= 50) break;
        }

        return s_http_response::ok({
            {"module", module},
            {"candidates", candidates},
            {"count", candidates.size()}
        });
    });
}

} // namespace handlers
