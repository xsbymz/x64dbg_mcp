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

namespace handlers {

void register_obfuscation_routes(c_http_router& router) {
    // GET /api/obfuscation/detect?address=&count= - Detect obfuscation techniques in code region
    router.get("/api/obfuscation/detect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto count_str = req.get_query("count", "64");
        auto address = bridge.eval_expression(address_str);
        int count = std::clamp(format_utils::safe_parse_int(count_str, 64), 1, 1000);

        auto result = bridge.disassemble_at(address, count);
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        const auto& instructions = result.value();
        int obfuscation_score = 0;
        auto techniques = nlohmann::json::array();

        int switch_count = 0;
        int cmp_count = 0;
        int indirect_jmp_count = 0;
        int arithmetic_heavy = 0;
        int nop_count = 0;

        for (const auto& instr : instructions) {
            std::string text = instr.value("instruction", "");
            std::string lower = text;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            // Extract mnemonic (first token)
            std::string mnemonic = lower.substr(0, lower.find(' '));
            std::string operands = "";
            size_t sp = lower.find(' ');
            if (sp != std::string::npos) {
                operands = lower.substr(sp + 1);
            }

            // Switch-based state machine (jmp [reg + offset])
            if (mnemonic == "jmp" && operands.find('[') != std::string::npos && operands.find('+') != std::string::npos) {
                switch_count++;
            }

            // Indirect jumps via register (JOP / VM dispatch)
            if (mnemonic == "jmp" && operands.find('[') == std::string::npos && operands.find("eax") != std::string::npos) {
                indirect_jmp_count++;
            }

            // High conditional density
            if (mnemonic == "cmp" || mnemonic == "test") {
                cmp_count++;
            }

            // Arithmetic substitution
            if (mnemonic == "imul" || mnemonic == "mul" || mnemonic == "xor") {
                arithmetic_heavy++;
            }

            // Nop sleds / dead code padding
            if (mnemonic == "nop") {
                nop_count++;
            }
        }

        if (switch_count >= 2) {
            int conf = std::clamp(switch_count * 15, 20, 100);
            techniques.push_back({
                {"type", "control_flow_flattening"},
                {"confidence", conf},
                {"address", format_utils::format_address(address)},
                {"description", "Switch-based state machine with " + std::to_string(switch_count) + " dispatches"}
            });
            obfuscation_score += 20;
        }

        if (indirect_jmp_count >= 2) {
            int conf = std::clamp(indirect_jmp_count * 10, 20, 100);
            techniques.push_back({
                {"type", "jump_obfuscation"},
                {"confidence", conf},
                {"address", format_utils::format_address(address)},
                {"description", std::to_string(indirect_jmp_count) + " indirect register jumps detected"}
            });
            obfuscation_score += 15;
        }

        if (cmp_count > count / 4 && cmp_count > 3) {
            int conf = std::clamp(static_cast<int>(cmp_count * 4), 20, 100);
            techniques.push_back({
                {"type", "opaque_predicates"},
                {"confidence", conf},
                {"address", format_utils::format_address(address)},
                {"description", "High conditional density (" + std::to_string(cmp_count) + " comparisons in window)"}
            });
            obfuscation_score += 15;
        }

        if (arithmetic_heavy > count / 8) {
            int conf = std::clamp(arithmetic_heavy * 6, 20, 100);
            techniques.push_back({
                {"type", "instruction_substitution"},
                {"confidence", conf},
                {"address", format_utils::format_address(address)},
                {"description", "Arithmetic-heavy patterns suggesting substitution obfuscation"}
            });
            obfuscation_score += 10;
        }

        if (nop_count > 8) {
            int conf = std::clamp(nop_count * 2, 20, 100);
            techniques.push_back({
                {"type", "dead_code_insertion"},
                {"confidence", conf},
                {"address", format_utils::format_address(address)},
                {"description", std::to_string(nop_count) + " NOPs suggest padding/dead code"}
            });
            obfuscation_score += 10;
        }

        obfuscation_score = std::clamp(obfuscation_score, 0, 100);
        bool is_obfuscated = obfuscation_score > 30;

        return s_http_response::ok({
            {"obfuscation_score", obfuscation_score},
            {"techniques", techniques},
            {"is_obfuscated", is_obfuscated}
        });
    });

    // GET /api/obfuscation/vm_detect?address=&count= - Detect virtual machine/interpreter patterns
    router.get("/api/obfuscation/vm_detect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto count_str = req.get_query("count", "128");
        auto address = bridge.eval_expression(address_str);
        int count = std::clamp(format_utils::safe_parse_int(count_str, 128), 1, 2000);

        auto result = bridge.disassemble_at(address, count);
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        const auto& instructions = result.value();
        int switch_ops = 0;
        int dispatch_hits = 0;
        int bytecode_fetch = 0;
        int custom_reg = 0;
        duint dispatch_addr = 0;
        std::vector<duint> handler_addrs;

        for (const auto& instr : instructions) {
            std::string text = instr.value("instruction", "");
            std::string lower = text;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            std::string mnemonic = lower.substr(0, lower.find(' '));
            std::string operands = "";
            size_t sp = lower.find(' ');
            if (sp != std::string::npos) {
                operands = lower.substr(sp + 1);
            }

            // Dispatch via jump table
            if (mnemonic == "jmp" && operands.find('[') != std::string::npos && operands.find('+') != std::string::npos) {
                switch_ops++;
                if (dispatch_addr == 0) {
                    dispatch_addr = format_utils::parse_address(instr.value("address", "0"));
                }
            }

            // Bytecode fetch: movzx from byte ptr
            if ((mnemonic == "movzx" || mnemonic == "movsx") && operands.find("byte ptr") != std::string::npos) {
                bytecode_fetch++;
            }

            // Opcode decode cmp
            if (mnemonic == "cmp" && operands.find("0x") != std::string::npos && operands.find("eax") != std::string::npos) {
                dispatch_hits++;
            }

            // Custom register bank (XMM/MMX used for general purpose)
            if ((mnemonic.find("movdqa") != std::string::npos || mnemonic.find("vmovdqa") != std::string::npos ||
                 mnemonic.find("movq") != std::string::npos) && operands.find("xmm") != std::string::npos) {
                custom_reg++;
            }
        }

        bool is_vm = (switch_ops >= 3 && bytecode_fetch >= 2) || (dispatch_hits >= 4 && switch_ops >= 2);
        int confidence = 0;
        if (switch_ops >= 3) confidence += 30;
        if (bytecode_fetch >= 2) confidence += 30;
        if (dispatch_hits >= 4) confidence += 20;
        if (custom_reg >= 1) confidence += 20;
        confidence = std::clamp(confidence, 0, 100);

        return s_http_response::ok({
            {"is_vm", is_vm},
            {"vm_info", {
                {"dispatch_address", format_utils::format_address(dispatch_addr)},
                {"opcode_count", bytecode_fetch},
                {"handler_count", switch_ops},
                {"custom_registers", custom_reg}
            }},
            {"confidence", confidence}
        });
    });

    // GET /api/obfuscation/string_decrypt?address= - Attempt to decrypt strings at address
    router.get("/api/obfuscation/string_decrypt", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        auto mem = bridge.read_memory(address, 256);
        if (!mem.has_value() || mem->empty()) {
            return s_http_response::not_found("No readable memory at address");
        }

        const auto& data = *mem;
        auto decrypted_strings = nlohmann::json::array();

        // Try single-byte XOR
        for (int key = 1; key < 256; ++key) {
            std::string candidate;
            candidate.reserve(std::min<size_t>(data.size(), 64));
            bool printable = true;
            for (size_t i = 0; i < data.size() && i < 64; ++i) {
                char c = static_cast<char>(data[i] ^ key);
                if (c < 0x20 || c > 0x7E) { printable = false; break; }
                candidate += c;
            }
            if (printable && candidate.size() >= 4) {
                decrypted_strings.push_back({
                    {"address", format_utils::format_address(address)},
                    {"encrypted", format_utils::format_bytes_compact(data.data(), std::min<size_t>(data.size(), 16))},
                    {"decrypted", candidate},
                    {"key", format_utils::format_hex(key)},
                    {"algorithm", "xor_single_byte"}
                });
                break;
            }
        }

        // Try rolling XOR
        if (decrypted_strings.empty()) {
            for (int key = 1; key < 256; ++key) {
                std::string candidate;
                candidate.reserve(std::min<size_t>(data.size(), 64));
                bool printable = true;
                uint8_t cur_key = static_cast<uint8_t>(key);
                for (size_t i = 0; i < data.size() && i < 64; ++i) {
                    char c = static_cast<char>(data[i] ^ cur_key);
                    if (c < 0x20 || c > 0x7E) { printable = false; break; }
                    candidate += c;
                    cur_key = (cur_key + 1) & 0xFF;
                }
                if (printable && candidate.size() >= 4) {
                    decrypted_strings.push_back({
                        {"address", format_utils::format_address(address)},
                        {"encrypted", format_utils::format_bytes_compact(data.data(), std::min<size_t>(data.size(), 16))},
                        {"decrypted", candidate},
                        {"key", format_utils::format_hex(key)},
                        {"algorithm", "xor_rolling"}
                    });
                    break;
                }
            }
        }

        // Try simple substitution (Caesar shift)
        if (decrypted_strings.empty()) {
            for (int shift = 1; shift < 26; ++shift) {
                std::string candidate;
                candidate.reserve(std::min<size_t>(data.size(), 64));
                bool printable = true;
                for (size_t i = 0; i < data.size() && i < 64; ++i) {
                    char c = static_cast<char>((data[i] - shift) & 0xFF);
                    if (c < 0x20 || c > 0x7E) { printable = false; break; }
                    candidate += c;
                }
                if (printable && candidate.size() >= 4) {
                    decrypted_strings.push_back({
                        {"address", format_utils::format_address(address)},
                        {"encrypted", format_utils::format_bytes_compact(data.data(), std::min<size_t>(data.size(), 16))},
                        {"decrypted", candidate},
                        {"key", std::to_string(shift)},
                        {"algorithm", "substitution_caesar"}
                    });
                    break;
                }
            }
        }

        return s_http_response::ok({
            {"decrypted_strings", decrypted_strings},
            {"attempted", decrypted_strings.size() > 0}
        });
    });

    // GET /api/obfuscation/opaque_predicates?address=&count= - Find opaque predicates
    router.get("/api/obfuscation/opaque_predicates", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto count_str = req.get_query("count", "64");
        auto address = bridge.eval_expression(address_str);
        int count = std::clamp(format_utils::safe_parse_int(count_str, 64), 1, 1000);

        auto result = bridge.disassemble_at(address, count);
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        const auto& instructions = result.value();
        auto predicates = nlohmann::json::array();

        for (const auto& instr : instructions) {
            std::string text = instr.value("instruction", "");
            std::string lower = text;
            std::transform(lower.begin(), lower.end(), lower.begin(), ::tolower);

            std::string mnemonic = lower.substr(0, lower.find(' '));
            std::string operands = "";
            size_t sp = lower.find(' ');
            if (sp != std::string::npos) {
                operands = lower.substr(sp + 1);
            }

            // Pattern: cmp X, 0 (possible always-true/false check)
            if (mnemonic == "cmp" && operands.find("0") != std::string::npos) {
                bool is_opaque = false;
                int confidence = 30;
                std::string desc = "Comparison with zero";

                if (operands.find("eax") != std::string::npos || operands.find("rax") != std::string::npos ||
                    operands.find("ecx") != std::string::npos || operands.find("rcx") != std::string::npos) {
                    confidence = 60;
                    desc = "Register compared with zero - possible opaque predicate";
                    is_opaque = true;
                }

                predicates.push_back({
                    {"address", instr.value("address", "")},
                    {"condition", text},
                    {"is_opaque", is_opaque},
                    {"confidence", confidence},
                    {"description", desc}
                });
            }

            // Pattern: test X, X (always true unless X==0)
            if (mnemonic == "test") {
                size_t comma = operands.find(',');
                if (comma != std::string::npos) {
                    std::string lhs = operands.substr(0, comma);
                    std::string rhs = operands.substr(comma + 1);
                    size_t rhs_start = rhs.find_first_not_of(" \t");
                    std::string rhs_clean = (rhs_start != std::string::npos) ? rhs.substr(rhs_start) : "";

                    if (lhs == rhs_clean) {
                        predicates.push_back({
                            {"address", instr.value("address", "")},
                            {"condition", text},
                            {"is_opaque", true},
                            {"confidence", 70},
                            {"description", "Self-test (reg & reg == 0 is always false) - likely opaque predicate"}
                        });
                    }
                }
            }

            // Pattern: imul rax, rax followed by cmp
            if (mnemonic == "imul" && operands.find("eax") != std::string::npos) {
                predicates.push_back({
                    {"address", instr.value("address", "")},
                    {"condition", text},
                    {"is_opaque", true},
                    {"confidence", 50},
                    {"description", "Signed multiply - possible opaque predicate component (x*x > 0)"}
                });
            }
        }

        return s_http_response::ok({
            {"predicates", predicates}
        });
    });
}

} // namespace handlers
