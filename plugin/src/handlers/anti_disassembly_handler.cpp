#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_anti_disassembly_routes(c_http_router& router) {
    router.post("/api/anti_disasm/detect_overlapping_instructions", [](const s_http_request& req) {
        json result;
        result["overlapping_instruction_techniques"] = {
            {"Jump_Into_Middle", "EB FF C0 (JMP $+1) landing on byte 0xC0 inside multi-byte instruction"},
            {"Conditional_Always_Taken", "XOR EAX, EAX; JZ $+2; [junk byte]; [actual code]"},
            {"Call_Plus_Five", "E8 00 00 00 00 (CALL $+5); POP RAX — used for PIC delta calculation and disassembler desync"},
            {"Two_Way_Jump", "Two conditional branches with opposite conditions jumping to same target with 1-byte offset difference"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/anti_disasm/find_junk_prefixes", [](const s_http_request& req) {
        json result;
        result["prefix_obfuscation_patterns"] = {
            {"Excessive_Prefixes", "Chains of 0x66 (operand-size), 0x67 (address-size), 0x2E/0x3E (segment override) before instruction"},
            {"REX_Prefix_Stacking", "Repeated REX prefixes (0x40-0x4F) in 64-bit mode to pad instruction length"},
            {"LOCK_Prefix_Misuse", "0xF0 (LOCK) on instructions that do not support bus locking (causes #UD or disasm failure)"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/anti_disasm/compare_linear_vs_recursive", [](const s_http_request& req) {
        json result;
        result["disassembly_strategy_comparison"] = {
            {"Linear_Sweep", "Decodes sequential memory bytes regardless of control flow (easily tricked by junk bytes in dead code)"},
            {"Recursive_Descent", "Follows control flow graph (JMP, CALL, RET, conditional branches) to identify real basic blocks"},
            {"Discrepancy_Analysis", "Locations where linear sweep decodes invalid instructions while recursive descent successfully navigates reveal intentional anti-disassembly traps"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

