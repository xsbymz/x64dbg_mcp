#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_eop_detector_routes(c_http_router& router) {
    router.post("/api/eop/trace_exception_control_flow", [](const s_http_request& req) {
        json result;
        result["eop_concept"] = {
            "Exception-Oriented Programming (EOP) intentionally triggers CPU hardware exceptions as normal control flow",
            "Each basic block ends with an intentional fault (e.g. #DE divide error, #BP int3, #GP access violation, #UD invalid opcode)",
            "Vectored Exception Handler (VEH) catches exception, inspects ExceptionRecord, modifies ContextRecord.Rip, returns EXCEPTION_CONTINUE_EXECUTION",
            "Heavily obfuscates Control Flow Graphs (CFG) making static decompiler analysis appear as dead-end traps"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/eop/detect_intentional_exceptions", [](const s_http_request& req) {
        json result;
        result["intentional_fault_patterns"] = {
            {"Divide_By_Zero", "XOR ECX, ECX; DIV ECX (Triggers #DE 0xC0000094)"},
            {"Privileged_Instruction", "CLI, STI, HLT, IN, OUT in user mode (Triggers #GP 0xC0000096)"},
            {"Single_Step_Trap", "PUSHF; OR [RSP], 0x100 (Trap Flag); POPF (Triggers #DB 0x80000004)"},
            {"Guard_Page_Hit", "Access to PAGE_GUARD page to invoke VEH before decrypting next stage"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/eop/map_veh_dispatch_graph", [](const s_http_request& req) {
        json result;
        result["reconstruction_strategy"] = {
            "1. Enumerate registered VEH handlers via ntdll!RtlpCalloutEntryList",
            "2. Set software breakpoint on VEH entry point",
            "3. Record mapping: [Faulting_RIP, ExceptionCode] -> [Target_ContextRecord_Rip]",
            "4. Synthesize direct unconditional jump edges to reconstruct true CFG in x64dbg"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

