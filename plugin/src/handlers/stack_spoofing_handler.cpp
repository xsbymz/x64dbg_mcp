#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_stack_spoofing_routes(c_http_router& router) {
    router.post("/api/stack_spoof/validate_all_thread_stacks", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["stack_spoofing_concepts"] = {
            {"Synthetic_Frames", "Constructing fake stack frames pointing to legitimate functions (e.g. BaseThreadInitThunk, RtlUserThreadStart)"},
            {"Stack_Pivoting", "Temporarily pointing RSP to spoofed stack buffer during sleep / alertable wait"},
            {"SilentMoonwalk", "Desynchronizing frame pointers and return addresses using custom VEH unwinding"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/stack_spoof/detect_unwind_anomalies", [](const s_http_request& req) {
        json result;
        result["unwind_validation_strategy"] = {
            "1. Walk call stack using RtlVirtualUnwind and RUNTIME_FUNCTION table (.pdata section)",
            "2. For each return address, verify existence of matching UNWIND_INFO structure in the target module",
            "3. Check for RSP modifications not accounted for by frame unwind codes (UWOP_ALLOC_SMALL, UWOP_ALLOC_LARGE, UWOP_PUSH_NONVOL)",
            "4. Flag return addresses that land in non-CALL instruction boundaries (e.g. mid-instruction or after NOP padding)"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/stack_spoof/find_forged_return_addresses", [](const s_http_request& req) {
        json result;
        result["forged_frame_indicators"] = {
            "Return address points into valid signed module but calling instruction preceding it is JMP/RET instead of CALL",
            "Stack frame lacks corresponding activation record in ETW Microsoft-Windows-Threat-Intelligence stack telemetry",
            "Frame pointer RBP / RSP does not align with Thread TEB.StackBase and TEB.StackLimit bounds"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

