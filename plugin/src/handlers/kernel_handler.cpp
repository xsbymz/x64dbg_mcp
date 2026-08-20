#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <algorithm>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_kernel_routes(c_http_router& router) {
    router.get("/api/kernel/token_steal_check", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto regs = bridge.get_register_dump();
        if (!regs.has_value()) {
            return s_http_response::internal_error("Failed to get registers");
        }

        const auto& r = regs.value();

        return s_http_response::ok({
            {"current_pid", format_utils::format_address(r.regcontext.ccx)},
            {"target_pid", format_utils::format_address(r.regcontext.cdx)},
            {"token_address", format_utils::format_address(r.regcontext.cax)},
            {"status", "Token steal primitive requires kernel-mode debugger or NtQuerySystemInformation"},
            {"mitigations", nlohmann::json::array({
                "PatchGuard",
                "Kernel CFG",
                "Driver Signature Enforcement"
            })}
        });
    });

    router.get("/api/kernel/pool_overflow_detection", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        return s_http_response::ok({
            {"status", "Pool overflow detection requires kernel memory access"},
            {"pool_tags", nlohmann::json::array()},
            {"overflow_candidates", nlohmann::json::array()},
            {"note", "Use WinDbg with kernel debugging for pool overflow analysis"}
        });
    });

    router.get("/api/kernel/callbacks", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto callbacks = nlohmann::json::array();

        std::vector<std::pair<std::string, duint>> known_callbacks = {
            {"PsSetCreateProcessNotifyRoutine", bridge.eval_expression("ntdll.PsSetCreateProcessNotifyRoutine")},
            {"PsSetCreateThreadNotifyRoutine", bridge.eval_expression("ntdll.PsSetCreateThreadNotifyRoutine")},
            {"PsSetLoadImageNotifyRoutine", bridge.eval_expression("ntdll.PsSetLoadImageNotifyRoutine")},
            {"CmRegisterCallback", bridge.eval_expression("ntdll.CmRegisterCallback")},
            {"ObRegisterCallbacks", bridge.eval_expression("ntdll.ObRegisterCallbacks")}
        };

        for (const auto& [name, addr] : known_callbacks) {
            if (addr != 0) {
                callbacks.push_back({
                    {"name", name},
                    {"address", format_utils::format_address(addr)},
                    {"status", "resolved"}
                });
            }
        }

        return s_http_response::ok({
            {"callbacks", callbacks},
            {"count", callbacks.size()},
            {"note", "Full kernel callback enumeration requires kernel debugging"}
        });
    });
}

} // namespace handlers
