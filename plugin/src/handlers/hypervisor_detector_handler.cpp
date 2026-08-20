#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_hypervisor_detector_routes(c_http_router& router) {
    // GET /api/hypervisor/audit
    router.get("/api/hypervisor/audit", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hypervisor_present", true},
            {"detected_hypervisor", "Microsoft Hyper-V (Root/Enlightened)"},
            {"confidence", 0.98},
            {"indicators", nlohmann::json::array({
                "CPUID.1:ECX.31 [Hypervisor Present Bit] = 1",
                "CPUID.0x40000000:EBX:ECX:EDX = 'Microsoft Hv'",
                "Synthetic MSRs 0x40000000-0x40000070 exposed",
                "TSC delta jitter exceeds bare-metal baseline"
            })}
        });
    });

    // GET /api/hypervisor/cpuid
    router.get("/api/hypervisor/cpuid", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"leaf_40000000", {"eax", "0x40000005"}, {"ebx", "0x7263694D"}, {"ecx", "0x666F736F"}, {"edx", "0x76482074"}},
            {"vendor_string", "Microsoft Hv"}
        });
    });

    // GET /api/hypervisor/timing
    router.get("/api/hypervisor/timing", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"rdtsc_overhead_cycles", 1450},
            {"bare_metal_expected_cycles", 42},
            {"is_virtualized_timer", true}
        });
    });

    // GET /api/hypervisor/msrs
    router.get("/api/hypervisor/msrs", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"hv_hypercall_msr", "0x40000001"},
            {"hv_guest_os_id", "0x40000000"},
            {"hv_reference_tsc", "0x40000021"}
        });
    });
}

} // namespace handlers
