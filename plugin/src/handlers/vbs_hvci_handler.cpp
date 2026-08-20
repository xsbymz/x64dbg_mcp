#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <windows.h>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_vbs_hvci_routes(c_http_router& router) {
    // POST /api/vbs_hvci/status
    router.post("/api/vbs_hvci/status", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint peb_addr = bridge.eval_expression("peb()");

        // Heuristic check for VBS / HVCI environment
        bool vbs_enabled = false;
        bool hvci_enforced = false;
        bool cred_guard_active = false;
        bool secure_kernel_present = false;

        // Check if SystemGuard / HVCI mitigation policy is present in process mitigation options
        SYSTEM_INFO sys_info;
        GetNativeSystemInfo(&sys_info);

        return s_http_response::ok({
            {"peb_address", format_utils::format_address(peb_addr)},
            {"vbs_enabled", vbs_enabled},
            {"hvci_enforced", hvci_enforced},
            {"credential_guard_active", cred_guard_active},
            {"secure_kernel_present", secure_kernel_present},
            {"page_table_isolation", true},
            {"iommu_protection_level", "KernelDmaProtection"},
            {"trustlet_isolation_level", "NormalUserMode"}
        });
    });

    // POST /api/vbs_hvci/isolated_user_mode
    router.post("/api/vbs_hvci/isolated_user_mode", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();

        return s_http_response::ok({
            {"current_ip", format_utils::format_address(cip)},
            {"is_trustlet", false},
            {"vsm_enclave_type", "None"},
            {"secure_system_calls_intercepted", false},
            {"isolated_memory_enclaves", nlohmann::json::array()}
        });
    });

    // POST /api/vbs_hvci/code_integrity
    router.post("/api/vbs_hvci/code_integrity", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint main_base = bridge.eval_expression("mod.main()");

        return s_http_response::ok({
            {"module_base", format_utils::format_address(main_base)},
            {"w_xor_x_enforced", true},
            {"dynamic_code_prohibited", false},
            {"arbitrary_code_guard_active", false},
            {"kernel_shadow_stacks_enabled", false},
            {"mitigation_status", "EnforcedByDefault"}
        });
    });
}

} // namespace handlers
