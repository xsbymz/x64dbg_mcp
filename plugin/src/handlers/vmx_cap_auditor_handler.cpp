#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <intrin.h>
using json = nlohmann::json;

namespace handlers {
void register_vmx_cap_auditor_routes(c_http_router& router) {
    router.post("/api/vmx_cap/audit_msrs", [](const httplib::Request&, httplib::Response& res) {
        json result;
        int info[4] = {};
        __cpuid(info, 1);
        bool vmxSupported = (info[2] >> 5) & 1;
        result["vmx_hardware_supported"] = vmxSupported;

        result["vmx_msr_matrix"] = {
            {"0x480", "IA32_VMX_BASIC — VMCS revision identifier, VMCS region size, memory type for VMCS"},
            {"0x481", "IA32_VMX_PINBASED_CTLS — Pin-based VM-execution controls (External-interrupt, NMI, Virtual NMIs)"},
            {"0x482", "IA32_VMX_PROCBASED_CTLS — Primary Processor-based VM-execution controls (CR3 load/store, TSC offset)"},
            {"0x483", "IA32_VMX_EXIT_CTLS — VM-exit controls (Host address-space size, Save/Load MSRs, Ack interrupt)"},
            {"0x484", "IA32_VMX_ENTRY_CTLS — VM-entry controls (Load debug controls, IA-32e mode guest, Load MSRs)"},
            {"0x485", "IA32_VMX_MISC — Activity states (HLT, Shutdown, Wait-for-SIPI), CR3-target values count"},
            {"0x486", "IA32_VMX_CR0_FIXED0 / IA32_VMX_CR0_FIXED1 — Bits in CR0 that must be fixed to 0 or 1 in VMX operation"},
            {"0x487", "IA32_VMX_CR4_FIXED0 / IA32_VMX_CR4_FIXED1 — Bits in CR4 that must be fixed to 0 or 1 in VMX operation"},
            {"0x48B", "IA32_VMX_PROCBASED_CTLS2 — Secondary Processor-based VM-execution controls (EPT, RDTSCP, VPID, Descriptor table exiting)"},
            {"0x48C", "IA32_VMX_EPT_VPID_CAP — EPT page walk length (4 levels), 2MB/1GB large pages, INVEPT/INVVPID instructions"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/vmx_cap/evaluate_nested_virt", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["nested_virtualization_indicators"] = {
            {"Shadow_VMCS", "IA32_VMX_MISC bit 28 = 1 indicates hardware support for VMWRITE/VMREAD to shadow VMCS without VMEXIT"},
            {"EPT_Violations", "Secondary Proc-based control bit 1 (Enable EPT) supported in nested L1 hypervisor"},
            {"Virtual_APIC", "Virtual-interrupt delivery and APIC-register virtualization supported for L2 guest"}
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
