#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <intrin.h>
using json = nlohmann::json;

namespace handlers {
void register_cr_register_routes(c_http_router& router) {
    router.post("/api/cr_regs/read_all", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["cr_register_reference"] = {
            {"CR0",{
                {"bit0","PE — Protected Mode Enable"},{"bit16","WP — Write Protect (kernel cannot write RO pages)"},
                {"bit29","NW — Not Write-through"},{"bit30","CD — Cache Disable"},
                {"bit31","PG — Paging Enable (must be 1 in long mode)"}
            }},
            {"CR2","Page Fault Linear Address — last faulting VA"},
            {"CR3","Page Directory Base Register (PDBR) — physical address of PML4"},
            {"CR4",{
                {"bit0","VME — Virtual-8086 Mode Extensions"},{"bit5","PAE — Physical Address Extension"},
                {"bit7","PGE — Page Global Enable"},{"bit10","OSXMMEXCPT — SSE unmasked exceptions"},
                {"bit11","UMIP — User Mode Instruction Prevention (blocks SGDT/SIDT/SLDT from ring3)"},
                {"bit13","VMXE — VMX Enable"},{"bit14","SMXE — Safer Mode Extensions"},
                {"bit16","FSGSBASE — RDFSBASE/WRFSBASE in ring3"},
                {"bit17","PCIDE — Process-Context Identifiers (ASID-like TLB tags)"},
                {"bit18","OSXSAVE — XSAVE/AVX Enable"},{"bit20","SMEP — Supervisor Mode Execution Prevention"},
                {"bit21","SMAP — Supervisor Mode Access Prevention"},
                {"bit22","PKE — Protection Keys Enable"},{"bit23","CET — Control-flow Enforcement"},
                {"bit24","PKS — Protection Keys for Supervisor"}
            }},
            {"CR8","Task Priority Register (TPR) — interrupt priority threshold (bits 3:0)"}
        };
        // Read CR4 via CPUID (some bits visible)
        int info[4] = {};
        __cpuid(info,1);
        // ECX bit 5 = VMX, bit 6 = SMX
        result["cpuid_vmx_supported"] = (info[2]>>5)&1;
        result["cpuid_smx_supported"] = (info[2]>>6)&1;
        result["cpuid_pcid_supported"] = (info[2]>>17)&1;
        result["cpuid_xsave_supported"] = (info[2]>>26)&1;
        __cpuidex(info,7,0);
        result["cpuid_smep_supported"] = (info[1]>>7)&1;
        result["cpuid_smap_supported"] = (info[1]>>20)&1;
        result["cpuid_cet_supported"]  = (info[3]>>7)&1;
        result["cpuid_umip_supported"] = (info[2]>>2)&1;
        result["note"] = "CR register reads (MOV RAX,CR0/CR4) require ring-0. Use kernel debug context. CR0.WP=0 means kernel can write read-only pages — critical exploit primitive.";
        res.set_content(result.dump(), "application/json");
    });
    router.post("/api/cr_regs/check_smep_smap", [](const httplib::Request&, httplib::Response& res) {
        json result;
        int info[4]={};
        __cpuidex(info,7,0);
        result["smep_cpuid_supported"] = (info[1]>>7)&1;
        result["smap_cpuid_supported"] = (info[1]>>20)&1;
        result["smep_significance"] = "SMEP (CR4.bit20): prevents kernel from executing user-mode pages. Bypassed by: (1) clearing CR4.bit20 via kernel exploit, (2) using kernel-controlled data page containing shellcode that gets executed, (3) ret2usr via userland address in kernel context";
        result["smap_significance"] = "SMAP (CR4.bit21): prevents kernel from reading/writing user-mode pages without CLAC/STAC. Bypassed by: (1) clearing CR4.bit21, (2) using kernel data structures that reference user addresses";
        result["bypass_primitives"] = {
            {"CR4_clear","Need arbitrary write to kernel memory or MSR write to clear SMEP/SMAP bits"},
            {"CR0_WP_clear","Clears write protection — allows patching read-only kernel code pages"},
            {"native_API","NtSetSystemInformation(SystemFlags) can clear some protections in debug builds"}
        };
        res.set_content(result.dump(), "application/json");
    });
    router.post("/api/cr_regs/detect_cleared_wp_bit", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["wp_bit_significance"] = "CR0.WP (bit 16): when cleared, kernel code can write to read-only (PAGE_READONLY) mapped pages. Classic primitive for patching ntoskrnl SSDT, IDT, or kernel code from ring-0 exploit.";
        result["detection_indicators"] = {
            "Monitor CR0 value before/after suspicious kernel operations (requires hypervisor or hardware debugger)",
            "ETW Microsoft-Windows-Kernel-General events for unusual privilege changes",
            "Hypervisor VMEXIT on MOV to CR0 instruction (VMX VM-execution controls)"
        };
        result["real_world_usage"] = {
            "Most kernel exploits clear WP bit before patching SSDT",
            "DKO M (Direct Kernel Object Manipulation) tool clears WP to patch EPROCESS",
            "DKOM rootkits use WP clear + write + WP restore in kernel thread"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
