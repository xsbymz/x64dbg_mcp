#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <intrin.h>
using json = nlohmann::json;

namespace handlers {
void register_msr_auditor_routes(c_http_router& router) {

    router.post("/api/msr/read_critical_msrs", [](const s_http_request& req) {
        json result;
        result["msr_reference"] = {
            {"0xC0000080","IA32_EFER — Extended Feature Enable: LME(bit8)=LongMode, NXE(bit11)=No-Execute Enable, SVME(bit12)=VMX"},
            {"0xC0000081","IA32_STAR — SYSCALL CS/SS selectors"},
            {"0xC0000082","IA32_LSTAR — SYSCALL 64-bit handler VA — ROOTKIT HOOK TARGET"},
            {"0xC0000083","IA32_CSTAR — SYSCALL compat-mode handler"},
            {"0xC0000084","IA32_SFMASK — SYSCALL RFLAGS mask"},
            {"0x00000174","IA32_SYSENTER_CS — SYSENTER handler CS"},
            {"0x00000175","IA32_SYSENTER_ESP — SYSENTER kernel stack"},
            {"0x00000176","IA32_SYSENTER_EIP — SYSENTER handler VA — LEGACY HOOK TARGET"},
            {"0x0000003A","IA32_FEATURE_CONTROL — VMX lock, SMXE"},
            {"0x00000048","IA32_SPEC_CTRL — IBRS(bit0)/STIBP(bit1)/SSBD(bit2) Spectre mitigations"},
            {"0x00000049","IA32_PRED_CMD — IBPB flush command"},
            {"0x00000000","IA32_P5_MC_ADDR — P5 MC address"},
            {"0x0000008B","IA32_BIOS_SIGN_ID — Microcode version (read after CPUID)"},
            {"0x0000010A","IA32_ARCH_CAPABILITIES — Hardware vuln mitigation flags"},
            {"0x00000277","IA32_PAT — Page Attribute Table"},
            {"0xC0000100","FS.Base — 64-bit FS segment base (TEB in user-mode)"},
            {"0xC0000101","GS.Base — 64-bit GS segment base (KPCR in kernel-mode)"},
            {"0xC0000102","KernelGSBase — Shadow GS (swapped by SWAPGS)"}
        };
        result["lstar_significance"] = "IA32_LSTAR (0xC0000082) points to KiSystemCall64 in ntoskrnl.exe. Rootkit overwrites this to intercept ALL system calls. Detection: read MSR, verify points into ntoskrnl text segment.";
        result["note"] = "MSR reads require kernel-mode privileges (RDMSR is ring-0 only). Use kernel driver or x64dbg kernel debug mode.";
        // Try CPUID for visible flags
        int cpuInfo[4] = {};
        __cpuid(cpuInfo, 1);
        result["cpuid_1_ecx"] = cpuInfo[2];
        result["cpuid_1_edx"] = cpuInfo[3];
        result["vmx_supported"] = (cpuInfo[2] >> 5) & 1;
        __cpuid(cpuInfo, 7);
        result["ibrs_ibpb_supported"] = (cpuInfo[3] >> 26) & 1;
        result["stibp_supported"] = (cpuInfo[3] >> 27) & 1;
        result["ssbd_supported"] = (cpuInfo[3] >> 31) & 1;
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/msr/detect_lstar_hook", [](const s_http_request& req) {
        json result;
        result["detection_method"] = {
            {"step1","Read LSTAR MSR (0xC0000082) value via RDMSR in kernel context"},
            {"step2","Enumerate all loaded kernel modules and their VA ranges"},
            {"step3","Check LSTAR value falls within ntoskrnl.exe .text section"},
            {"step4","If outside ntoskrnl range: LSTAR is hooked — record value as IOC"},
            {"step5","Also check for trampoline: if LSTAR points into ntoskrnl but first instruction is JMP elsewhere"}
        };
        result["expected_target"] = "nt!KiSystemCall64 (ntoskrnl.exe text section)";
        result["known_rootkits_using_lstar"] = {"Azazel","Custom kernel backdoors","Nation-state implants (various)"};
        result["bypass_note"] = "Some rootkits keep LSTAR pointing to KiSystemCall64 but patch the first few instructions (inline hook) to redirect before dispatch table lookup";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/msr/audit_mitigation_msrs", [](const s_http_request& req) {
        json result;
        // Read arch capabilities via CPUID leaf 7
        int cpuInfo[4] = {};
        __cpuidex(cpuInfo, 7, 0);
        result["ia32_arch_capabilities_flags"] = {
            {"RDCL_NO",    (cpuInfo[3]>>0)&1, "Immune to Meltdown (RDCL)"},
            {"IBRS_ALL",   (cpuInfo[3]>>1)&1, "IBRS protects all modes (not just kernel entry)"},
            {"RSBA",       (cpuInfo[3]>>2)&1, "RSB alternate: retpoline may be insufficient"},
            {"SKIP_L1DFL", (cpuInfo[3]>>3)&1, "L1D flush not needed on VMX entry/exit"},
            {"SSB_NO",     (cpuInfo[3]>>4)&1, "Not susceptible to Speculative Store Bypass"},
            {"MDS_NO",     (cpuInfo[3]>>5)&1, "Not susceptible to MDS (RIDL/Fallout/ZombieLoad)"},
            {"IF_PSCHANGE", (cpuInfo[3]>>6)&1,"Page-size change MSR TSX abort vulnerability"},
            {"TSX_CTRL",   (cpuInfo[3]>>7)&1, "TSX (HLE/RTM) can be disabled"},
            {"TAA_NO",     (cpuInfo[3]>>8)&1, "Not susceptible to TSX Async Abort"}
        };
        result["spec_ctrl_bits"] = {
            {"bit0","IBRS — Indirect Branch Restricted Speculation"},
            {"bit1","STIBP — Single Thread Indirect Branch Predictor isolation"},
            {"bit2","SSBD — Speculative Store Bypass Disable"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

