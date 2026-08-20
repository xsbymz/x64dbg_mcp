#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <intrin.h>
using json = nlohmann::json;

namespace handlers {
void register_cpu_vuln_routes(c_http_router& router) {
    router.post("/api/cpu_vuln/read_cpuid_vulnerability_leaves", [](const httplib::Request&, httplib::Response& res) {
        json result;
        int info[4] = {};
        __cpuid(info,0); result["max_leaf"] = info[0];
        __cpuid(info,1);
        result["family"] = (info[0]>>8)&0xF; result["model"] = (info[0]>>4)&0xF;
        result["stepping"] = info[0]&0xF;
        char brand[49]={}; int b[4]={};
        __cpuid(b,0x80000002); memcpy(brand,b,16);
        __cpuid(b,0x80000003); memcpy(brand+16,b,16);
        __cpuid(b,0x80000004); memcpy(brand+32,b,16);
        result["brand_string"] = std::string(brand);
        __cpuidex(info,7,0);
        result["leaf7_edx"] = {
            {"IBRS_IBPB",(info[3]>>26)&1},{"STIBP",(info[3]>>27)&1},
            {"L1D_FLUSH",(info[3]>>28)&1},{"ARCH_CAPS",(info[3]>>29)&1},
            {"CORE_CAPS",(info[3]>>30)&1},{"SSBD",(info[3]>>31)&1}
        };
        result["vulnerabilities"] = {
            {"Spectre_V1","Bounds check bypass — mitigated by compiler barriers (lfence), not hardware"},
            {"Spectre_V2","Branch target injection — mitigated by IBRS/IBPB/retpoline"},
            {"Spectre_V3","Meltdown — mitigated by KPTI (Kernel Page Table Isolation)"},
            {"MDS","Microarchitectural Data Sampling (RIDL/Fallout/ZombieLoad) — mitigated by MDS_NO or MD_CLEAR"},
            {"TAA","TSX Async Abort — mitigated by TAA_NO or TSX_CTRL"},
            {"SRBDS","Special Register Buffer Data Sampling — CPU RNG data leak across cores"}
        };
        res.set_content(result.dump(), "application/json");
    });
    router.post("/api/cpu_vuln/check_arch_capabilities_msr", [](const httplib::Request&, httplib::Response& res) {
        json result;
        int info[4]={};
        __cpuidex(info,7,0);
        bool hasArchCaps = (info[3]>>29)&1;
        result["arch_capabilities_msr_available"] = hasArchCaps;
        result["msr_index"] = "0x10A (IA32_ARCH_CAPABILITIES)";
        result["flags_map"] = {
            {"bit0","RDCL_NO — not susceptible to Meltdown"},
            {"bit1","IBRS_ALL — IBRS active in all modes"},
            {"bit2","RSBA — Retpoline may not be sufficient (RSB underflow)"},
            {"bit3","SKIP_L1DFL — L1D flush not needed on VM entry"},
            {"bit4","SSB_NO — Speculative Store Bypass immune"},
            {"bit5","MDS_NO — MDS immune (RIDL/Fallout/ZombieLoad)"},
            {"bit8","TAA_NO — TSX Async Abort immune"},
            {"bit10","MISC_PACKAGE_CTLS — package-level MSR controls available"},
            {"bit31","PBRSB_NO — PBS Return Stack Buffer immune"}
        };
        result["note"] = "Requires RDMSR 0x10A in kernel mode. Use x64dbg kernel debug context or driver.";
        res.set_content(result.dump(), "application/json");
    });
    router.post("/api/cpu_vuln/assess_exploit_mitigations", [](const httplib::Request&, httplib::Response& res) {
        json result;
        int info[4]={};
        __cpuidex(info,7,0);
        result["mitigation_assessment"] = {
            {"IBRS_available",((info[3]>>26)&1)==1},
            {"STIBP_available",((info[3]>>27)&1)==1},
            {"SSBD_available",((info[3]>>31)&1)==1},
            {"L1D_FLUSH_available",((info[3]>>28)&1)==1}
        };
        result["exploit_surface"] = {
            {"Spectre_V1","User-space PoC: bounds-bypass using array[untrusted_offset] pattern; mitigations: lfence, ArrayIndexMaskingBarrier"},
            {"Spectre_V2","JIT engine exploitation via indirect branch misprediction; mitigated by retpoline or IBRS"},
            {"MDS","Cross-SMT thread data leakage via CPU ports (MDS_NO=0 means vulnerable)"},
            {"Rowhammer","DRAM bit-flip attacks possible on non-ECC memory — LPDDR4 most vulnerable"}
        };
        // KPTI check via NtQuerySystemInformation
        typedef NTSTATUS(NTAPI* pNtQSI)(ULONG,PVOID,ULONG,PULONG);
        auto NtQSI = (pNtQSI)GetProcAddress(GetModuleHandleW(L"ntdll.dll"),"NtQuerySystemInformation");
        if (NtQSI) {
            BYTE buf[16]={};
            ULONG ret=0;
            // SystemKernelVaShadowInformation = 196
            NTSTATUS st = NtQSI(196, buf, sizeof(buf), &ret);
            result["kpti_query_status"] = (int)st;
            if (NT_SUCCESS(st) && ret>=4) result["kpti_flags"] = *(DWORD*)buf;
        }
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
