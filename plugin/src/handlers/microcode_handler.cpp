#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <intrin.h>
using json = nlohmann::json;

namespace handlers {
void register_microcode_handler_routes(c_http_router& router) {
    router.post("/api/microcode/read_version", [](const s_http_request& req) {
        json result;
        // Force microcode version latch with CPUID(0)
        int info[4]={};
        __cpuid(info,0);
        __cpuid(info,1);
        result["cpuid_model_info"] = info[0];
        result["extended_family"] = (info[0]>>20)&0xFF;
        result["extended_model"]  = (info[0]>>16)&0xF;
        result["processor_type"]  = (info[0]>>12)&0x3;
        result["family_id"]       = (info[0]>>8)&0xF;
        result["model_id"]        = (info[0]>>4)&0xF;
        result["stepping_id"]     = info[0]&0xF;
        result["note"] = "Microcode version is in IA32_BIOS_SIGN_ID MSR (0x8B, high 32 bits) after CPUID(1). Requires RDMSR in ring-0. CPUID(1) forces CPU to latch current microcode revision into MSR 0x8B.";
        result["microcode_msr"] = "0x8B (IA32_BIOS_SIGN_ID) — bits[63:32] = microcode update revision";
        result["intel_microcode_db"] = "https://github.com/intel/Intel-Linux-Processor-Microcode-Data-Files — maps CPUID signature+platform to latest microcode version";
        // Check CPUID vendor
        char vendor[13]={};
        memcpy(vendor,&info[1],4); memcpy(vendor+4,&info[3],4); memcpy(vendor+8,&info[2],4);
        result["cpu_vendor"] = std::string(vendor);
        result["is_intel"] = (std::string(vendor) == "GenuineIntel");
        result["is_amd"]   = (std::string(vendor) == "AuthenticAMD");
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/microcode/check_patch_level", [](const s_http_request& req) {
        json result;
        result["known_critical_patches"] = {
            {"Spectre_V1","CVE-2017-5753 — microcode: no direct fix, software mitigations needed"},
            {"Spectre_V2","CVE-2017-5715 — microcode adds IBRS/IBPB support (Intel microcode >=0x80 for Skylake)"},
            {"Meltdown","CVE-2017-5754 — OS-level KPTI, no microcode fix"},
            {"MDS","CVE-2018-12126/30/31 CVE-2019-11091 — microcode MD_CLEAR (VERW) required"},
            {"TAA","CVE-2019-11135 — TSX Async Abort, microcode TSX_CTRL support"},
            {"SRBDS","CVE-2020-0543 — Special Register Buffer Data Sampling — microcode needed"},
            {"MMIO_Stale_Data","CVE-2022-21123/24/25/26 — microcode required for mitigation"}
        };
        result["assessment_method"] = "Compare CPUID family/model/stepping against Intel microcode catalog; check IA32_ARCH_CAPABILITIES bits for hardware fixes";
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/microcode/assess_vulnerability_exposure", [](const s_http_request& req) {
        json result;
        int info[4]={};
        __cpuidex(info,7,0);
        result["hardware_vuln_summary"] = {
            {"mds_no",          ((info[3]>>5)&1)==1 ? "immune" : "VULNERABLE — MDS side-channel possible"},
            {"taa_no",          false},
            {"rdcl_no",         false},
            {"ssb_no",          ((info[3]>>4)&1)==1 ? "immune" : "may be vulnerable to SSB"},
            {"ibrs_all",        ((info[3]>>26)&1)==1 ? "IBRS works in all modes" : "IBRS only on kernel entry"}
        };
        result["exploit_relevance"] = "Unpatched CPUs allow cross-process/cross-VM secret leakage. In cloud environments: leak host secrets from co-resident VMs. In malware context: bypass ASLR by leaking kernel addresses via speculative execution.";
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

