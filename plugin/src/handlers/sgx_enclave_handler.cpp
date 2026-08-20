#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <intrin.h>
using json = nlohmann::json;

namespace handlers {
void register_sgx_enclave_routes(c_http_router& router) {
    router.post("/api/sgx/detect_enclaves", [](const s_http_request& req) {
        json result;
        int info[4]={};
        __cpuid(info,0); int maxLeaf=info[0];
        bool sgxSupported = false;
        if (maxLeaf>=7) {
            __cpuidex(info,7,0);
            sgxSupported = (info[1]>>2)&1;
        }
        result["sgx_supported"] = sgxSupported;
        if (sgxSupported && maxLeaf>=0x12) {
            __cpuidex(info,0x12,0);
            result["sgx_features"] = {
                {"SGX1",(info[0]>>0)&1},{"SGX2",(info[0]>>1)&1},
                {"ENCLV_EINCVIRTCHILD",(info[0]>>5)&1},
                {"EUPDATESVN",(info[0]>>6)&1},
                {"ENBR_ENCLU",(info[0]>>7)&1}
            };
            result["miscselect"] = info[1];
            __cpuidex(info,0x12,1);
            result["secs_attributes_mask_lo"] = info[0];
            result["secs_attributes_mask_hi"] = info[1];
        }
        result["sgx_epc_regions"] = json::array();
        if (sgxSupported && maxLeaf>=0x12) {
            for (int i=2; i<10; i++) {
                __cpuidex(info,0x12,i);
                int subtype = info[0]&0xF;
                if (subtype==0) break;
                if (subtype==1) {
                    json epc;
                    uint64_t base = ((uint64_t)(info[1]&0xFFFFF)<<32)|(info[0]&0xFFFFF000);
                    uint64_t size = ((uint64_t)(info[3]&0xFFFFF)<<32)|(info[2]&0xFFFFF000);
                    epc["base"] = base; epc["size"] = size;
                    epc["type"] = "Confidential";
                    result["sgx_epc_regions"].push_back(epc);
                }
            }
        }
        result["malware_relevance"] = {
            "SGX enclaves cannot be debugged, inspected, or dumped — even by kernel/hypervisor",
            "Malware can hide C2 keys, license checks, or anti-analysis code in enclave",
            "Cryptocurrency miners use SGX to protect algorithm from modification",
            "SGX side-channels (SGAxe, CacheOut) allow partial enclave memory recovery"
        };
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/sgx/read_epc_layout", [](const s_http_request& req) {
        json result;
        result["epc_structure"] = {
            {"EPC","Enclave Page Cache — physical memory reserved for SGX by firmware, encrypted by hardware"},
            {"SECS","SGX Enclave Control Structure — 4KB per enclave, holds metadata"},
            {"TCS","Thread Control Structure — per-thread entry point (EENTER instruction)"},
            {"REG","Regular enclave page — code and data"},
            {"VA","Version Array — 512 version slots for EBLOCK/ETRACK"}
        };
        result["debug_vs_production"] = {
            {"debug_enclave","SECS.ATTRIBUTES.DEBUG=1 — can be debugged with sgx-gdb, memory accessible"},
            {"production_enclave","SECS.ATTRIBUTES.DEBUG=0 — no debug access, hardware enforced"},
            {"detection","Check if target uses sgx_create_enclave(ENCLAVE_TYPE_SGX,flags) with debug=1 vs 0"}
        };
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/sgx/analyze_sigstruct", [](const s_http_request& req) {
        json result;
        result["sigstruct_fields"] = {
            {"HEADER","0x06000000E100000000000100H — constant magic bytes"},
            {"VENDOR","0=Intel, 1=non-Intel"},
            {"DATE","Build date YYYYMMDD"},
            {"HEADER2","0x01010000600000006000000001000000H"},
            {"SWDEFINED","Software-defined data (32 bytes)"},
            {"MODULUS","3072-bit RSA public key"},
            {"EXPONENT","RSA public exponent (3 or 65537)"},
            {"SIGNATURE","RSA signature over header+body"},
            {"MISCSELECT","Extended SSA features mask"},
            {"MISCMASK","Mask for MISCSELECT"},
            {"ATTRIBUTES","Enclave attributes: DEBUG, MODE64BIT, PROVISIONKEY, EINITTOKEN"},
            {"ATTRIBUTEMASK","Mask for ATTRIBUTES"},
            {"ENCLAVEHASH","256-bit SHA-256 measurement of enclave (MRENCLAVE)"},
            {"ISVPRODID","ISV product ID"},
            {"ISVSVN","ISV security version number — used for sealing key derivation"}
        };
        result["mrenclave_significance"] = "MRENCLAVE is the cryptographic identity of enclave code. Sealing uses MRENCLAVE or MRSIGNER to bind data to specific enclave version. Leaked sealed data reveals enclave identity.";
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

