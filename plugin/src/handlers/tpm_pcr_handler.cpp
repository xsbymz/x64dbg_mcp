#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <tbs.h>
#pragma comment(lib, "tbs.lib")
using json = nlohmann::json;

namespace handlers {
void register_tpm_pcr_routes(c_http_router& router) {

    router.post("/api/tpm/read_pcr_banks", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body=json::object(); }
        json result;
        result["pcr_reference"] = {
            {"PCR0","Core Root of Trust — CRTM/BIOS firmware"},
            {"PCR1","BIOS configuration and data"},
            {"PCR2","UEFI driver/application code"},
            {"PCR3","UEFI driver/application configuration"},
            {"PCR4","IPL (Initial Program Loader) — Windows Boot Manager bootmgfw.efi"},
            {"PCR5","IPL configuration"},
            {"PCR6","State transition events"},
            {"PCR7","Secure Boot policy — KEK/db/dbx measurements"},
            {"PCR8-15","OS-controlled measurements"},
            {"PCR16","Debug PCR (resettable)"},
            {"PCR23","Application-specific"}
        };
        result["bitlocker_sealing"] = {
            {"default_pcrs","PCR0+PCR2+PCR4+PCR7+PCR11"},
            {"pcr7_importance","Contains Secure Boot policy hash — changing SecureBoot/KEK/db breaks unsealing"},
            {"evil_maid_attack","Physical attacker modifies boot chain -> PCR values change -> BitLocker prompts recovery key"},
            {"pcr_prediction","Pre-compute expected PCR values to predict VMK sealing conditions"}
        };
        // Open TPM context
        TBS_HCONTEXT hCtx = 0;
        TBS_CONTEXT_PARAMS2 params = {};
        params.version = TBS_CONTEXT_VERSION_TWO;
        HRESULT hr = Tbsi_Context_Create((PCTBS_CONTEXT_PARAMS)&params, &hCtx);
        result["tpm_context_opened"] = SUCCEEDED(hr);
        result["tpm_hr"] = (int)hr;
        if (SUCCEEDED(hr)) {
            Tbsip_Context_Close(hCtx);
        }
        result["read_pcr_strategy"] = "Send TPM2_CC_PCR_Read command via Tbsip_Submit_Command to read PCR bank values";
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/tpm/get_ek_certificate", [](const s_http_request& req) {
        json result;
        result["ek_certificate"] = {
            {"location","NVRAM index 0x01C00002 (RSA-2048 EK cert) or 0x01C00014 (ECC-256)"},
            {"purpose","Endorsement Key certifies TPM authenticity — used in attestation"},
            {"manufacturer","EK cert signed by TPM manufacturer (Infineon, STMicroelectronics, Nuvoton)"},
            {"privacy_note","EK is a long-term identifier — can be used to track device"}
        };
        result["tpm2_command"] = {
            {"command","TPM2_CC_NV_READ (0x014E)"},
            {"index","0x01C00002"},
            {"usage","Read EK certificate blob from TPM NVRAM"}
        };
        // Try reading EK cert from Windows certificate store
        HCERTSTORE hStore = CertOpenSystemStoreA(0, "MY");
        result["cert_store_opened"] = (hStore != nullptr);
        if (hStore) { CertCloseStore(hStore,0); }
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/tpm/analyze_measurement_log", [](const s_http_request& req) {
        json result;
        result["measurement_log"] = {
            {"location","C:\\Windows\\Logs\\MeasuredBoot\\ (Windows TCG log)"},
            {"format","TCG EFI Platform Specification log (binary, event types)"},
            {"event_types",{
                {"EV_PREBOOT_CERT",0},{"EV_POST_CODE",1},{"EV_NO_ACTION",3},
                {"EV_SEPARATOR",4},{"EV_ACTION",5},{"EV_EVENT_TAG",6},
                {"EV_S_CRTM_CONTENTS",7},{"EV_S_CRTM_VERSION",8},{"EV_CPU_MICROCODE",9},
                {"EV_PLATFORM_CONFIG_FLAGS",10},{"EV_EFI_VARIABLE_DRIVER_CONFIG",0x80000001},
                {"EV_EFI_BOOT_SERVICES_APPLICATION",0x80000003},
                {"EV_EFI_GPT_EVENT",0x80000006}
            }}
        };
        // Enumerate measured boot log files
        result["log_files"] = json::array();
        WIN32_FIND_DATAW fd = {};
        HANDLE h = FindFirstFileW(L"C:\\Windows\\Logs\\MeasuredBoot\\*.log", &fd);
        if (h != INVALID_HANDLE_VALUE) {
            do {
                char nameA[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8,0,fd.cFileName,-1,nameA,sizeof(nameA),nullptr,nullptr);
                json entry; entry["file"] = std::string(nameA);
                entry["size"] = (DWORD)fd.nFileSizeLow;
                result["log_files"].push_back(entry);
            } while (FindNextFileW(h,&fd));
            FindClose(h);
        }
        result["log_count"] = result["log_files"].size();
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

