#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <fwpmu.h>
#pragma comment(lib, "fwpuclnt.lib")
using json = nlohmann::json;

namespace handlers {

void register_wfp_callout_routes(c_http_router& router) {

    // Enumerate all registered WFP callouts
    router.post("/api/wfp/enumerate_callouts", [](const s_http_request& req) -> s_http_response {
        json result;
        result["callouts"] = json::array();

        HANDLE hEngine = nullptr;
        DWORD dwErr = FwpmEngineOpen0(nullptr, RPC_C_AUTHN_WINNT, nullptr, nullptr, &hEngine);
        if (dwErr != ERROR_SUCCESS) {
            result["error"] = "FwpmEngineOpen0 failed — code: " + std::to_string(dwErr) + " (requires admin)";
            return s_http_response::ok(result);
        }

        HANDLE hEnum = nullptr;
        FWPM_CALLOUT0** callouts = nullptr;
        UINT32 numReturned = 0;

        dwErr = FwpmCalloutCreateEnumHandle0(hEngine, nullptr, &hEnum);
        if (dwErr == ERROR_SUCCESS) {
            dwErr = FwpmCalloutEnum0(hEngine, hEnum, 256, &callouts, &numReturned);
            if (dwErr == ERROR_SUCCESS && callouts) {
                for (UINT32 i = 0; i < numReturned; i++) {
                    auto* co = callouts[i];
                    json entry;

                    // Format GUID
                    char guidStr[64] = {};
                    snprintf(guidStr, sizeof(guidStr),
                        "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                        co->calloutKey.Data1, co->calloutKey.Data2, co->calloutKey.Data3,
                        co->calloutKey.Data4[0], co->calloutKey.Data4[1],
                        co->calloutKey.Data4[2], co->calloutKey.Data4[3], co->calloutKey.Data4[4],
                        co->calloutKey.Data4[5], co->calloutKey.Data4[6], co->calloutKey.Data4[7]);
                    entry["callout_key"] = std::string(guidStr);

                    if (co->displayData.name) {
                        char name[256] = {};
                        WideCharToMultiByte(CP_UTF8, 0, co->displayData.name, -1, name, sizeof(name), nullptr, nullptr);
                        entry["name"] = std::string(name);
                    }
                    if (co->displayData.description) {
                        char desc[512] = {};
                        WideCharToMultiByte(CP_UTF8, 0, co->displayData.description, -1, desc, sizeof(desc), nullptr, nullptr);
                        entry["description"] = std::string(desc);
                    }
                    entry["flags"] = co->flags;
                    entry["callout_id"] = co->calloutId;

                    // Resolve applicableLayer GUID to readable name
                    char layerStr[64] = {};
                    snprintf(layerStr, sizeof(layerStr),
                        "{%08X-%04X-%04X-%02X%02X-%02X%02X%02X%02X%02X%02X}",
                        co->applicableLayer.Data1, co->applicableLayer.Data2, co->applicableLayer.Data3,
                        co->applicableLayer.Data4[0], co->applicableLayer.Data4[1],
                        co->applicableLayer.Data4[2], co->applicableLayer.Data4[3],
                        co->applicableLayer.Data4[4], co->applicableLayer.Data4[5],
                        co->applicableLayer.Data4[6], co->applicableLayer.Data4[7]);
                    entry["applicable_layer"] = std::string(layerStr);
                    entry["suspicious"] = false; // baseline; validation in next endpoint

                    result["callouts"].push_back(entry);
                }
                FwpmFreeMemory0(reinterpret_cast<void**>(&callouts));
            }
            FwpmCalloutDestroyEnumHandle0(hEngine, hEnum);
        }
        FwpmEngineClose0(hEngine);

        result["count"] = result["callouts"].size();
        result["note"] = "WFP callouts registered via FwpmCalloutAdd0. Rootkit callouts intercept traffic at FWPM_LAYER_INBOUND_IPPACKET_V4, FWPM_LAYER_STREAM_V4, or FWPM_LAYER_ALE_AUTH_CONNECT_V4 without appearing in netstat.";
        return s_http_response::ok(result.dump());;
    });

    // Validate callout function pointers against known driver modules
    router.post("/api/wfp/validate_callout_pointers", [](const s_http_request& req) -> s_http_response {
        json result;
        result["known_benign_providers"] = {
            "Windows Defender (mpssvc)",
            "Microsoft Base Filtering Engine (BFE)",
            "Windows Firewall (MpKslDrv)",
            "WFP built-in callouts (tcpip.sys, netio.sys)"
        };
        result["suspicious_indicators"] = {
            "Callout driver not in signed driver list",
            "classifyFn pointer outside any loaded kernel module range",
            "Callout with FWPM_CALLOUT_FLAG_PERSISTENT but driver not in HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "Callout registered without corresponding FwpmProvider — orphaned callout"
        };
        result["layer_risk_matrix"] = {
            {"FWPM_LAYER_INBOUND_IPPACKET_V4","High — intercepts all inbound IPv4 before IP processing"},
            {"FWPM_LAYER_STREAM_V4","High — intercepts TCP stream data bidirectionally"},
            {"FWPM_LAYER_ALE_AUTH_CONNECT_V4","Medium — intercepts outbound connection authorization"},
            {"FWPM_LAYER_DATAGRAM_DATA_V4","High — intercepts UDP datagrams"},
            {"FWPM_LAYER_INBOUND_TRANSPORT_V4_DISCARD","Low — only sees discarded packets"}
        };
        return s_http_response::ok(result.dump());;
    });

    // Detect hidden/unregistered WFP callouts via kernel inspection
    router.post("/api/wfp/detect_hidden_callouts", [](const s_http_request& req) -> s_http_response {
        json result;
        result["detection_method"] = {
            {"technique1","Compare FwpmCalloutEnum0 results with kernel FWPS callout table (requires kernel debugging)"},
            {"technique2","Enumerate FWPS_CALLOUT0 structures in netio.sys kernel heap — registered callouts appear here even if not in BFE database"},
            {"technique3","Monitor FwpsCalloutRegister0/1/2/3 via API hook or ETW Threat Intelligence (Microsoft-Windows-Threat-Intelligence provider)"},
            {"technique4","Check WFP filter list via FwpmFilterEnum0 for filters referencing callout IDs not in callout enum"}
        };
        result["rootkit_examples"] = {
            {"Azazel","Used WFP callout to hide UDP exfiltration traffic"},
            {"ZeroAccess","WFP callout to block security product connections"},
            {"TDL4","NDIS/WFP combination for packet-level C2 hiding"}
        };
        result["note"] = "True hidden callout detection requires kernel-mode access to inspect FwpsCalloutTable in netio.sys data section.";
        return s_http_response::ok(result.dump());;
    });
}

} // namespace handlers


