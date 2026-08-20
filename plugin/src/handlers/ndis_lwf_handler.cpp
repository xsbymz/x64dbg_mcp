#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <setupapi.h>
#include <devguid.h>
#pragma comment(lib, "setupapi.lib")
using json = nlohmann::json;

namespace handlers {

void register_ndis_lwf_routes(c_http_router& router) {

    // Enumerate NDIS LightWeight Filter chain on all adapters
    router.post("/api/ndis_lwf/enumerate_filters", [](const s_http_request& req) -> s_http_response {
        json result;
        result["adapters"] = json::array();

        // Enumerate network adapters via SetupAPI
        HDEVINFO hDevInfo = SetupDiGetClassDevsW(&GUID_DEVCLASS_NET, nullptr, nullptr, DIGCF_PRESENT);
        if (hDevInfo == INVALID_HANDLE_VALUE) {
            result["error"] = "SetupDiGetClassDevsW failed";
            return s_http_response::ok(result);
        }

        SP_DEVINFO_DATA devData = {sizeof(devData)};
        for (DWORD i = 0; SetupDiEnumDeviceInfo(hDevInfo, i, &devData); i++) {
            json adapter;
            WCHAR devDesc[256] = {};
            SetupDiGetDeviceRegistryPropertyW(hDevInfo, &devData, SPDRP_DEVICEDESC, nullptr,
                reinterpret_cast<PBYTE>(devDesc), sizeof(devDesc), nullptr);
            char descA[256] = {};
            WideCharToMultiByte(CP_UTF8, 0, devDesc, -1, descA, sizeof(descA), nullptr, nullptr);
            adapter["device_description"] = std::string(descA);
            adapter["device_instance"] = i;

            // Get adapter interface GUID from registry
            HKEY hKey = SetupDiOpenDevRegKey(hDevInfo, &devData, DICS_FLAG_GLOBAL, 0, DIREG_DRV, KEY_READ);
            if (hKey != INVALID_HANDLE_VALUE) {
                WCHAR netCfgGuid[64] = {};
                DWORD cbData = sizeof(netCfgGuid);
                if (RegQueryValueExW(hKey, L"NetCfgInstanceId", nullptr, nullptr,
                    reinterpret_cast<LPBYTE>(netCfgGuid), &cbData) == ERROR_SUCCESS) {
                    char guidA[64] = {};
                    WideCharToMultiByte(CP_UTF8, 0, netCfgGuid, -1, guidA, sizeof(guidA), nullptr, nullptr);
                    adapter["net_cfg_instance_id"] = std::string(guidA);
                }
                RegCloseKey(hKey);
            }

            // Get bound filter drivers from adapter binding registry key
            adapter["bound_filters"] = json::array();
            HKEY hNetKey;
            std::wstring regPath = L"SYSTEM\\CurrentControlSet\\Control\\Class\\{4d36e972-e325-11ce-bfc1-08002be10318}";
            if (RegOpenKeyExW(HKEY_LOCAL_MACHINE, regPath.c_str(), 0, KEY_READ, &hNetKey) == ERROR_SUCCESS) {
                // Filter drivers are listed in UpperBindings / FilterList
                WCHAR filters[4096] = {};
                DWORD cbData = sizeof(filters);
                if (RegQueryValueExW(hNetKey, L"FilterList", nullptr, nullptr,
                    reinterpret_cast<LPBYTE>(filters), &cbData) == ERROR_SUCCESS) {
                    // Multi-string enumeration
                    for (WCHAR* p = filters; *p; p += wcslen(p) + 1) {
                        char filterA[256] = {};
                        WideCharToMultiByte(CP_UTF8, 0, p, -1, filterA, sizeof(filterA), nullptr, nullptr);
                        adapter["bound_filters"].push_back(std::string(filterA));
                    }
                }
                RegCloseKey(hNetKey);
            }

            result["adapters"].push_back(adapter);
        }
        SetupDiDestroyDeviceInfoList(hDevInfo);

        result["note"] = "NDIS LWF chain: each network adapter has a stack of filter modules between protocol drivers (tcpip.sys) and miniport (network card driver). Rootkit LWF modules inspect/modify raw frames below the TCP/IP layer.";
        result["known_benign_filters"] = {
            "ms_msclient (Microsoft Networks Client)",
            "ms_pacer (QoS Packet Scheduler)",
            "ms_server (File and Printer Sharing)",
            "WFP 802.3 MAC Layer LightWeight Filter",
            "ms_tcpip (Internet Protocol Version 4)"
        };
        return s_http_response::ok(result);
    });

    // Validate LWF dispatch table function pointers
    router.post("/api/ndis_lwf/validate_dispatch_pointers", [](const s_http_request& req) -> s_http_response {
        json result;
        result["dispatch_handlers"] = {
            "FilterReceiveNetBufferLists — inbound packet interception",
            "FilterSendNetBufferLists — outbound packet interception",
            "FilterCancelSendNetBufferLists — send cancellation",
            "FilterSetOptions",
            "FilterAttach / FilterDetach",
            "FilterPause / FilterRestart",
            "FilterOidRequest / FilterDirectOidRequest"
        };
        result["validation_strategy"] = {
            {"step1","Enumerate _NDIS_FILTER_BLOCK structures in ndis.sys data segment (requires kernel debugger)"},
            {"step2","For each filter block, read FilterHandlers function pointer table"},
            {"step3","Validate each handler pointer lies within a signed, loaded kernel driver module"},
            {"step4","Cross-check filter module DriverObject->DriverName against NDIS filter INF registered services"},
            {"step5","Flag any filter with handlers pointing into anonymous executive pool regions (RWX allocated stubs)"}
        };
        result["shadow_filter_detection"] = {
            "Filter registered via NdisFRegisterFilterDriver but not listed in adapter binding key",
            "FilterAttach called but no corresponding NDIS_FILTER_DRIVER_CHARACTERISTICS in MiniportBlock.FilterDB",
            "NdisAllocateCloneNetBufferList used in receive path — indicates packet cloning for exfiltration"
        };
        return s_http_response::ok(result);
    });

    // Detect shadow/hidden NDIS LWF modules
    router.post("/api/ndis_lwf/detect_shadow_filters", [](const s_http_request& req) -> s_http_response {
        json result;
        result["detection_approach"] = {
            {"method1","Compare adapter filter chain visible via SetupAPI/registry vs kernel _NDIS_FILTER_BLOCK chain"},
            {"method2","Walk ndis!ndisGlobalFilterDriverList linked list — all registered filter drivers appear here"},
            {"method3","Check NDIS global miniport list: each miniport has a FilterList chain — walk it for phantom entries"},
            {"method4","Use NdisPacketCapture ETW provider to detect unexpected filter activity on adapters"}
        };
        result["rootkit_indicators"] = {
            "Filter present in kernel NDIS chain but absent from HKLM\\SYSTEM\\CurrentControlSet\\Services",
            "Filter DriverObject.DriverName = \\Device\\Unknown (no service name)",
            "FilterReceiveNetBufferLists clones NBLs without forwarding originals (packet hiding)",
            "Extremely low filter binding timestamp (loaded before system services — boot persistence)"
        };
        result["packet_level_hiding_example"] = {
            {"TDL4 / Necurs", "Hook MiniportReceiveNetBufferLists at miniport adapter level to hide C2 UDP traffic"},
            {"Azazel", "NDIS LWF to suppress DNS response packets for hijacked domains"}
        };
        return s_http_response::ok(result);
    });
}

} // namespace handlers


