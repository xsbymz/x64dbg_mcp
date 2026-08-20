#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <wbemidl.h>
#pragma comment(lib, "wbemuuid.lib")
using json = nlohmann::json;

namespace handlers {
void register_wmi_subscription_routes(c_http_router& router) {
    router.post("/api/wmi_sub/enumerate_subscriptions", [](const s_http_request& req) {
        json result;
        result["subscriptions"] = json::array();
        // Enumerate WMI subscriptions via WMI COM API
        IWbemLocator* pLoc = nullptr;
        IWbemServices* pSvc = nullptr;
        HRESULT hr = CoInitializeEx(nullptr, COINIT_MULTITHREADED);
        bool coinit = SUCCEEDED(hr);
        hr = CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(void**)&pLoc);
        if (SUCCEEDED(hr) && pLoc) {
            BSTR ns = SysAllocString(L"ROOT\\subscription");
            hr = pLoc->ConnectServer(ns,nullptr,nullptr,nullptr,0,nullptr,nullptr,&pSvc);
            SysFreeString(ns);
            if (SUCCEEDED(hr) && pSvc) {
                // Set security
                CoSetProxyBlanket(pSvc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,
                    RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE);
                // Query EventFilter
                IEnumWbemClassObject* pEnum = nullptr;
                BSTR lang = SysAllocString(L"WQL");
                BSTR query = SysAllocString(L"SELECT * FROM __EventFilter");
                hr = pSvc->ExecQuery(lang,query,WBEM_FLAG_FORWARD_ONLY,nullptr,&pEnum);
                SysFreeString(lang); SysFreeString(query);
                if (SUCCEEDED(hr) && pEnum) {
                    IWbemClassObject* pObj = nullptr; ULONG ret = 0;
                    while (pEnum->Next(WBEM_INFINITE,1,&pObj,&ret)==S_OK) {
                        json entry; entry["type"] = "__EventFilter";
                        VARIANT vName={},vQuery={};
                        if (SUCCEEDED(pObj->Get(L"Name",0,&vName,nullptr,nullptr)) && vName.vt==VT_BSTR) {
                            char a[256]={}; WideCharToMultiByte(CP_UTF8,0,vName.bstrVal,-1,a,sizeof(a),nullptr,nullptr);
                            entry["name"]=std::string(a);
                        }
                        if (SUCCEEDED(pObj->Get(L"Query",0,&vQuery,nullptr,nullptr)) && vQuery.vt==VT_BSTR) {
                            char a[1024]={}; WideCharToMultiByte(CP_UTF8,0,vQuery.bstrVal,-1,a,sizeof(a),nullptr,nullptr);
                            entry["query"]=std::string(a);
                        }
                        VariantClear(&vName); VariantClear(&vQuery);
                        result["subscriptions"].push_back(entry);
                        pObj->Release();
                    }
                    pEnum->Release();
                }
                pSvc->Release();
            }
            pLoc->Release();
        }
        if (coinit) CoUninitialize();
        result["count"] = result["subscriptions"].size();
        result["persistence_techniques"] = {
            "ActiveScriptEventConsumer: runs VBScript/JScript — fileless execution",
            "CommandLineEventConsumer: runs executable on trigger",
            "Common triggers: __InstanceModificationEvent on Win32_LocalTime, __InstanceCreationEvent on Win32_Process"
        };
        result["known_malware"] = {"APT32","APT33","FIN6","Emotet (WMI lateral movement)","Venom RAT (persistence)"};
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/wmi_sub/decode_active_script_consumers", [](const s_http_request& req) {
        json result;
        IWbemLocator* pLoc = nullptr; IWbemServices* pSvc = nullptr;
        HRESULT hr = CoInitializeEx(nullptr,COINIT_MULTITHREADED);
        bool ci = SUCCEEDED(hr);
        hr = CoCreateInstance(CLSID_WbemLocator,nullptr,CLSCTX_INPROC_SERVER,IID_IWbemLocator,(void**)&pLoc);
        result["active_script_consumers"] = json::array();
        if (SUCCEEDED(hr) && pLoc) {
            BSTR ns = SysAllocString(L"ROOT\\subscription");
            hr = pLoc->ConnectServer(ns,nullptr,nullptr,nullptr,0,nullptr,nullptr,&pSvc);
            SysFreeString(ns);
            if (SUCCEEDED(hr) && pSvc) {
                CoSetProxyBlanket(pSvc,RPC_C_AUTHN_WINNT,RPC_C_AUTHZ_NONE,nullptr,RPC_C_AUTHN_LEVEL_CALL,RPC_C_IMP_LEVEL_IMPERSONATE,nullptr,EOAC_NONE);
                IEnumWbemClassObject* pEnum = nullptr;
                BSTR lang = SysAllocString(L"WQL");
                BSTR q = SysAllocString(L"SELECT * FROM ActiveScriptEventConsumer");
                if (SUCCEEDED(pSvc->ExecQuery(lang,q,WBEM_FLAG_FORWARD_ONLY,nullptr,&pEnum)) && pEnum) {
                    IWbemClassObject* pObj=nullptr; ULONG ret=0;
                    while (pEnum->Next(WBEM_INFINITE,1,&pObj,&ret)==S_OK) {
                        json entry;
                        VARIANT v={};
                        if (SUCCEEDED(pObj->Get(L"ScriptText",0,&v,nullptr,nullptr)) && v.vt==VT_BSTR) {
                            char a[4096]={}; WideCharToMultiByte(CP_UTF8,0,v.bstrVal,-1,a,sizeof(a),nullptr,nullptr);
                            entry["script_text"]=std::string(a);
                            std::string s(a); std::transform(s.begin(),s.end(),s.begin(),::tolower);
                            entry["suspicious"] = (s.find("cmd")!=std::string::npos||s.find("powershell")!=std::string::npos||s.find("wscript")!=std::string::npos);
                        }
                        VariantClear(&v);
                        result["active_script_consumers"].push_back(entry);
                        pObj->Release();
                    }
                    pEnum->Release();
                }
                SysFreeString(lang); SysFreeString(q);
                pSvc->Release();
            }
            pLoc->Release();
        }
        if (ci) CoUninitialize();
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/wmi_sub/detect_suspicious_bindings", [](const s_http_request& req) {
        json result;
        result["binding_analysis"] = {
            "A complete WMI subscription requires three objects: __EventFilter + __EventConsumer + __FilterToConsumerBinding",
            "Bindings link a specific filter to a specific consumer",
            "Suspicious: consumer name uses random GUID-like string, filter uses __InstanceModificationEvent on Win32_LocalTime (periodic timer), script base64-encoded"
        };
        result["ioc_patterns"] = {
            "Consumer name: SCM Event Log Consumer, BVTFilter, KernCap, DiskCleanup",
            "Filter query: SELECT * FROM __InstanceModificationEvent WITHIN 60 WHERE TargetInstance ISA 'Win32_PerfFormattedData_PerfOS_System'",
            "Script text contains: FromBase64String, Invoke-Expression, [System.Convert], wscript.shell"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

