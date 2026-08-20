#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_dll_notification_routes(c_http_router& router) {
    router.post("/api/dll_notify/enumerate_callbacks", [](const s_http_request& req) {
        json result;
        // LdrpDllNotificationList is at ntdll!LdrpDllNotificationList
        // Structure: _LDR_DLL_NOTIFICATION_ENTRY { LIST_ENTRY Links; PLDR_DLL_NOTIFICATION_FUNCTION Callback; PVOID Context; }
        result["mechanism"] = {
            "LdrRegisterDllNotification(0, callback, ctx, &cookie) registers to LdrpDllNotificationList",
            "Called synchronously on DLL load (LDR_DLL_NOTIFICATION_REASON_LOADED=1) and unload (REASON_UNLOADED=2)",
            "Callback receives: BaseDllName, FullDllName, DllBase, SizeOfImage",
            "No privileges required — any code in process can register"
        };
        result["malware_use_cases"] = {
            "Turla: Monitors DLL loads to inject code into specific DLL without hooking LoadLibrary",
            "APT28: Waits for target DLL (e.g. cryptobase.dll) then patches its loaded image",
            "Credential stealers: Watch for wdigest.dll/lsasrv.dll load to find auth function offsets",
            "Persistence: On any DLL load, re-inject if previous injection was cleaned"
        };
        // Try to locate LdrpDllNotificationList
        HMODULE hNtdll = GetModuleHandleW(L"ntdll.dll");
        result["ntdll_base"] = (uintptr_t)hNtdll;
        // LdrRegisterDllNotification is exported
        FARPROC regFn = GetProcAddress(hNtdll,"LdrRegisterDllNotification");
        FARPROC unregFn = GetProcAddress(hNtdll,"LdrUnregisterDllNotification");
        result["LdrRegisterDllNotification_addr"] = (uintptr_t)regFn;
        result["LdrUnregisterDllNotification_addr"] = (uintptr_t)unregFn;
        result["enumeration_strategy"] = {
            "1. Find ntdll!LdrpDllNotificationList via pattern scan (look for LIST_ENTRY near LdrRegisterDllNotification code)",
            "2. Walk LIST_ENTRY chain: each entry is _LDR_DLL_NOTIFICATION_ENTRY",
            "3. Extract callback function pointer from each entry",
            "4. Validate callback against known benign modules (ntdll,kernelbase,apphelp)"
        };
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/dll_notify/validate_callback_pointers", [](const s_http_request& req) {
        json result;
        result["benign_callback_sources"] = {"ntdll.dll","kernelbase.dll","apphelp.dll","shcore.dll"};
        result["suspicious_indicators"] = {
            "Callback pointer in anonymous MEM_PRIVATE region (injected shellcode)",
            "Callback in DLL with no module list entry (phantom DLL)",
            "Multiple callbacks registered by same cookie address",
            "Callback registered after suspicious memory allocation event"
        };
        return s_http_response::ok(result.dump());;
    });
    router.post("/api/dll_notify/detect_malicious_registrations", [](const s_http_request& req) {
        json result;
        result["detection_signatures"] = {
            {"Turla_KDFLT","Registers callback targeting KDFLT::DllNotification — watch for cryptobase.dll"},
            {"APT28_XAgent","Callback watches for winhttp.dll to patch COM credential APIs"},
            {"Credential_stealer","Callback waits for wdigest.dll, patches g_WDigestCredentials list pointer"}
        };
        result["ioc_patterns"] = {
            "Callback in heap-allocated executable memory",
            "Callback immediately patches loaded DLL .text section",
            "Callback opens handle to LSASS process",
            "Callback reads HKCU registry keys on every DLL load"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

