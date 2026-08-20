#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_powershell_scriptblock_routes(c_http_router& router) {
    router.post("/api/ps_scriptblock/extract_from_memory", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["scriptblock_caching_mechanism"] = {
            "PowerShell engine (System.Management.Automation.dll) caches compiled ScriptBlockAst and text representation in CLR managed heap",
            "ScriptBlock logging (EID 4104) is generated during compilation before AMSI buffer scan",
            "Even if AMSI is patched or ETW is disabled in memory, the ScriptBlock text remains extractable from process heap memory"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/ps_scriptblock/decode_obfuscated_blocks", [](const s_http_request& req) {
        json result;
        result["obfuscation_patterns"] = {
            {"String_Reverse", "[Array]::Reverse($arr); [String]::Join('', $arr)"},
            {"SecureString_Decode", "[Runtime.InteropServices.Marshal]::PtrToStringAuto(...) with BSTR allocation"},
            {"Type_Casting", "[Type]('[R'+'ef]'), [AppDomain]::CurrentDomain.DefineDynamicAssembly"},
            {"Backtick_Tick_Insertion", "I`n`v`o`k`e`-`E`x`p`r`e`s`s`i`o`n (iex)"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/ps_scriptblock/detect_amsi_bypass_patterns", [](const s_http_request& req) {
        json result;
        result["amsi_bypass_signatures"] = {
            {"AmsiScanBuffer_Patch", "Overwriting amsi.dll!AmsiScanBuffer prologue with 0xB8 0x57 0x00 0x07 0x80 0xC3 (MOV EAX, 0x80070057; RET)"},
            {"amsiInitFailed_Reflection", "[Ref].Assembly.GetType('System.Management.Automation.AmsiUtils').GetField('amsiInitFailed','NonPublic,Static').SetValue($null,$true)"},
            {"AmsiContext_Nulling", "Zeroing out amsiContext pointer in System.Management.Automation memory"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

