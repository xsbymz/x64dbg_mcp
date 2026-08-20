#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_lolbin_argument_routes(c_http_router& router) {
    router.post("/api/lolbin/extract_command_line", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        DWORD targetPid = body.value("pid", (DWORD)GetCurrentProcessId());
        json result;
        result["pid"] = targetPid;
        result["command_line_sources"] = {
            {"PEB_ProcessParameters", "PEB->ProcessParameters->CommandLine (UNICODE_STRING)"},
            {"NtQueryInformationProcess", "ProcessCommandLineInformation (Class 60) query"},
            {"WMI_Win32_Process", "CommandLine property via WMI / CIM repository"},
            {"ETW_Process_Start", "Microsoft-Windows-Kernel-Process event ID 1"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/lolbin/detect_known_patterns", [](const s_http_request& req) {
        json result;
        result["lolbin_threat_matrix"] = {
            {"mshta.exe", "mshta.exe vbscript:Close(Execute(\"...\")) or remote HTA execution"},
            {"rundll32.exe", "rundll32.exe javascript:\"\\..\\mshtml,RunHTMLApplication \" or ordinal execution"},
            {"certutil.exe", "certutil.exe -urlcache -split -f [url] [out] or -decode / -encode payload staging"},
            {"bitsadmin.exe", "bitsadmin.exe /transfer myjob /download /priority high [url] [dest]"},
            {"regsvr32.exe", "regsvr32.exe /s /n /u /i:http://... scrobj.dll (Squiblydoo)"},
            {"wmic.exe", "wmic.exe process call create [cmd] / os get /format:[xsl_url]"},
            {"powershell.exe", "powershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc [Base64]"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/lolbin/decode_encoded_arguments", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string commandLine = body.value("command_line", "");
        json result;
        result["command_line"] = commandLine;
        result["decoding_pipeline"] = {
            "1. Strip PowerShell / Command-line obfuscation: carets (^), quotes (\"\", ''), environment variable expansions (%COMSPEC%)",
            "2. Identify and decode Base64 / Unicode UTF-16LE encoded strings (-e / -enc / -encodedcommand)",
            "3. Decompress GZIP / Deflate compressed script blocks",
            "4. Resolve hex-encoded command arguments (/hex / 0x arrays)"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

