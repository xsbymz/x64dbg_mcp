#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_pdb_guid_mismatch_routes(c_http_router& router) {
    router.post("/api/pdb_guid/extract_debug_info", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string moduleName = body.value("module_name", "");
        json result;
        result["module_name"] = moduleName;
        result["cv_info_structure"] = {
            {"CvSignature", "0x53445352 ('RSDS' for CodeView PDB 7.0)"},
            {"Signature_GUID", "128-bit unique compilation UUID"},
            {"Age", "Incremental compilation generation counter (typically 1 for release builds)"},
            {"PdbFileName", "Absolute or relative build path to PDB symbol file"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/pdb_guid/compare_with_symbol_server", [](const s_http_request& req) {
        json result;
        result["symbol_server_comparison"] = {
            "1. Format Microsoft Symbol Server URL: https://msdl.microsoft.com/download/symbols/[pdbName]/[guid][age]/[pdbName]",
            "2. If binary claims to be a Windows system DLL (e.g. kernel32.dll, ntdll.dll), query symbol server",
            "3. If symbol server returns 404 Not Found for reported GUID -> binary was recompiled/trojanized",
            "4. If symbol server returns valid PDB matching original binary -> verify code hash against symbols"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/pdb_guid/check_known_malware_guids", [](const s_http_request& req) {
        json result;
        result["malware_pdb_indicators"] = {
            "PDB path containing usernames, offensive framework names, or malware builder artifacts (e.g. 'mimikatz', 'beacon', 'b4', 'c2')",
            "Reused GUID across distinct malware samples indicating shared builder / generator utility",
            "Fake symbol path imitating system binaries with misspelled directory names"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

