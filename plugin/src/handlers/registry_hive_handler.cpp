#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_registry_hive_routes(c_http_router& router) {
    router.post("/api/reg_hive/parse_hive_file", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string hivePath = body.value("hive_path", "C:\\Windows\\System32\\config\\SAM");
        json result;
        result["hive_path"] = hivePath;
        result["regf_header_structure"] = {
            {"Magic", "0x66676572 ('regf' — REGF Header Signature)"},
            {"Sequence1 / Sequence2", "Sync counters indicating clean vs dirty shutdown"},
            {"TimeStamp", "FILETIME of last hive modification"},
            {"MajorVersion / MinorVersion", "1 / 3, 1 / 5 (Format versions)"},
            {"RootKeyOffset", "Offset to root named key cell ('nk' record)"},
            {"HiveBinsDataSize", "Total size of hive bins data allocated in 4096-byte pages"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/reg_hive/extract_sam_hashes", [](const s_http_request& req) {
        json result;
        result["sam_extraction_algorithm"] = {
            "1. Read 'SYSTEM' hive -> parse ControlSet001\\Control\\Lsa\\JD, Skew1, GBG, Data keys -> compute SysKey (BootKey)",
            "2. Read 'SAM' hive -> parse SAM\\Domains\\Account\\Users\\[RID] 'F' and 'V' values",
            "3. Decrypt 'F' value using SysKey to obtain SAM Encryption Key (AES-128 / DES)",
            "4. Decrypt 'V' value NT/LM hash blobs using RID-derived hash key to obtain user NTLM hashes",
            "5. Bypasses live LSASS memory access entirely — works on locked / offline disk images"
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/reg_hive/read_lsa_secrets_offline", [](const s_http_request& req) {
        json result;
        result["lsa_secrets_targets"] = {
            {"$SECURITY\\Policy\\Secrets\\$MACHINE.ACC", "Active Directory domain machine account password"},
            {"$SECURITY\\Policy\\Secrets\\DPAPI_SYSTEM", "System-wide DPAPI master encryption key"},
            {"$SECURITY\\Policy\\Secrets\\_SC_ServiceName", "Service account plaintext passwords"}
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

