#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_code_sig_validator_routes(c_http_router& router) {
    router.post("/api/code_sig/rehash_memory_sections", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string moduleName = body.value("module_name", "ntdll.dll");
        json result;
        result["module_name"] = moduleName;
        result["validation_workflow"] = {
            "1. Read mapped module PE headers in target process",
            "2. Extract Section Header for .text and executable code sections",
            "3. Calculate in-memory SHA256 digest of code sections",
            "4. Account for relocation table fixups and legitimate page patches",
            "5. Compare against Authenticode signed catalog / embedded PKCS#7 signature"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/code_sig/compare_against_authenticode", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["authenticode_structure"] = {
            {"Security_Directory", "IMAGE_DIRECTORY_ENTRY_SECURITY in OptionalHeader"},
            {"WIN_CERTIFICATE", "Length, Revision (0x0200 = WIN_CERT_REVISION_2_0), CertificateType (WIN_CERT_TYPE_PKCS_SIGNED_DATA)"},
            {"Digest_Algorithm", "SHA-256 (modern) or SHA-1 (legacy)"},
            {"Signer_Chain", "Leaf certificate -> Intermediate CA -> Microsoft Trusted Root Certificate Authority"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/code_sig/detect_signed_binary_tampering", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["tampering_indicators"] = {
            "In-memory hash divergence from on-disk Authenticode signed digest",
            "PAGE_EXECUTE_READWRITE permissions on sections signed as read-only code",
            "Inline hooks, detour trampolines, or injected shellcode placed in padding/caves of signed binary"
        };
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
