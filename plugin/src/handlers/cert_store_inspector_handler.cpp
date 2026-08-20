#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_cert_store_inspector_routes(c_http_router& router) {
    router.post("/api/cert_store/enumerate_all_stores", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["system_certificate_stores"] = {
            {"MY", "Personal certificates (holds private keys for authentication/signing)"},
            {"ROOT", "Trusted Root Certification Authorities (Trust anchors for PKI validation)"},
            {"CA", "Intermediate Certification Authorities"},
            {"Trust", "Enterprise trust list"},
            {"Disallowed", "Untrusted certificates (Revocation blacklist)"}
        };
        result["registry_backing_locations"] = {
            "HKLM\\SOFTWARE\\Microsoft\\SystemCertificates",
            "HKCU\\SOFTWARE\\Microsoft\\SystemCertificates",
            "HKLM\\SOFTWARE\\Policies\\Microsoft\\SystemCertificates (GPO pushed roots)"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/cert_store/detect_rogue_root_cas", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["rogue_root_ca_threats"] = {
            "Adversaries inject self-signed root certificates into ROOT store to enable transparent TLS/HTTPS decryption (MITM)",
            "Malware install rogue CA to validate self-signed driver or executable signatures without SmartScreen warnings",
            "Detection: Compare SHA1/SHA256 thumbprints of all ROOT certificates against Microsoft Trusted Root Certificate Program catalog"
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/cert_store/validate_against_microsoft_trusted_list", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["authroot_stl_verification"] = "Verifies store entries against Microsoft authroot.stl (DisallowedCert.stl and AuthRoot.stl updated via Windows Update)";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
