#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <wincrypt.h>
#pragma comment(lib, "crypt32.lib")
using json = nlohmann::json;

namespace handlers {
void register_authenticode_leaf_parser_routes(c_http_router& router) {
    router.post("/api/authenticode/parse_leaf_cert", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string filePath = body.value("file_path", "");
        json result;
        result["file_path"] = filePath;
        result["authenticode_structure"] = {
            {"PKCS#7_SignedData", "OID 1.2.840.113549.1.7.2 containing ContentInfo and signerInfos"},
            {"SpcIndirectDataContent", "OID 1.3.6.1.4.1.311.2.1.4 holding DigestAlgorithm and PE image hash"},
            {"SignerInfo", "IssuerAndSerialNumber, DigestAlgorithm (SHA256), EncryptedDigest"},
            {"RFC_3161_Timestamp", "OID 1.3.6.1.4.1.311.3.3.1 (Authenticode Timestamp) or OID 1.2.840.113549.1.9.16.1.4 (RFC 3161 TSTInfo)"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/authenticode/validate_timestamp_countersignature", [](const s_http_request& req) {
        json result;
        result["timestamp_validation_rules"] = {
            "1. Extract unauthenticatedAttributes from SignerInfo structure",
            "2. Locate counterSign (OID 1.2.840.113549.1.9.6) or id-aa-timeStampToken",
            "3. Verify TimeStamp Authority (TSA) certificate chain against trusted roots",
            "4. Verify signing time was before certificate expiration date for long-term validity"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

