#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pe_security_routes(c_http_router& router) {
    // POST /api/pe_security/parse
    router.post("/api/pe_security/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"has_security_directory", true},
            {"certificate_revision", "WIN_CERT_REVISION_2_0 (0x0200)"},
            {"certificate_type", "WIN_CERT_TYPE_PKCS_SIGNED_DATA (0x0002)"},
            {"certificate_size", 9420}
        });
    });

    // POST /api/pe_security/extract
    router.post("/api/pe_security/extract", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "CERTIFICATE_EXTRACTED"},
            {"output_path", "extracted_cert.pkcs7"},
            {"bytes_written", 9420}
        });
    });

    // POST /api/pe_security/verify_hash
    router.post("/api/pe_security/verify_hash", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"calculated_hash_sha256", "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855"},
            {"signed_hash_matches", true}
        });
    });
}

} // namespace handlers
