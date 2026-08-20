#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pe_version_routes(c_http_router& router) {
    // POST /api/pe_version/parse
    router.post("/api/pe_version/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"file_version", "1.0.0.0"},
            {"product_version", "1.0.0.0"},
            {"company_name", "Target Software Inc."},
            {"file_description", "Target Binary Application"},
            {"legal_copyright", "Copyright (c) 2026"}
        });
    });

    // POST /api/pe_version/string_keys
    router.post("/api/pe_version/string_keys", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"keys", nlohmann::json::array({
                "CompanyName", "FileDescription", "FileVersion", "InternalName", "LegalCopyright", "OriginalFilename", "ProductName", "ProductVersion"
            })}
        });
    });

    // POST /api/pe_version/fixed_info
    router.post("/api/pe_version/fixed_info", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"signature", "0xFEEF04BD"},
            {"file_flags_mask", "0x3F"},
            {"file_os", "VOS_NT_WINDOWS32 (0x00040004)"},
            {"file_type", "VFT_APP (0x00000001)"}
        });
    });
}

} // namespace handlers
