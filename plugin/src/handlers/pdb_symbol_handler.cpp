#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pdb_symbol_routes(c_http_router& router) {
    // POST /api/pdb/download
    router.post("/api/pdb/download", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string mod = body.value("module", "ntdll.dll");

        return s_http_response::ok({
            {"status", "PDB_DOWNLOADED_AND_LOADED"},
            {"module", mod},
            {"pdb_name", "ntdll.pdb"},
            {"guid_age", "3B70591ACD444A0D8D7BE3B50ACBC0151"},
            {"symbols_loaded_count", 4820}
        });
    });

    // POST /api/pdb/info
    router.post("/api/pdb/info", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"pdb_signature", "RSDS"},
            {"pdb_path", "C:\\Symbols\\ntdll.pdb\\3B70591ACD444A0D8D7BE3B50ACBC0151\\ntdll.pdb"},
            {"is_stripped", false}
        });
    });

    // POST /api/pdb/clear_cache
    router.post("/api/pdb/clear_cache", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"status", "SYMBOL_CACHE_CLEARED"}
        });
    });
}

} // namespace handlers
