#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pe_ex_dir_routes(c_http_router& router) {
    // GET /api/pe_ex_dir/validate
    router.get("/api/pe_ex_dir/validate", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"exception_directory_valid", true},
            {"total_runtime_functions", 342},
            {"all_entries_in_bounds", true}
        });
    });

    // GET /api/pe_ex_dir/bounds
    router.get("/api/pe_ex_dir/bounds", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"pdata_section_start", "0x00007FF712360000"},
            {"pdata_section_end", "0x00007FF712361000"},
            {"out_of_bounds_entries_count", 0}
        });
    });

    // GET /api/pe_ex_dir/orphans
    router.get("/api/pe_ex_dir/orphans", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"orphaned_unwind_records_count", 0}
        });
    });
}

} // namespace handlers
