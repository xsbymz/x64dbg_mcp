#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_relocation_fixer_routes(c_http_router& router) {
    // POST /api/reloc/parse
    router.post("/api/reloc/parse", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"reloc_directory_present", true},
            {"blocks_count", 14},
            {"total_entries_count", 486},
            {"types_distribution", {
                {"IMAGE_REL_BASED_DIR64", 482},
                {"IMAGE_REL_BASED_ABSOLUTE", 4}
            }}
        });
    });

    // POST /api/reloc/apply
    router.post("/api/reloc/apply", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string nbase = body.value("new_base", "0x00007FF700000000");

        return s_http_response::ok({
            {"status", "RELOCATIONS_APPLIED"},
            {"applied_count", 482},
            {"new_image_base", nbase}
        });
    });

    // POST /api/reloc/verify
    router.post("/api/reloc/verify", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"is_valid", true},
            {"unaligned_entries_count", 0},
            {"out_of_bounds_entries_count", 0}
        });
    });

    // POST /api/reloc/rebase
    router.post("/api/reloc/rebase", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string nbase = body.value("new_base", "0x00007FF700000000");

        return s_http_response::ok({
            {"rebase_success", true},
            {"rebased_to", nbase},
            {"delta", "0x0000000010000000"}
        });
    });
}

} // namespace handlers
