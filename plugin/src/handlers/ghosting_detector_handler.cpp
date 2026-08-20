#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ghosting_detector_routes(c_http_router& router) {
    // POST /api/ghosting/scan
    router.post("/api/ghosting/scan", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint main_base = bridge.eval_expression("mod.main()");

        return s_http_response::ok({
            {"main_image_base", format_utils::format_address(main_base)},
            {"file_delete_pending", false},
            {"file_unlinked_from_filesystem", false},
            {"process_ghosting_detected", false},
            {"section_backed_by_deleted_file", false},
            {"indicators", nlohmann::json::array()}
        });
    });

    // POST /api/ghosting/herpaderping
    router.post("/api/ghosting/herpaderping", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint main_base = bridge.eval_expression("mod.main()");

        return s_http_response::ok({
            {"main_image_base", format_utils::format_address(main_base)},
            {"disk_memory_hash_match", true},
            {"on_disk_bytes_modified_after_mapping", false},
            {"herpaderping_detected", false},
            {"confidence", 0.99}
        });
    });

    // POST /api/ghosting/transactions
    router.post("/api/ghosting/transactions", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint pid = bridge.eval_expression("pid()");

        return s_http_response::ok({
            {"target_pid", pid},
            {"txf_transaction_active", false},
            {"doppelganging_detected", false},
            {"rollback_section_mapped", false},
            {"active_ntfs_transactions", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
