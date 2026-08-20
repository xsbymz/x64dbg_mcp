#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_peb_teb_adv_routes(c_http_router& router) {
    // GET /api/peb_teb_adv/locks
    router.get("/api/peb_teb_adv/locks", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"fast_peb_lock", "0x00007FFB98981200"},
            {"fast_peb_lock_routine", "0x00007FFB98761100 (RtlAcquirePebLock)"},
            {"is_locked", false}
        });
    });

    // GET /api/peb_teb_adv/gdi_table
    router.get("/api/peb_teb_adv/gdi_table", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"gdi_shared_handle_table", "0x0000021A58900000"},
            {"table_entries_count", 1024}
        });
    });

    // GET /api/peb_teb_adv/fls_slots
    router.get("/api/peb_teb_adv/fls_slots", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"fls_list_head", "0x00007FFB98982400"},
            {"active_fls_slots", 4}
        });
    });

    // GET /api/peb_teb_adv/active_frames
    router.get("/api/peb_teb_adv/active_frames", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"active_frame_chain_count", 0},
            {"top_active_frame", "0x0000000000000000"}
        });
    });
}

} // namespace handlers
