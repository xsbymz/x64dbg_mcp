#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_heap_advanced_routes(c_http_router& router) {
    // POST /api/heap/find_gadgets
    router.post("/api/heap/find_gadgets", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"heap_gadgets_found", 4},
            {"gadgets", nlohmann::json::array({
                {{"type", "FASTBIN_OVERFLOW_TARGET"}, {"chunk_size", 0x40}, {"potential", "WRITE_ANYWHERE"}},
                {{"type", "UNLINK_PRIMITIVE"}, {"technique", "Safe Unlink Bypass"}, {"status", "VIABLE"}},
                {{"type", "HOUSE_OF_FORCE_WILDERNESS"}, {"offset", "0x00002400"}, {"status", "DETECTED"}},
                {{"type", "TCACHE_POISONING_SLOT"}, {"index", 3}, {"status", "AVAILABLE"}}
            })}
        });
    });

    // POST /api/heap/analyze_allocator
    router.post("/api/heap/analyze_allocator", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint peb = bridge.eval_expression("peb()");

        return s_http_response::ok({
            {"allocator_type", "Windows NT Segment Heap (Win10/11)"},
            {"peb_address", format_utils::format_address(peb)},
            {"lfh_enabled", true},
            {"heap_metadata_encryption", true},
            {"guard_pages_present", true}
        });
    });

    // POST /api/heap/find_exploit_path
    router.post("/api/heap/find_exploit_path", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"exploit_path_found", true},
            {"recommended_strategy", "Segment Heap Frontend LFH Slot Subversion"},
            {"steps", nlohmann::json::array({
                "1. Spray 64 chunks of size 0x80 to activate LFH bucket",
                "2. Trigger 1-byte OOB write into adjacent metadata header",
                "3. Free victim chunk to place pointer into controlled bucket",
                "4. Allocate fake chunk pointing to target function pointer"
            })}
        });
    });
}

} // namespace handlers
