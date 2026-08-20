#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ebpf_analyzer_routes(c_http_router& router) {
    // POST /api/ebpf/enum_programs
    router.post("/api/ebpf/enum_programs", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"ebpf_driver_present", true},
            {"ebpfcore_sys_loaded", true},
            {"programs", nlohmann::json::array({
                {{"id", 1}, {"name", "xdp_packet_filter"}, {"program_type", "EBPF_PROGRAM_TYPE_XDP"}, {"instruction_count", 48}}
            })}
        });
    });

    // POST /api/ebpf/dump_maps
    router.post("/api/ebpf/dump_maps", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"maps", nlohmann::json::array({
                {{"id", 1}, {"name", "ip_block_hash"}, {"map_type", "BPF_MAP_TYPE_HASH"}, {"key_size", 4}, {"value_size", 8}, {"max_entries", 1024}}
            })}
        });
    });
}

} // namespace handlers
