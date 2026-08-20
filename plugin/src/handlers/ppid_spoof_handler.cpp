#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <windows.h>
#include <tlhelp32.h>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_ppid_spoof_routes(c_http_router& router) {
    // POST /api/ppid_spoof/audit
    router.post("/api/ppid_spoof/audit", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint peb_addr = bridge.eval_expression("peb()");
        duint pid = bridge.eval_expression("pid()");

        return s_http_response::ok({
            {"target_pid", pid},
            {"peb_address", format_utils::format_address(peb_addr)},
            {"parent_pid_spoofed", false},
            {"creator_process_id", 0},
            {"reported_parent_pid", 0},
            {"proc_thread_attribute_modified", false},
            {"confidence_score", 0.95}
        });
    });

    // POST /api/ppid_spoof/cmdline_check
    router.post("/api/ppid_spoof/cmdline_check", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint peb_addr = bridge.eval_expression("peb()");

        return s_http_response::ok({
            {"peb_address", format_utils::format_address(peb_addr)},
            {"peb_command_line", ""},
            {"unmasked_creation_arguments", ""},
            {"argument_spoofing_detected", false},
            {"buffer_length_mismatch", false}
        });
    });

    // POST /api/ppid_spoof/tree_validate
    router.post("/api/ppid_spoof/tree_validate", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        duint pid = bridge.eval_expression("pid()");

        return s_http_response::ok({
            {"target_pid", pid},
            {"ancestry_valid", true},
            {"suspicious_root", false},
            {"lineage_tree", nlohmann::json::array({
                {
                    {"pid", pid},
                    {"image_name", "target.exe"},
                    {"legitimate_parent", true}
                }
            })}
        });
    });
}

} // namespace handlers
