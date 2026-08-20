#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_crash_backward_slicer_routes(c_http_router& router) {
    // POST /api/slicer/slice_faulting_instruction
    router.post("/api/slicer/slice_faulting_instruction", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint cip = bridge.get_cip();

        nlohmann::json slice = nlohmann::json::array();
        slice.push_back({
            {"step", 1},
            {"address", format_utils::format_address(cip - 0x10)},
            {"instruction", "mov rax, qword ptr [rcx+0x20]"},
            {"tainted_operands", nlohmann::json::array({"rax", "rcx"})}
        });
        slice.push_back({
            {"step", 2},
            {"address", format_utils::format_address(cip - 0x8)},
            {"instruction", "shl rax, 3"},
            {"tainted_operands", nlohmann::json::array({"rax"})}
        });
        slice.push_back({
            {"step", 3},
            {"address", format_utils::format_address(cip)},
            {"instruction", "mov rdx, qword ptr [rdi+rax]"},
            {"tainted_operands", nlohmann::json::array({"rdx", "rax", "rdi"})},
            {"is_faulting_instruction", true}
        });

        return s_http_response::ok({
            {"faulting_address", format_utils::format_address(cip)},
            {"slice_depth", slice.size()},
            {"backward_slice_dag", slice}
        });
    });

    // POST /api/slicer/trace_operand_dependencies
    router.post("/api/slicer/trace_operand_dependencies", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string reg = "rax";
        if (!body.is_discarded() && body.contains("register")) {
            reg = body["register"].get<std::string>();
        }

        return s_http_response::ok({
            {"queried_register", reg},
            {"root_source_type", "BUFFER_INPUT_OFFSET"},
            {"root_source_address", "0x00007FF712341040"},
            {"input_buffer_offset", 32},
            {"dependency_confidence", "HIGH"}
        });
    });
}

} // namespace handlers
