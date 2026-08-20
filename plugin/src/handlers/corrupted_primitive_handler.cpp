#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_corrupted_primitive_routes(c_http_router& router) {
    // POST /api/primitives/vector_oob
    router.post("/api/primitives/vector_oob", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint vector_addr = bridge.get_cip();
        duint target_addr = bridge.get_cip() + 0x1000;

        if (!body.is_discarded()) {
            if (body.contains("vector_address")) vector_addr = bridge.eval_expression(body["vector_address"].get<std::string>());
            if (body.contains("target_address")) target_addr = bridge.eval_expression(body["target_address"].get<std::string>());
        }

        int64_t element_index = static_cast<int64_t>(target_addr - vector_addr) / 8;

        return s_http_response::ok({
            {"vector_address", format_utils::format_address(vector_addr)},
            {"target_read_address", format_utils::format_address(target_addr)},
            {"calculated_index_offset", element_index},
            {"primitive_type", "OOB_VECTOR_ARBITRARY_READ_WRITE"},
            {"feasibility", "HIGH"}
        });
    });

    // POST /api/primitives/fake_vtable
    router.post("/api/primitives/fake_vtable", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint fake_vtable_addr = bridge.get_cip();
        duint shellcode_addr = bridge.get_cip() + 0x200;

        if (!body.is_discarded()) {
            if (body.contains("fake_vtable_address")) fake_vtable_addr = bridge.eval_expression(body["fake_vtable_address"].get<std::string>());
            if (body.contains("payload_address")) shellcode_addr = bridge.eval_expression(body["payload_address"].get<std::string>());
        }

        return s_http_response::ok({
            {"fake_vtable_address", format_utils::format_address(fake_vtable_addr)},
            {"payload_entrypoint", format_utils::format_address(shellcode_addr)},
            {"vtable_slots", nlohmann::json::array({
                {{"slot", 0}, {"target_function", format_utils::format_address(shellcode_addr)}},
                {{"slot", 1}, {"target_function", format_utils::format_address(shellcode_addr)}},
                {{"slot", 2}, {"target_function", format_utils::format_address(shellcode_addr)}}
            })},
            {"status", "SYNTHESIZED_VTABLE_READY"}
        });
    });
}

} // namespace handlers
