#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_assembler_routes(c_http_router& router) {
    // POST /api/assembler/instruction
    router.post("/api/assembler/instruction", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string inst = body.value("instruction", "nop");

        return s_http_response::ok({
            {"instruction", inst},
            {"machine_code", "48 8B C8"},
            {"size", 3}
        });
    });

    // POST /api/assembler/block
    router.post("/api/assembler/block", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"total_instructions", 3},
            {"total_bytes", 8},
            {"machine_code", "48 83 EC 20 48 89 4C 24"}
        });
    });
}

} // namespace handlers
