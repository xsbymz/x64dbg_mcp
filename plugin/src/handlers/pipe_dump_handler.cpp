#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_pipe_dump_routes(c_http_router& router) {
    // POST /api/pipe_dump/buffers
    router.post("/api/pipe_dump/buffers", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"in_buffer_size", 4096},
            {"out_buffer_size", 4096},
            {"bytes_available", 0},
            {"status", "PIPE_BUFFER_READ"}
        });
    });

    // POST /api/pipe_dump/instances
    router.post("/api/pipe_dump/instances", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"current_instances", 1},
            {"max_instances", 255}
        });
    });

    // POST /api/pipe_dump/transactions
    router.post("/api/pipe_dump/transactions", [](const s_http_request& req) -> s_http_response {
        return s_http_response::ok({
            {"pending_transactions_count", 0},
            {"transactions", nlohmann::json::array()}
        });
    });
}

} // namespace handlers
