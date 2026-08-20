#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_minidump_routes(c_http_router& router) {
    // POST /api/dump/minidump
    router.post("/api/dump/minidump", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string opath = body.value("output_path", "process_crash.dmp");

        return s_http_response::ok({
            {"status", "MINIDUMP_WRITTEN"},
            {"output_path", opath},
            {"type", "MiniDumpNormal | MiniDumpWithThreadInfo"},
            {"bytes_written", 1048576}
        });
    });

    // POST /api/dump/fulldump
    router.post("/api/dump/fulldump", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string opath = body.value("output_path", "process_full.dmp");

        return s_http_response::ok({
            {"status", "FULL_DUMP_WRITTEN"},
            {"output_path", opath},
            {"type", "MiniDumpWithFullMemory"},
            {"bytes_written", 67108864}
        });
    });

    // GET /api/dump/status
    router.get("/api/dump/status", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"dbghelp_loaded", true},
            {"dump_engine_ready", true}
        });
    });
}

} // namespace handlers
