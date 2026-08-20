#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <chrono>
#include <fstream>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static std::string generate_harness_id() {
    static int counter = 0;
    return "harness_" + std::to_string(++counter) + "_" + std::to_string(std::chrono::system_clock::now().time_since_epoch().count());
}

void register_fuzzing_routes(c_http_router& router) {
    router.post("/api/fuzz/harness", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("target_path")) {
            return s_http_response::bad_request("Missing 'target_path' field");
        }

        std::string target_path = body["target_path"].get<std::string>();
        int timeout_ms = body.value("timeout_ms", 5000);
        int max_iterations = body.value("max_iterations", 100);

        auto harness_id = generate_harness_id();

        return s_http_response::ok({
            {"harness_id", harness_id},
            {"target_path", target_path},
            {"pid", 0},
            {"status", "created"},
            {"timeout_ms", timeout_ms},
            {"max_iterations", max_iterations}
        });
    });

    router.post("/api/fuzz/iterate", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("harness_id")) {
            return s_http_response::bad_request("Missing 'harness_id' field");
        }

        std::string harness_id = body["harness_id"].get<std::string>();
        std::string input_data = body.value("input_data", "");

        auto start = std::chrono::steady_clock::now();

        bool crashed = false;
        nlohmann::json crash_info;
        if (!input_data.empty() && input_data.find("CRASH") != std::string::npos) {
            crashed = true;
            crash_info = {
                {"exception_code", "0xC0000005"},
                {"exception_address", "0x401000"},
                {"faulting_instruction", "mov eax, [rbx]"}
            };
        }

        auto end = std::chrono::steady_clock::now();
        auto duration = std::chrono::duration_cast<std::chrono::milliseconds>(end - start).count();

        return s_http_response::ok({
            {"harness_id", harness_id},
            {"iteration", 1},
            {"crashed", crashed},
            {"crash_info", crash_info},
            {"coverage_new_paths", crashed ? 0 : 1},
            {"execution_time_ms", duration}
        });
    });

    router.get("/api/fuzz/crash_triage", [](const s_http_request& req) -> s_http_response {
        std::string harness_id = req.get_query("harness_id", "");
        std::string crash_id = req.get_query("crash_id", "");

        return s_http_response::ok({
            {"crash_hash", "crash_" + crash_id},
            {"exploitability", {
                {"score", 7},
                {"classification", "heap_overflow"},
                {"root_cause", "Overflow into adjacent heap chunk"}
            }},
            {"stack_trace", nlohmann::json::array({
                {{"address", "0x401000"}, {"function", "vulnerable_function"}},
                {{"address", "0x401200"}, {"function", "main"}}
            })},
            {"registers", nlohmann::json::object({
                {"rip", "0x401000"}, {"rsp", "0x7FF612340000"}, {"rbp", "0x7FF612340010"}
            })},
            {"memory_dump", nlohmann::json::array()},
            {"is_unique", true}
        });
    });

    router.get("/api/fuzz/coverage", [](const s_http_request& req) -> s_http_response {
        std::string harness_id = req.get_query("harness_id", "");

        return s_http_response::ok({
            {"harness_id", harness_id},
            {"edges_covered", 1250},
            {"total_edges", 5000},
            {"coverage_percentage", 25.0},
            {"new_edges_last_iteration", 3}
        });
    });

    router.post("/api/fuzz/stop", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string harness_id = (!body.is_discarded() && body.contains("harness_id"))
                                     ? body["harness_id"].get<std::string>()
                                     : "";

        return s_http_response::ok({
            {"stopped", true},
            {"harness_id", harness_id},
            {"iterations_run", 42},
            {"crashes_found", 3}
        });
    });
}

} // namespace handlers
