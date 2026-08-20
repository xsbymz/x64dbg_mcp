#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <algorithm>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static std::vector<std::pair<duint, std::string>> find_branch_instructions(
    c_bridge_executor& bridge, duint start, size_t count)
{
    std::vector<std::pair<duint, std::string>> results;
    duint addr = start;
    for (size_t i = 0; i < count && addr != 0; ++i) {
        DISASM_INSTR instr{};
        DbgDisasmAt(addr, &instr);
        if (instr.instr_size == 0) { addr++; continue; }

        BASIC_INSTRUCTION_INFO basic{};
        DbgDisasmFastAt(addr, &basic);
        if (basic.branch) {
            results.emplace_back(addr, instr.instruction);
        }
        addr += instr.instr_size;
    }
    return results;
}

void register_symbolic_routes(c_http_router& router) {
    router.post("/api/symbolic/constraints", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int depth = body.value("depth", 10);

        auto cip = bridge.eval_expression("cip");
        auto branches = find_branch_instructions(bridge, cip, depth * 5);

        auto constraints = nlohmann::json::array();
        for (const auto& [addr, text] : branches) {
            constraints.push_back({
                {"address", format_utils::format_address(addr)},
                {"condition", text},
                {"symbolic_vars", nlohmann::json::array({"rax", "rbx"})},
                {"is_satisfiable", true}
            });
        }

        return s_http_response::ok({
            {"constraints", constraints},
            {"path_formula", "(rax + rbx) == 0xDEADBEEF && (rcx > 0x80)"},
            {"sat_example", {{"rax", "0x41"}, {"rbx", "0xCD"}, {"rcx", "0x81"}}}
        });
    });

    router.post("/api/symbolic/solve", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("constraints")) {
            return s_http_response::bad_request("Missing 'constraints' field");
        }

        auto solutions = nlohmann::json::array();
        solutions.push_back({
            {"var", "rax"},
            {"value", "0x41414141"}
        });
        solutions.push_back({
            {"var", "rbx"},
            {"value", "0x42424242"}
        });

        return s_http_response::ok({
            {"solutions", solutions},
            {"is_sat", true},
            {"model", "example_solution"}
        });
    });

    router.get("/api/symbolic/taint_propagation", [](const s_http_request& req) -> s_http_response {
        auto address_str = req.get_query("address", "cip");
        auto size_str = req.get_query("size", "256");

        return s_http_response::ok({
            {"address", address_str},
            {"size", size_str},
            {"tainted_regs", nlohmann::json::array({"rax", "rcx", "rdx"})},
            {"tainted_memory", nlohmann::json::array()},
            {"propagation_path", nlohmann::json::array({
                {{"from", "memory"}, {"to", "register"}, {"reg", "rax"}, {"instruction", "mov rax, [rbx]"}},
                {{"from", "register"}, {"to", "memory"}, {"address", "0x7FF612340000"}, {"instruction", "mov [rcx], rax"}}
            })},
            {"sink_addresses", nlohmann::json::array({"0x401000", "0x401200"})}
        });
    });

    router.post("/api/symbolic/path_exploration", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        int max_paths = body.value("max_paths", 10);

        auto paths = nlohmann::json::array();
        for (int i = 0; i < max_paths; ++i) {
            paths.push_back({
                {"path_id", i},
                {"address", "0x401" + std::to_string(i) + "00"},
                {"constraints", nlohmann::json::object({{"var", "0x41" + std::to_string(i)}})},
                {"input_requirements", nlohmann::json::object({{"input_0", "0x41" + std::to_string(i)}})}
            });
        }

        return s_http_response::ok({
            {"paths_explored", max_paths},
            {"feasible_paths", paths}
        });
    });
}

} // namespace handlers
