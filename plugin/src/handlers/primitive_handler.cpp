#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <algorithm>
#include <cctype>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static std::vector<std::pair<std::string, std::string>> get_module_list() {
    std::vector<std::pair<std::string, std::string>> modules;
    MEMMAP memmap{};
    if (!DbgMemMap(&memmap)) return modules;

    for (int i = 0; i < memmap.count; ++i) {
        const auto& page = memmap.page[i];
        if (page.mbi.State != MEM_COMMIT) continue;
        std::string info = page.info;
        if (info.empty()) continue;
        std::string lower = info;
        std::transform(lower.begin(), lower.end(), lower.begin(), [](unsigned char c) { return std::tolower(c); });
        if (lower.size() > 4 && (lower.ends_with(".dll") || lower.ends_with(".exe") || lower.ends_with(".sys"))) {
            auto last_sep = info.find_last_of("\\/");
            std::string mod_name = (last_sep != std::string::npos) ? info.substr(last_sep + 1) : info;
            bool found = false;
            for (const auto& m : modules) {
                if (m.first == mod_name) { found = true; break; }
            }
            if (!found) {
                modules.emplace_back(mod_name, format_utils::format_address(reinterpret_cast<duint>(page.mbi.BaseAddress)));
            }
        }
    }

    if (memmap.page) BridgeFree(memmap.page);
    return modules;
}

static duint resolve_function(const std::string& module, const std::string& func) {
    std::string expr = module + ":" + func;
    auto addr = DbgValFromString(expr.c_str());
    if (addr == 0) {
        expr = module + "." + func;
        addr = DbgValFromString(expr.c_str());
    }
    return addr;
}

void register_primitive_routes(c_http_router& router) {
    router.get("/api/primitive/detect", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto modules = get_module_list();

        auto arbitrary_read = nlohmann::json::array();
        auto arbitrary_write = nlohmann::json::array();
        auto info_leak = nlohmann::json::array();
        auto dangerous = nlohmann::json::array();

        struct func_entry {
            const char* category;
            const char* func_name;
            const char* description;
        };

        const func_entry arbitrary_read_funcs[] = {
            {"arbitrary_read", "memcpy", "Copies user-controlled length from user-controlled source"},
            {"arbitrary_read", "ReadProcessMemory", "Reads another process memory with user-controlled parameters"},
            {"arbitrary_read", "wcscpy", "Copies wide string with user-controlled source"},
            {"arbitrary_read", "strncpy", "Copies n bytes from user-controlled source"},
            {"arbitrary_read", "lstrcpy", "Copies string with user-controlled source"},
            {"arbitrary_read", "RtlCopyMemory", "Alias for RtlMoveMemory with user-controlled parameters"},
            {"arbitrary_read", "RtlMoveMemory", "Moves memory with user-controlled parameters"},
            {"arbitrary_read", "CopyMemory", "Alias for RtlCopyMemory with user-controlled parameters"},
        };

        const func_entry arbitrary_write_funcs[] = {
            {"arbitrary_write", "WriteProcessMemory", "Writes to another process memory with user-controlled parameters"},
            {"arbitrary_write", "memmove", "Moves memory with user-controlled destination"},
            {"arbitrary_write", "memset", "Fills memory with user-controlled destination and size"},
            {"arbitrary_write", "RtlFillMemory", "Fills memory with user-controlled parameters"},
            {"arbitrary_write", "FillMemory", "Alias for RtlFillMemory"},
        };

        const func_entry info_leak_funcs[] = {
            {"info_leak", "NtQueryInformationProcess", "Queries process information including debug port"},
            {"info_leak", "NtQuerySystemInformation", "Queries system information"},
            {"info_leak", "NtQueryVirtualMemory", "Queries virtual memory layout"},
            {"info_leak", "EnumWindows", "Enumerates top-level windows"},
            {"info_leak", "EnumThreadWindows", "Enumerates windows belonging to a thread"},
            {"info_leak", "GetForegroundWindow", "Gets the foreground window handle"},
            {"info_leak", "GetWindowText", "Gets window text"},
            {"info_leak", "GetWindowThreadProcessId", "Gets process/thread ID of a window"},
            {"info_leak", "NtQueryObject", "Queries object information"},
        };

        const func_entry dangerous_funcs[] = {
            {"dangerous", "strcpy", "Unbounded string copy"},
            {"dangerous", "sprintf", "Unbounded formatted string write"},
            {"dangerous", "gets", "Reads line without bounds checking"},
            {"dangerous", "scanf", "Reads formatted input without bounds checking"},
            {"dangerous", "sscanf", "Reads formatted string without bounds checking"},
            {"dangerous", "strcat", "Unbounded string concatenation"},
            {"dangerous", "memcpy", "Copies n bytes without overlap check"},
        };

        auto check_func = [&](const func_entry& entry, nlohmann::json& arr) {
            for (const auto& mod : modules) {
                auto addr = resolve_function(mod.first, entry.func_name);
                if (addr != 0) {
                    arr.push_back({
                        {"name", entry.func_name},
                        {"address", format_utils::format_address(addr)},
                        {"module", mod.first},
                        {"description", entry.description},
                        {"type", entry.category}
                    });
                    return;
                }
            }
        };

        for (const auto& entry : arbitrary_read_funcs) check_func(entry, arbitrary_read);
        for (const auto& entry : arbitrary_write_funcs) check_func(entry, arbitrary_write);
        for (const auto& entry : info_leak_funcs) check_func(entry, info_leak);
        for (const auto& entry : dangerous_funcs) check_func(entry, dangerous);

        return s_http_response::ok({
            {"arbitrary_read_candidates", arbitrary_read},
            {"arbitrary_write_candidates", arbitrary_write},
            {"info_leak_candidates", info_leak},
            {"dangerous_funcs", dangerous}
        });
    });

    router.post("/api/primitive/trace", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("function_address")) {
            return s_http_response::bad_request("Missing 'function_address' field");
        }

        auto func_addr_str = body["function_address"].get<std::string>();
        auto function_address = bridge.eval_expression(func_addr_str);
        if (function_address == 0) {
            return s_http_response::bad_request("Invalid function address");
        }

        auto max_traces = body.value("max_traces", 10);
        if (max_traces < 1) max_traces = 1;
        if (max_traces > 1000) max_traces = 1000;

        std::string trace_cond = "eip == " + format_utils::format_address(function_address);

        std::string log_format = "RIP=" + format_utils::format_address(function_address) +
                                 " RSP={r} RBP={r} RAX={r} RBX={r} RCX={r} RDX={r} R8={r} R9={r}";
        std::string log_cmd = "TraceSetLog \"" + log_format + "\", eip == " + format_utils::format_address(function_address);
        bridge.exec_command(log_cmd);

        std::string trace_cmd = "TraceIntoConditional \"" + trace_cond + "\", " + std::to_string(max_traces);
        auto success = bridge.exec_command_async(trace_cmd);

        return s_http_response::ok({
            {"success", success},
            {"function_address", format_utils::format_address(function_address)},
            {"max_traces", max_traces},
            {"traces", nlohmann::json::array()},
            {"command", trace_cmd},
            {"message", "Conditional trace started asynchronously. Check trace log for results."}
        });
    });
}

} // namespace handlers
