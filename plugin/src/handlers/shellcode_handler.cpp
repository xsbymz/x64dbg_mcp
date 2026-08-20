#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <cstring>
#include <vector>
#include <algorithm>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_scriptapi_memory.h"

namespace handlers {

void register_shellcode_routes(c_http_router& router) {
    // POST /api/shellcode/execute - Allocate memory, write shellcode bytes, and execute
    router.post("/api/shellcode/execute", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("bytes")) {
            return s_http_response::bad_request("Missing 'bytes' field (hex string like \"90 90 CC\")");
        }

        auto hex_str = body["bytes"].get<std::string>();
        auto bytes = format_utils::parse_hex_bytes(hex_str);
        if (bytes.empty()) {
            return s_http_response::bad_request("No valid bytes to execute");
        }

        auto timeout_ms = body.value("timeout_ms", 5000);
        bool single_step = body.value("single_step", false);

        // Allocate memory in target process
        duint alloc_addr = Script::Memory::RemoteAlloc(0, static_cast<duint>(bytes.size()));
        if (alloc_addr == 0) {
            return s_http_response::internal_error("Failed to allocate memory for shellcode");
        }

        // Write shellcode bytes
        if (!Script::Memory::Write(alloc_addr, bytes.data(), static_cast<duint>(bytes.size()), nullptr)) {
            Script::Memory::RemoteFree(alloc_addr);
            return s_http_response::internal_error("Failed to write shellcode bytes");
        }

        nlohmann::json result = {
            {"allocated_address", format_utils::format_address(alloc_addr)},
            {"size", bytes.size()}
        };

        if (single_step) {
            std::string cond = "cip == " + format_utils::format_address(alloc_addr) + " || cip < " + format_utils::format_address(alloc_addr + bytes.size());
            std::string trace_cmd = "TraceIntoConditional " + cond + ", " + std::to_string(static_cast<int>(bytes.size() * 10));
            if (!bridge.exec_command_async(trace_cmd)) {
                result["execution_result"] = "error";
                result["exception_info"] = "Failed to start trace";
                return s_http_response::ok(result);
            }

            if (!bridge.exec_command_and_wait("stop", timeout_ms)) {
                result["execution_result"] = "timeout";
                result["message"] = "Trace timed out, debugger may still be running";
                return s_http_response::ok(result);
            }

            result["execution_result"] = "completed";

            auto reg_dump = bridge.get_register_dump();
            if (reg_dump.has_value()) {
                const auto& reg = reg_dump.value();
                nlohmann::json snap = {
                    {"cip", format_utils::format_address(reg.regcontext.cip)},
                    {"csp", format_utils::format_address(reg.regcontext.csp)},
                    {"rax", format_utils::format_address(reg.regcontext.cax)},
                    {"rbx", format_utils::format_address(reg.regcontext.cbx)},
                    {"rcx", format_utils::format_address(reg.regcontext.ccx)},
                    {"rdx", format_utils::format_address(reg.regcontext.cdx)},
                    {"rsi", format_utils::format_address(reg.regcontext.csi)},
                    {"rdi", format_utils::format_address(reg.regcontext.cdi)}
                };
#ifdef _WIN64
                snap["r8"]  = format_utils::format_address(reg.regcontext.r8);
                snap["r9"]  = format_utils::format_address(reg.regcontext.r9);
                snap["r10"] = format_utils::format_address(reg.regcontext.r10);
                snap["r11"] = format_utils::format_address(reg.regcontext.r11);
                snap["r12"] = format_utils::format_address(reg.regcontext.r12);
                snap["r13"] = format_utils::format_address(reg.regcontext.r13);
                snap["r14"] = format_utils::format_address(reg.regcontext.r14);
                snap["r15"] = format_utils::format_address(reg.regcontext.r15);
#endif
                result["registers_snapshot"] = snap;
            }
        } else {
            // Set RIP and run
            std::string set_cip = "setcip " + format_utils::format_address(alloc_addr);
            bridge.exec_command(set_cip);
            if (!DbgFunctions()->AnimateCommand("run")) {
                Script::Memory::RemoteFree(alloc_addr);
                return s_http_response::internal_error("Failed to execute shellcode");
            }

            if (!bridge.exec_command_and_wait("stop", timeout_ms)) {
                result["execution_result"] = "timeout";
                result["message"] = "Shellcode execution timed out, debugger may still be running";
                return s_http_response::ok(result);
            }

            auto reg_dump = bridge.get_register_dump();
            if (reg_dump.has_value()) {
                const auto& reg = reg_dump.value();
                result["registers_snapshot"] = {
                    {"cip", format_utils::format_address(reg.regcontext.cip)},
                    {"csp", format_utils::format_address(reg.regcontext.csp)},
                    {"rax", format_utils::format_address(reg.regcontext.cax)},
                    {"rbx", format_utils::format_address(reg.regcontext.cbx)},
                    {"rcx", format_utils::format_address(reg.regcontext.ccx)},
                    {"rdx", format_utils::format_address(reg.regcontext.cdx)}
                };
            }

            result["execution_result"] = "completed";
        }

        return s_http_response::ok(result);
    });

    // GET /api/shellcode/disassemble?address=0x...&count= - Linear disassembly of raw bytes
    router.get("/api/shellcode/disassemble", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "cip");
        auto count_str = req.get_query("count", "16");

        auto address = bridge.eval_expression(address_str);
        auto count = format_utils::safe_parse_int(count_str, 16);
        if (count < 1) count = 1;
        if (count > 5000) count = 5000;

        auto result = bridge.disassemble_at(address, count);
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        return s_http_response::ok({
            {"address",      format_utils::format_address(address)},
            {"count",        result->size()},
            {"instructions", result.value()}
        });
    });
}

} // namespace handlers
