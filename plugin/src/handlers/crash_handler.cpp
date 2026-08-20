#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include <algorithm>
#include <cstdint>
#include <string>
#include <vector>
#include <unordered_map>

namespace handlers {

static std::string classify_crash(duint exception_code, duint fault_addr, duint rsp) {
    std::string classification = "unknown";
    if (exception_code == 0xC0000005) {
        if (fault_addr == 0) classification = "NULL dereference";
        else classification = "access violation";
    } else if (exception_code == 0xC0000094) {
        classification = "integer divide by zero";
    } else if (exception_code == 0x80000003) {
        classification = "breakpoint";
    } else if (exception_code == 0xC00000FD) {
        classification = "stack overflow";
    } else if (exception_code == 0xC0000017) {
        classification = "no memory";
    } else if (exception_code == 0xC000001D) {
        classification = "illegal instruction";
    } else if (exception_code == 0xC0000006) {
        classification = "page in page file";
    } else if (exception_code == 0xC0000092) {
        classification = "PAGE_GUARD violation";
    } else if (exception_code == 0xC000008D) {
        classification = "floating-point exception";
    }
    return classification;
}

void register_crash_routes(c_http_router& router) {
    router.get("/api/crash/buckets", [](const s_http_request&) -> s_http_response {
        auto known = nlohmann::json::array({
            {{"code", "0x80000003"}, {"name", "STATUS_BREAKPOINT"},           {"description", "A breakpoint was encountered"}},
            {{"code", "0xC0000005"}, {"name", "STATUS_ACCESS_VIOLATION"},     {"description", "Memory access violation (read/write/execute)"}},
            {{"code", "0xC000001D"}, {"name", "STATUS_ILLEGAL_INSTRUCTION"},  {"description", "Invalid opcode encountered"}},
            {{"code", "0xC0000094"}, {"name", "STATUS_INTEGER_DIVIDE_BY_ZERO"}, {"description", "Division by zero (integer)"}},
            {{"code", "0xC000008D"}, {"name", "STATUS_FLOAT_MULTIPLE_FAULTS"}, {"description", "Floating-point multiple faults"}},
            {{"code", "0xC000008E"}, {"name", "STATUS_FLOAT_DIVIDE_BY_ZERO"},  {"description", "Floating-point division by zero"}},
            {{"code", "0xC00000FD"}, {"name", "STATUS_STACK_OVERFLOW"},       {"description", "Stack overflow"}},
            {{"code", "0xC0000017"}, {"name", "STATUS_NO_MEMORY"},            {"description", "Insufficient memory"}},
            {{"code", "0xC0000092"}, {"name", "STATUS_STACK_BUFFER_OVERRUN"}, {"description", "Stack buffer overrun"}},
            {{"code", "0xC0000006"}, {"name", "STATUS_IN_PAGE_ERROR"},        {"description", "Page in page file could not be read"}},
            {{"code", "0xC0000409"}, {"name", "STATUS_STACK_BUFFER_OVERRUN"}, {"description", "Stack buffer overrun (GS cookie)"}},
            {{"code", "0xE06D7363"}, {"name", "C++ EH Exception"},            {"description", "C++ exception (MSVC / _set_se_translator)"}},
            {{"code", "0x40010006"}, {"name", "Control-C / Control-Break"},   {"description", "Console control signal"}},
            {{"code", "0x406D1388"}, {"name", "MSVC PDB Exception"},          {"description", "Debugger symbol load notification"}}
        });
        return s_http_response::ok({
            {"exceptions", known},
            {"count", known.size()}
        });
    });

    router.get("/api/crash/last", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        duint exception_code = bridge.eval_expression("LastExceptionInfo.Code");
        duint exception_addr = bridge.eval_expression("LastExceptionInfo.Address");
        DWORD flags = 0;

        auto flags_mem = bridge.read_memory(exception_addr, 4);
        if (flags_mem.has_value() && flags_mem->size() >= 4) {
            std::memcpy(&flags, flags_mem->data(), 4);
        }

        return s_http_response::ok({
            {"exception_code",    format_utils::format_address(exception_code)},
            {"exception_address", format_utils::format_address(exception_addr)},
            {"flags",             format_utils::format_address(flags)}
        });
    });

    router.get("/api/crash/triage", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        duint exception_code = bridge.eval_expression("LastExceptionInfo.Code");
        duint exception_addr = bridge.eval_expression("LastExceptionInfo.Address");

        auto dump_result = bridge.get_register_dump();
        if (!dump_result.has_value()) {
            return s_http_response::internal_error("Failed to get register dump");
        }

        const auto& ctx = dump_result->regcontext;
        duint rsp = ctx.csp;
        duint rbp = ctx.cbp;

        auto disasm_result = bridge.disassemble_at(exception_addr, 5);
        nlohmann::json faulting_disasm = nlohmann::json::array();
        if (disasm_result.has_value()) {
            faulting_disasm = disasm_result.value();
        }

        nlohmann::json registers;
#ifdef _WIN64
        registers["rax"] = format_utils::format_address(ctx.cax);
        registers["rcx"] = format_utils::format_address(ctx.ccx);
        registers["rdx"] = format_utils::format_address(ctx.cdx);
        registers["rbx"] = format_utils::format_address(ctx.cbx);
        registers["rsp"] = format_utils::format_address(ctx.csp);
        registers["rbp"] = format_utils::format_address(ctx.cbp);
        registers["rsi"] = format_utils::format_address(ctx.csi);
        registers["rdi"] = format_utils::format_address(ctx.cdi);
        registers["r8"]  = format_utils::format_address(ctx.r8);
        registers["r9"]  = format_utils::format_address(ctx.r9);
        registers["r10"] = format_utils::format_address(ctx.r10);
        registers["r11"] = format_utils::format_address(ctx.r11);
        registers["r12"] = format_utils::format_address(ctx.r12);
        registers["r13"] = format_utils::format_address(ctx.r13);
        registers["r14"] = format_utils::format_address(ctx.r14);
        registers["r15"] = format_utils::format_address(ctx.r15);
        registers["rip"] = format_utils::format_address(ctx.cip);
#else
        registers["eax"] = format_utils::format_address(ctx.cax);
        registers["ecx"] = format_utils::format_address(ctx.ccx);
        registers["edx"] = format_utils::format_address(ctx.cdx);
        registers["ebx"] = format_utils::format_address(ctx.cbx);
        registers["esp"] = format_utils::format_address(ctx.csp);
        registers["ebp"] = format_utils::format_address(ctx.cbp);
        registers["esi"] = format_utils::format_address(ctx.csi);
        registers["edi"] = format_utils::format_address(ctx.cdi);
        registers["eip"] = format_utils::format_address(ctx.cip);
#endif
        registers["eflags"] = format_utils::format_address(ctx.eflags);
        registers["cs"] = ctx.cs;
        registers["ds"] = ctx.ds;
        registers["es"] = ctx.es;
        registers["fs"] = ctx.fs;
        registers["gs"] = ctx.gs;
        registers["ss"] = ctx.ss;

        auto stack_mem = bridge.read_memory(rsp, 32);
        std::string stack_top;
        if (stack_mem.has_value()) {
            stack_top = format_utils::format_bytes_hex(stack_mem->data(), std::min<size_t>(stack_mem->size(), 32));
        }

        DBGSEHCHAIN seh{};
        DbgFunctions()->GetSEHChain(&seh);
        auto seh_chain = nlohmann::json::array();
        for (duint i = 0; i < seh.total; ++i) {
            auto addr = seh.records[i].addr;
            auto handler = seh.records[i].handler;
            seh_chain.push_back({
                {"index",        i},
                {"record_addr",  format_utils::format_address(addr)},
                {"handler_addr", format_utils::format_address(handler)},
                {"handler_label", bridge.get_label_at(handler)},
                {"handler_module", bridge.get_module_at(handler)}
            });
        }
        if (seh.records) {
            BridgeFree(seh.records);
        }

        duint region_base = 0;
        duint region_size = 0;
        DWORD protect = 0;
        DWORD state = 0;
        DWORD mem_type = 0;
        duint page_base = DbgMemFindBaseAddr(exception_addr, &region_size);
        if (page_base != 0) {
            auto mem_info = bridge.read_memory(page_base, 16);
            if (mem_info.has_value() && mem_info.value().size() >= 12) {
                protect = *reinterpret_cast<const DWORD*>(mem_info.value().data());
                state = *reinterpret_cast<const DWORD*>(mem_info.value().data() + 4);
                mem_type = *reinterpret_cast<const DWORD*>(mem_info.value().data() + 8);
            }
        }

        std::string classification = classify_crash(exception_code, exception_addr, rsp);

        return s_http_response::ok({
            {"exception_code",     format_utils::format_address(exception_code)},
            {"exception_address",  format_utils::format_address(exception_addr)},
            {"faulting_disasm",    faulting_disasm},
            {"registers",          registers},
            {"stack_top",          stack_top},
            {"seh_chain",          seh_chain},
            {"memory_info", {
                {"base",            format_utils::format_address(page_base)},
                {"region_size",     region_size},
                {"protection",      format_utils::format_protection(protect)},
                {"protection_raw",  format_utils::format_address(protect)},
                {"state",           format_utils::format_mem_state(state)},
                {"state_raw",       format_utils::format_address(state)},
                {"type",            format_utils::format_mem_type(mem_type)},
                {"type_raw",        format_utils::format_address(mem_type)}
            }},
            {"classification",     classification}
        });
    });
}

} // namespace handlers
