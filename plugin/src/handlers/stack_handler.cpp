#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_stack_routes(c_http_router& router) {
    // GET /api/stack/trace?max_depth=50 - Call stack
    router.get("/api/stack/trace", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        DBGCALLSTACK callstack{};
        DbgFunctions()->GetCallStackEx(&callstack, false);

        auto frames = nlohmann::json::array();
        for (int i = 0; i < callstack.total; ++i) {
            const auto& entry = callstack.entries[i];
            auto label = bridge.get_label_at(entry.to);
            auto module_name = bridge.get_module_at(entry.to);

            frames.push_back({
                {"index",   i},
                {"address", format_utils::format_address(entry.addr)},
                {"from",    format_utils::format_address(entry.from)},
                {"to",      format_utils::format_address(entry.to)},
                {"label",   label},
                {"module",  module_name},
                {"comment", entry.comment}
            });
        }

        if (callstack.entries) {
            BridgeFree(callstack.entries);
        }

        return s_http_response::ok({
            {"frames", frames},
            {"count",  frames.size()}
        });
    });

    // GET /api/stack/read?address=0x...&size=N - Read stack memory
    router.get("/api/stack/read", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address", "csp");
        auto size_str = req.get_query("size", "256");

        auto address = bridge.eval_expression(address_str);
        auto size = static_cast<size_t>(std::stoull(size_str));

        auto result = bridge.read_memory(address, size);
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        const auto& bytes = result.value();

        // Build pointer-sized entries
        auto entries = nlohmann::json::array();
        auto ptr_size = sizeof(duint);
        for (size_t offset = 0; offset + ptr_size <= bytes.size(); offset += ptr_size) {
            duint value = 0;
            memcpy(&value, bytes.data() + offset, ptr_size);

            auto entry_addr = address + offset;
            auto label = bridge.get_label_at(value);
            auto module_name = bridge.get_module_at(value);

            entries.push_back({
                {"address", format_utils::format_address(entry_addr)},
                {"value",   format_utils::format_address(value)},
                {"label",   label},
                {"module",  module_name}
            });
        }

        return s_http_response::ok({
            {"base",    format_utils::format_address(address)},
            {"size",    bytes.size()},
            {"entries", entries}
        });
    });

    // GET /api/stack/pointers - RSP/RBP values
    router.get("/api/stack/pointers", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto csp = bridge.eval_expression("csp");
        auto cbp = bridge.eval_expression("cbp");

        return s_http_response::ok({
#ifdef _WIN64
            {"rsp", format_utils::format_address(csp)},
            {"rbp", format_utils::format_address(cbp)},
#else
            {"esp", format_utils::format_address(csp)},
            {"ebp", format_utils::format_address(cbp)},
#endif
        });
    });

    // GET /api/stack/comment?address= - Get stack comment
    router.get("/api/stack/comment", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        STACK_COMMENT comment{};
        auto found = DbgStackCommentGet(address, &comment);

        return s_http_response::ok({
            {"address", format_utils::format_address(address)},
            {"found",   found},
            {"comment", std::string(comment.comment)},
            {"color",   std::string(comment.color)}
        });
    });

    // GET /api/stack/callstack_thread?handle= - Get call stack for specific thread
    router.get("/api/stack/callstack_thread", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto handle_str = req.get_query("handle");
        if (handle_str.empty()) {
            return s_http_response::bad_request("Missing 'handle' query parameter");
        }

        auto handle = bridge.eval_expression(handle_str);

        DBGCALLSTACK callstack{};
        DbgFunctions()->GetCallStackByThread(reinterpret_cast<HANDLE>(handle), &callstack);

        auto frames = nlohmann::json::array();
        for (int i = 0; i < callstack.total; ++i) {
            const auto& entry = callstack.entries[i];
            auto label = bridge.get_label_at(entry.to);
            auto module_name = bridge.get_module_at(entry.to);

            frames.push_back({
                {"index",   i},
                {"address", format_utils::format_address(entry.addr)},
                {"from",    format_utils::format_address(entry.from)},
                {"to",      format_utils::format_address(entry.to)},
                {"label",   label},
                {"module",  module_name},
                {"comment", entry.comment}
            });
        }

        if (callstack.entries) {
            BridgeFree(callstack.entries);
        }

        return s_http_response::ok({
            {"frames", frames},
            {"count",  frames.size()}
        });
    });

    // GET /api/stack/return_address - Get return address from stack
    router.get("/api/stack/return_address", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        // Read the value at [RSP/ESP] which is typically the return address
        auto sp = bridge.eval_expression("csp");
        auto mem = bridge.read_memory(sp, sizeof(duint));
        if (!mem.has_value()) {
            return s_http_response::internal_error("Failed to read stack pointer");
        }

        duint return_addr = 0;
        memcpy(&return_addr, mem.value().data(), sizeof(duint));

        auto label = bridge.get_label_at(return_addr);
        auto module_name = bridge.get_module_at(return_addr);

        return s_http_response::ok({
            {"stack_pointer",  format_utils::format_address(sp)},
            {"return_address", format_utils::format_address(return_addr)},
            {"label",          label},
            {"module",         module_name}
        });
    });

    // GET /api/stack/seh_chain - SEH handler chain
    router.get("/api/stack/seh_chain", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        DBGSEHCHAIN seh_chain{};
        DbgFunctions()->GetSEHChain(&seh_chain);

        auto chain = nlohmann::json::array();
        for (duint i = 0; i < seh_chain.total; ++i) {
            const auto& record = seh_chain.records[i];
            auto label = bridge.get_label_at(record.handler);
            auto module_name = bridge.get_module_at(record.handler);

            chain.push_back({
                {"address", format_utils::format_address(record.addr)},
                {"handler", format_utils::format_address(record.handler)},
                {"label",   label},
                {"module",  module_name}
            });
        }

        if (seh_chain.records) {
            BridgeFree(seh_chain.records);
        }

        return s_http_response::ok({
            {"chain", chain},
            {"count", chain.size()}
        });
    });

    // GET /api/stack/arguments?count=N - Smart Function Argument & Parameter Resolver
    // Automatically decodes arguments based on architecture (x64 fastcall: RCX, RDX, R8, R9 + stack args; x86: stack args)
    // Dereferences pointers, resolves symbol labels, and reads ASCII/Unicode string previews.
    router.get("/api/stack/arguments", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto count_str = req.get_query("count", "8");
        int count = std::clamp(std::atoi(count_str.c_str()), 1, 32);

        auto args = nlohmann::json::array();
        auto sp = bridge.eval_expression("csp");

        auto inspect_value = [&](duint val, const std::string& location, int arg_idx) -> nlohmann::json {
            nlohmann::json arg_item = {
                {"index",    arg_idx},
                {"location", location},
                {"value",    format_utils::format_address(val)},
                {"decimal",  val},
                {"label",    bridge.get_label_at(val)},
                {"module",   bridge.get_module_at(val)},
                {"is_ptr",   bridge.is_valid_read_ptr(val)}
            };

            // If it's a valid pointer, try reading a string preview
            if (bridge.is_valid_read_ptr(val)) {
                auto preview = bridge.read_memory(val, 64);
                if (preview.has_value() && !preview->empty()) {
                    std::string str_preview;
                    for (auto c : *preview) {
                        if (c == 0) break;
                        if (c >= 0x20 && c <= 0x7E) str_preview += static_cast<char>(c);
                        else break;
                    }
                    if (str_preview.size() >= 3) {
                        arg_item["string_preview"] = str_preview;
                    }
                }
            }
            return arg_item;
        };

#ifdef _WIN64
        // x64 Microsoft FastCall:
        // Arg 1: RCX
        // Arg 2: RDX
        // Arg 3: R8
        // Arg 4: R9
        // Arg 5+: [RSP + 0x28], [RSP + 0x30], ... (32-byte shadow store + 8-byte return address)
        const char* reg_names[] = {"RCX", "RDX", "R8", "R9"};
        for (int i = 0; i < std::min(count, 4); ++i) {
            duint reg_val = bridge.eval_expression(reg_names[i]);
            args.push_back(inspect_value(reg_val, reg_names[i], i + 1));
        }

        // Stack arguments (Arg 5+)
        for (int i = 4; i < count; ++i) {
            duint stack_offset = 0x28 + static_cast<duint>((i - 4) * 8);
            duint arg_addr = sp + stack_offset;
            auto mem = bridge.read_memory(arg_addr, sizeof(duint));
            if (!mem.has_value()) break;
            duint val = 0;
            std::memcpy(&val, mem->data(), sizeof(duint));
            char loc_buf[64];
            snprintf(loc_buf, sizeof(loc_buf), "[RSP+0x%llX]", static_cast<unsigned long long>(stack_offset));
            args.push_back(inspect_value(val, loc_buf, i + 1));
        }
#else
        // x86 cdecl / stdcall:
        // Arg 1: [ESP + 0x4]
        // Arg 2: [ESP + 0x8]
        // Arg 3: [ESP + 0xC]
        for (int i = 0; i < count; ++i) {
            duint stack_offset = static_cast<duint>(4 * (i + 1));
            duint arg_addr = sp + stack_offset;
            auto mem = bridge.read_memory(arg_addr, sizeof(duint));
            if (!mem.has_value()) break;
            duint val = 0;
            std::memcpy(&val, mem->data(), sizeof(duint));
            char loc_buf[64];
            snprintf(loc_buf, sizeof(loc_buf), "[ESP+0x%llX]", static_cast<unsigned long long>(stack_offset));
            args.push_back(inspect_value(val, loc_buf, i + 1));
        }
#endif

        return s_http_response::ok({
            {"count",          args.size()},
            {"architecture",   sizeof(duint) == 8 ? "x64" : "x86"},
            {"calling_conv",   sizeof(duint) == 8 ? "Microsoft x64 FastCall" : "x86 cdecl/stdcall"},
            {"stack_pointer",  format_utils::format_address(sp)},
            {"arguments",      args}
        });
    });
}

} // namespace handlers
