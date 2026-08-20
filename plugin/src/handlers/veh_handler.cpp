#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <cstdint>
#include <cstring>
#include "_dbgfunctions.h"

namespace handlers {

#pragma pack(push, 1)
struct _vectored_handler_entry {
    uint64_t next;
    uint64_t handler_function;
};
#pragma pack(pop)

static std::expected<uint64_t, std::string> read_ptr(auto& bridge, uint64_t addr) {
    auto mem = bridge.read_memory(addr, sizeof(uint64_t));
    if (!mem.has_value() || mem->size() != sizeof(uint64_t)) {
        return std::unexpected("Failed to read pointer at " + std::to_string(addr));
    }
    uint64_t val = 0;
    memcpy(&val, mem->data(), sizeof(uint64_t));
    return val;
}

void register_veh_routes(c_http_router& router) {
    router.get("/api/veh/chain", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto pid = static_cast<DWORD>(bridge.eval_expression("$pid"));
        auto peb_addr = DbgGetPebAddress(pid);
        if (peb_addr == 0) {
            return s_http_response::internal_error("Failed to get PEB address");
        }

        uint64_t veh_head = 0;
#ifdef _WIN64
        constexpr uint64_t vectored_handler_list_offset = 0x570;
#else
        constexpr uint64_t vectored_handler_list_offset = 0x338;
#endif
        auto head_result = read_ptr(bridge, peb_addr + vectored_handler_list_offset);
        if (!head_result.has_value()) {
            return s_http_response::internal_error(head_result.error());
        }
        veh_head = head_result.value();

        auto handlers = nlohmann::json::array();
        uint64_t current = veh_head;
        while (current != 0) {
            auto entry_result = bridge.read_memory(current, sizeof(_vectored_handler_entry));
            if (!entry_result.has_value() || entry_result->size() != sizeof(_vectored_handler_entry)) {
                break;
            }
            _vectored_handler_entry entry;
            memcpy(&entry, entry_result->data(), sizeof(entry));
            nlohmann::json item = {
                {"address", format_utils::format_address(current)},
                {"handler_function", format_utils::format_address(entry.handler_function)},
                {"next", format_utils::format_address(entry.next)}
            };
            handlers.push_back(item);
            current = entry.next;
        }

        return s_http_response::ok({
            {"veh_address", format_utils::format_address(veh_head)},
            {"handlers", handlers},
            {"count", handlers.size()}
        });
    });
}

} // namespace handlers
