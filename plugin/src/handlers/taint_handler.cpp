#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <mutex>
#include <unordered_map>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

static std::unordered_map<duint, size_t> g_taint_ranges;
static std::unordered_map<duint, size_t> g_taint_ids;
static std::mutex g_taint_mutex;
static size_t g_taint_counter = 1;

static bool address_in_taint(duint addr, size_t size, duint& out_taint_addr, size_t& out_taint_size) {
    for (const auto& [ta, ts] : g_taint_ranges) {
        duint start = ta;
        duint end = ta + ts;
        if (addr >= start && (addr + size) <= end) {
            out_taint_addr = ta;
            out_taint_size = ts;
            return true;
        }
        if (addr < end && (addr + size) > start) {
            out_taint_addr = ta;
            out_taint_size = ts;
            return true;
        }
    }
    return false;
}

void register_taint_routes(c_http_router& router) {
    router.post("/api/taint/mark", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address") || !body.contains("size")) {
            return s_http_response::bad_request("Missing 'address' and/or 'size' fields");
        }

        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        duint address;
        if (body["address"].is_string()) {
            address = bridge.eval_expression(body["address"].get<std::string>());
        } else if (body["address"].is_number_unsigned()) {
            address = body["address"].get<duint>();
        } else {
            return s_http_response::bad_request("Invalid address format");
        }

        size_t size = body["size"].get<size_t>();

        if (address == 0 || size == 0) {
            return s_http_response::bad_request("Invalid address or size");
        }

        std::lock_guard<std::mutex> lock(g_taint_mutex);
        size_t taint_id = g_taint_counter++;
        g_taint_ranges[address] = size;
        g_taint_ids[address] = taint_id;

        return s_http_response::ok({
            {"marked", true},
            {"address", format_utils::format_address(address)},
            {"size", size},
            {"taint_id", taint_id}
        });
    });

    router.post("/api/taint/clear", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded()) {
            return s_http_response::bad_request("Invalid JSON body");
        }

        std::lock_guard<std::mutex> lock(g_taint_mutex);

        if (body.contains("all") && body["all"].is_boolean() && body["all"].get<bool>()) {
            g_taint_ranges.clear();
            g_taint_ids.clear();
        } else if (body.contains("address")) {
            duint address;
            if (body["address"].is_string()) {
                address = format_utils::parse_address(body["address"].get<std::string>());
            } else if (body["address"].is_number_unsigned()) {
                address = body["address"].get<duint>();
            } else {
                return s_http_response::bad_request("Invalid address format");
            }
            g_taint_ranges.erase(address);
            g_taint_ids.erase(address);
        } else {
            return s_http_response::bad_request("Specify 'all': true or provide 'address'");
        }

        return s_http_response::ok({
            {"cleared", true}
        });
    });

    router.get("/api/taint/status", [](const s_http_request&) -> s_http_response {
        std::lock_guard<std::mutex> lock(g_taint_mutex);

        size_t total_bytes = 0;
        auto ranges = nlohmann::json::array();

        for (const auto& [addr, size] : g_taint_ranges) {
            total_bytes += size;
            auto id_it = g_taint_ids.find(addr);
            size_t taint_id = (id_it != g_taint_ids.end()) ? id_it->second : 0;
            ranges.push_back({
                {"address", format_utils::format_address(addr)},
                {"size", size},
                {"taint_id", taint_id}
            });
        }

        return s_http_response::ok({
            {"active_taints", g_taint_ranges.size()},
            {"total_tainted_bytes", total_bytes},
            {"ranges", ranges}
        });
    });

    router.post("/api/taint/trace_step", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto reg_dump = bridge.get_register_dump();
        if (!reg_dump.has_value()) {
            return s_http_response::internal_error(reg_dump.error());
        }

        duint rip = reg_dump->regcontext.cip;
        auto propagations = nlohmann::json::array();

        std::lock_guard<std::mutex> lock(g_taint_mutex);
        if (g_taint_ranges.empty()) {
            return s_http_response::ok({
                {"propagations", propagations}
            });
        }

#ifdef _WIN64
        duint regs[] = {
            reg_dump->regcontext.cax, reg_dump->regcontext.ccx, reg_dump->regcontext.cdx,
            reg_dump->regcontext.cbx, reg_dump->regcontext.csp, reg_dump->regcontext.cbp,
            reg_dump->regcontext.csi, reg_dump->regcontext.cdi, reg_dump->regcontext.r8,
            reg_dump->regcontext.r9, reg_dump->regcontext.r10, reg_dump->regcontext.r11,
            reg_dump->regcontext.r12, reg_dump->regcontext.r13, reg_dump->regcontext.r14,
            reg_dump->regcontext.r15
        };
        const char* reg_names[] = {
            "rax", "rcx", "rdx", "rbx", "rsp", "rbp", "rsi", "rdi",
            "r8", "r9", "r10", "r11", "r12", "r13", "r14", "r15"
        };
#else
        duint regs[] = {
            reg_dump->regcontext.cax, reg_dump->regcontext.ccx, reg_dump->regcontext.cdx,
            reg_dump->regcontext.cbx, reg_dump->regcontext.csp, reg_dump->regcontext.cbp,
            reg_dump->regcontext.csi, reg_dump->regcontext.cdi
        };
        const char* reg_names[] = {
            "eax", "ecx", "edx", "ebx", "esp", "ebp", "esi", "edi"
        };
#endif
        constexpr size_t reg_count = sizeof(regs) / sizeof(regs[0]);

        for (size_t i = 0; i < reg_count; ++i) {
            duint taint_addr = 0;
            size_t taint_size = 0;
            if (address_in_taint(regs[i], 1, taint_addr, taint_size)) {
                propagations.push_back({
                    {"from", "memory"},
                    {"from_address", format_utils::format_address(taint_addr)},
                    {"to", "register"},
                    {"to_register", reg_names[i]},
                    {"instruction_address", format_utils::format_address(rip)}
                });
            }
        }

        auto inst_bytes = bridge.read_memory(rip, 16);
        if (inst_bytes.has_value() && inst_bytes->size() >= 3) {
            const auto& bytes = inst_bytes.value();
            if ((bytes[0] == 0x88 || bytes[0] == 0x89) && bytes.size() >= 3) {
                uint8_t modrm = bytes[1];
                uint8_t mod = (modrm >> 6) & 0x3;
                uint8_t rm = modrm & 0x7;
                uint8_t src_reg_idx = (modrm >> 3) & 0x7;

                if (mod != 0x3) {
                    duint mem_addr = 0;
                    int offset = 2;

                    if (rm == 0x4 && mod != 0x3) {
                        if (bytes.size() >= offset + 1) {
                            uint8_t sib = bytes[offset];
                            uint8_t base = sib & 0x7;
                            offset++;
                            if (base != 0x5 || mod == 0x0) {
                                mem_addr = regs[base];
                            }
                            if (mod == 0x1 && bytes.size() >= offset + 1) {
                                mem_addr += static_cast<int8_t>(bytes[offset]);
                            } else if (mod == 0x2 && bytes.size() >= offset + 4) {
                                int32_t disp = static_cast<int32_t>(bytes[offset]) |
                                               (static_cast<int32_t>(bytes[offset + 1]) << 8) |
                                               (static_cast<int32_t>(bytes[offset + 2]) << 16) |
                                               (static_cast<int32_t>(bytes[offset + 3]) << 24);
                                mem_addr += disp;
                            }
                        }
                    } else {
                        if (mod == 0x0) {
                            if (rm == 0x5) {
                                if (bytes.size() >= offset + 4) {
                                    mem_addr = static_cast<duint>(bytes[offset]) |
                                               (static_cast<duint>(bytes[offset + 1]) << 8) |
                                               (static_cast<duint>(bytes[offset + 2]) << 16) |
                                               (static_cast<duint>(bytes[offset + 3]) << 24);
                                }
                            } else {
                                mem_addr = regs[rm];
                            }
                        } else if (mod == 0x1 && bytes.size() >= offset + 1) {
                            mem_addr = regs[rm] + static_cast<int8_t>(bytes[offset]);
                        } else if (mod == 0x2 && bytes.size() >= offset + 4) {
                            int32_t disp = static_cast<int32_t>(bytes[offset]) |
                                           (static_cast<int32_t>(bytes[offset + 1]) << 8) |
                                           (static_cast<int32_t>(bytes[offset + 2]) << 16) |
                                           (static_cast<int32_t>(bytes[offset + 3]) << 24);
                            mem_addr = regs[rm] + disp;
                        }
                    }

                    if (mem_addr != 0) {
                        duint taint_addr = 0;
                        size_t taint_size = 0;
                        if (address_in_taint(mem_addr, 1, taint_addr, taint_size)) {
                            if (src_reg_idx < reg_count) {
                                duint src_taint_addr = 0;
                                size_t src_taint_size = 0;
                                if (address_in_taint(regs[src_reg_idx], 1, src_taint_addr, src_taint_size)) {
                                    propagations.push_back({
                                        {"from", "register"},
                                        {"from_register", reg_names[src_reg_idx]},
                                        {"to", "memory"},
                                        {"to_address", format_utils::format_address(mem_addr)},
                                        {"instruction_address", format_utils::format_address(rip)}
                                    });
                                }
                            }
                        }
                    }
                }
            }
        }

        return s_http_response::ok({
            {"propagations", propagations}
        });
    });
}

} // namespace handlers
