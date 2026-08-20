#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_heap_routes(c_http_router& router) {
    router.get("/api/heap/list", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        BridgeList<HEAPINFO> heaps;
        auto success = DbgFunctions()->EnumHeaps(&heaps);

        if (!success) {
            return s_http_response::ok({
                {"heaps", nlohmann::json::array()},
                {"count", 0}
            });
        }

        auto result = nlohmann::json::array();
        for (int i = 0; i < heaps.Count(); ++i) {
            result.push_back({
                {"address", format_utils::format_address(heaps[i].addr)},
                {"size",    heaps[i].size},
                {"flags",   format_utils::format_address(heaps[i].flags)}
            });
        }

        return s_http_response::ok({
            {"heaps", result},
            {"count", result.size()}
        });
    });

    router.get("/api/heap/walk", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto addr_str = req.get_query("address", "");
        if (addr_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto heap_base = format_utils::parse_address(addr_str);
        if (heap_base == 0) {
            return s_http_response::bad_request("Invalid heap address");
        }

        auto header = bridge.read_memory(heap_base, 0x200);
        if (!header.has_value() || header->size() < 0x200) {
            return s_http_response::not_found("Failed to read heap header at " + format_utils::format_address(heap_base));
        }

        nlohmann::json heap_info = {
            {"base", format_utils::format_address(heap_base)},
            {"size", 0},
            {"flags", 0},
            {"segment_count", 0}
        };

        DWORD segment_count = 0;
        memcpy(&segment_count, header->data() + 0x158, sizeof(DWORD));
        heap_info["segment_count"] = segment_count;
        if (segment_count == 0) segment_count = 1;

        DWORD heap_flags = 0;
        memcpy(&heap_flags, header->data() + 0x70, sizeof(DWORD));
        heap_info["flags"] = format_utils::format_address(heap_flags);

        duint heap_size = 0;
        memcpy(&heap_size, header->data() + 0x88, sizeof(duint));
        heap_info["size"] = heap_size;

        auto segments = nlohmann::json::array();
        auto chunks = nlohmann::json::array();
        constexpr size_t MAX_CHUNKS = 200;
#ifdef _WIN64
        constexpr size_t HEAP_GRANULARITY = 0x10;
#else
        constexpr size_t HEAP_GRANULARITY = 0x8;
#endif

        for (DWORD seg_idx = 0; seg_idx < segment_count && seg_idx < 128; ++seg_idx) {
            duint seg_addr = 0;
            size_t seg_ptr_offset = 0x2B0 + seg_idx * sizeof(duint);
            if (header->size() >= seg_ptr_offset + sizeof(duint)) {
                memcpy(&seg_addr, header->data() + seg_ptr_offset, sizeof(duint));
            }
            if (seg_addr == 0) continue;

            auto seg_hdr = bridge.read_memory(seg_addr, 0x80);
            if (!seg_hdr.has_value() || seg_hdr->size() < 0x80) continue;

            duint seg_base = 0;
            memcpy(&seg_base, seg_hdr->data() + 0x30, sizeof(duint));

            duint first_entry = 0;
            memcpy(&first_entry, seg_hdr->data() + 0x38, sizeof(duint));

            duint last_entry = 0;
            memcpy(&last_entry, seg_hdr->data() + 0x40, sizeof(duint));

            duint committed_pages = 0;
            memcpy(&committed_pages, seg_hdr->data() + 0x48, sizeof(duint));

            duint uncommitted_pages = 0;
            memcpy(&uncommitted_pages, seg_hdr->data() + 0x50, sizeof(duint));

            segments.push_back({
                {"base", format_utils::format_address(seg_base)},
                {"size", committed_pages + uncommitted_pages},
                {"committed", committed_pages},
                {"uncommitted", uncommitted_pages},
                {"first_entry", format_utils::format_address(first_entry)},
                {"last_entry", format_utils::format_address(last_entry)}
            });

            if (first_entry != 0 && chunks.size() < MAX_CHUNKS) {
                duint current = first_entry;
                size_t chunk_count = 0;
                while (current != 0 && current < last_entry + 0x1000 && chunk_count < MAX_CHUNKS) {
                    auto entry_hdr = bridge.read_memory(current, 0x10);
                    if (!entry_hdr.has_value() || entry_hdr->size() < 0x10) break;

                    uint16_t chunk_size = 0;
                    memcpy(&chunk_size, entry_hdr->data(), sizeof(uint16_t));

                    uint16_t prev_size = 0;
                    memcpy(&prev_size, entry_hdr->data() + 2, sizeof(uint16_t));

                    uint8_t flags = entry_hdr->data()[5];
                    uint8_t unused_bytes = entry_hdr->data()[6];
                    uint8_t seg_index = entry_hdr->data()[7];

                    std::string state = "free";
                    if (flags & 0x01) state = "busy";
                    if (flags & 0x04) {
                        if (state == "free") state = "last";
                        else state += "|last";
                    }

                    chunks.push_back({
                        {"address", format_utils::format_address(current)},
                        {"size", chunk_size},
                        {"state", state},
                        {"prev_size", prev_size},
                        {"flags", flags}
                    });

                    if (chunk_size < HEAP_GRANULARITY) break;
                    current += static_cast<duint>(chunk_size) * HEAP_GRANULARITY;
                    chunk_count++;
                }
            }
        }

        return s_http_response::ok({
            {"heap_info", heap_info},
            {"segments", segments},
            {"chunks", chunks}
        });
    });

    router.get("/api/heap/corruption", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto addr_str = req.get_query("address", "");
        if (addr_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto heap_base = format_utils::parse_address(addr_str);
        if (heap_base == 0) {
            return s_http_response::bad_request("Invalid heap address");
        }

        auto issues = nlohmann::json::array();
        bool is_corrupted = false;

        auto header = bridge.read_memory(heap_base, 0x200);
        if (!header.has_value() || header->size() < 0x200) {
            issues.push_back({
                {"type", "unreadable"},
                {"address", format_utils::format_address(heap_base)},
                {"description", "Cannot read heap header"}
            });
            is_corrupted = true;
        } else {
            DWORD heap_flags = 0;
            memcpy(&heap_flags, header->data() + 0x70, sizeof(DWORD));

            if (heap_flags & 0x80000000) {
                issues.push_back({
                    {"type", "invalid_flags"},
                    {"address", format_utils::format_address(heap_base)},
                    {"description", "Heap has unexpected flag bits set: " + format_utils::format_hex(heap_flags)}
                });
                is_corrupted = true;
            }

            DWORD segment_count = 0;
            memcpy(&segment_count, header->data() + 0x158, sizeof(DWORD));
            if (segment_count > 128) {
                issues.push_back({
                    {"type", "invalid_segment_count"},
                    {"address", format_utils::format_address(heap_base)},
                    {"description", "Segment count exceeds maximum: " + std::to_string(segment_count)}
                });
                is_corrupted = true;
            }

            for (DWORD i = 0; i < segment_count && i < 128; ++i) {
                duint seg_addr = 0;
                size_t seg_ptr_offset = 0x2B0 + i * sizeof(duint);
                if (header->size() >= seg_ptr_offset + sizeof(duint)) {
                    memcpy(&seg_addr, header->data() + seg_ptr_offset, sizeof(duint));
                }
                if (seg_addr != 0 && (seg_addr < heap_base || seg_addr > heap_base + 0x10000000)) {
                    issues.push_back({
                        {"type", "invalid_segment_pointer"},
                        {"address", format_utils::format_address(seg_addr)},
                        {"description", "Segment pointer out of reasonable heap range"}
                    });
                    is_corrupted = true;
                    break;
                }
            }

            for (DWORD i = 0; i < segment_count && i < 128; ++i) {
                duint seg_addr = 0;
                size_t seg_ptr_offset = 0x2B0 + i * sizeof(duint);
                if (header->size() >= seg_ptr_offset + sizeof(duint)) {
                    memcpy(&seg_addr, header->data() + seg_ptr_offset, sizeof(duint));
                }
                if (seg_addr == 0) continue;

                auto seg_hdr = bridge.read_memory(seg_addr, 0x80);
                if (!seg_hdr.has_value() || seg_hdr->size() < 0x80) continue;

                duint seg_sig = 0;
                memcpy(&seg_sig, seg_hdr->data() + 0x8, sizeof(duint));
                if (seg_sig != 0xEEFFEEFFEEFFEEFFULL) {
                    issues.push_back({
                        {"type", "invalid_segment_signature"},
                        {"address", format_utils::format_address(seg_addr)},
                        {"description", "Segment signature mismatch: " + format_utils::format_hex(seg_sig)}
                    });
                    is_corrupted = true;
                    break;
                }
            }
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(heap_base)},
            {"is_corrupted", is_corrupted},
            {"issues", issues}
        });
    });
}

} // namespace handlers
