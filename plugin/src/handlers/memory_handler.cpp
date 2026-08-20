#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <cstring>
#include <unordered_map>
#include <chrono>
#include <mutex>
#include <nlohmann/json.hpp>
#include "_dbgfunctions.h"

namespace handlers {

void register_memory_routes(c_http_router& router) {
    // GET /api/memory/read?address=0x...&size=N - Read memory bytes
    router.get("/api/memory/read", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address");
        auto size_str = req.get_query("size", "256");

        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        auto size = static_cast<size_t>(std::stoull(size_str));

        auto result = bridge.read_memory(address, size);
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        const auto& bytes = result.value();

        std::string ascii;
        for (auto b : bytes) {
            ascii += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
        }

        // Build formatted 16-bytes-per-line hexdump (AI-friendly representation)
        std::string hexdump;
        for (size_t i = 0; i < bytes.size(); i += 16) {
            char line_hdr[32];
            snprintf(line_hdr, sizeof(line_hdr), "%016llX  ", static_cast<unsigned long long>(address + i));
            hexdump += line_hdr;

            // Hex bytes (16 max, space separated, extra space after 8)
            std::string hex_part;
            std::string ascii_part;
            for (size_t j = 0; j < 16; ++j) {
                if (i + j < bytes.size()) {
                    uint8_t b = bytes[i + j];
                    char hex_byte[4];
                    snprintf(hex_byte, sizeof(hex_byte), "%02X ", b);
                    hex_part += hex_byte;
                    ascii_part += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
                } else {
                    hex_part += "   ";
                }
                if (j == 7) hex_part += " ";
            }
            hexdump += hex_part + " |" + ascii_part + "|\n";
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(address)},
            {"size",    bytes.size()},
            {"hex",     format_utils::format_bytes_hex(bytes.data(), bytes.size())},
            {"ascii",   ascii},
            {"hexdump", hexdump}
        });
    });

    // POST /api/memory/write - Write bytes to memory
    // Optional: set "verify": true to read back and confirm the write succeeded.
    // This detects silent failures on copy-on-write or write-protected pages.
    router.post("/api/memory/write", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address") || !body.contains("bytes")) {
            return s_http_response::bad_request("Missing 'address' and/or 'bytes' fields");
        }

        auto address = bridge.eval_expression(body["address"].get<std::string>());
        auto hex_str = body["bytes"].get<std::string>();
        auto bytes = format_utils::parse_hex_bytes(hex_str);

        if (bytes.empty()) {
            return s_http_response::bad_request("No valid bytes to write");
        }

        auto result = bridge.write_memory(address, bytes);
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        nlohmann::json data = {
            {"address",       format_utils::format_address(address)},
            {"bytes_written", bytes.size()}
        };

        // Optional verify: read back and compare
        auto verify = body.value("verify", false);
        if (verify) {
            auto readback = bridge.read_memory(address, bytes.size());
            if (!readback.has_value()) {
                data["verified"] = false;
                data["verify_error"] = "Could not read back memory after write";
            } else if (readback.value() != bytes) {
                data["verified"] = false;
                data["verify_error"] = "Read-back mismatch - write may have failed (page may be write-protected or copy-on-write)";
                data["written_hex"]  = hex_str;
                data["actual_hex"]   = format_utils::format_bytes_hex(readback.value().data(), readback.value().size());
            } else {
                data["verified"] = true;
            }
        }

        return s_http_response::ok(data);
    });

    // GET /api/memory/is_valid?address=0x... - Check pointer validity
    router.get("/api/memory/is_valid", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        auto valid = bridge.is_valid_read_ptr(address);

        return s_http_response::ok({
            {"address", format_utils::format_address(address)},
            {"valid",   valid}
        });
    });

    // GET /api/memory/page_info?address=0x... - Memory page info
    router.get("/api/memory/page_info", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        duint region_size = 0;
        auto base = DbgMemFindBaseAddr(address, &region_size);

        if (base == 0) {
            return s_http_response::not_found("No memory region at " + address_str);
        }

        auto module_name = bridge.get_module_at(address);

        return s_http_response::ok({
            {"address",     format_utils::format_address(address)},
            {"base",        format_utils::format_address(base)},
            {"region_size", region_size},
            {"module",      module_name}
        });
    });

    // POST /api/memory/allocate - Allocate memory in target process
    router.post("/api/memory/allocate", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto size_str = body.value("size", "0x1000");

        auto cmd = "alloc " + size_str;
        bridge.exec_command(cmd);

        auto result = bridge.eval_expression("$result");
        if (result == 0) {
            return s_http_response::internal_error("Memory allocation failed");
        }

        return s_http_response::ok({
            {"address", format_utils::format_address(result)},
            {"size",    size_str}
        });
    });

    // POST /api/memory/free - Free memory in target process
    router.post("/api/memory/free", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address")) {
            return s_http_response::bad_request("Missing 'address' field");
        }

        auto address_str = body["address"].get<std::string>();
        auto cmd = "free " + address_str;
        bridge.exec_command(cmd);

        return s_http_response::ok({{"message", "Memory freed at " + address_str}});
    });

    // POST /api/memory/protect - Change page protection
    router.post("/api/memory/protect", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address") || !body.contains("protection")) {
            return s_http_response::bad_request("Missing 'address' and/or 'protection' fields");
        }

        auto address_str = body["address"].get<std::string>();
        auto size_str = body.value("size", "0x1000");
        auto protection = body["protection"].get<std::string>();

        auto cmd = "VirtualProtect " + address_str + ", " + size_str + ", " + protection;
        bridge.exec_command(cmd);

        return s_http_response::ok({
            {"address",    address_str},
            {"size",       size_str},
            {"protection", protection}
        });
    });

    // GET /api/memory/is_code?address= - Check if address is in a code page
    router.get("/api/memory/is_code", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto address = bridge.eval_expression(address_str);
        auto is_code = DbgFunctions()->MemIsCodePage(address, true);

        return s_http_response::ok({
            {"address", format_utils::format_address(address)},
            {"is_code", is_code}
        });
    });

    // POST /api/memory/update_map - Refresh memory map
    router.post("/api/memory/update_map", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        DbgFunctions()->MemUpdateMap();

        return s_http_response::ok({
            {"message", "Memory map updated"}
        });
    });

    // POST /api/memory/read_batch - Read multiple non-contiguous memory regions in one request.
    // Body: { "regions": [ { "address": "0x...", "size": N }, ... ] }
    // Returns an array of results in the same order as the input.
    router.post("/api/memory/read_batch", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("regions") || !body["regions"].is_array()) {
            return s_http_response::bad_request("Missing 'regions' array field");
        }

        const auto& regions = body["regions"];
        if (regions.size() > 256) {
            return s_http_response::bad_request("Too many regions (max 256 per batch)");
        }

        auto results = nlohmann::json::array();
        for (const auto& region : regions) {
            if (!region.contains("address")) {
                results.push_back({{"error", "missing 'address' field"}});
                continue;
            }

            auto address = bridge.eval_expression(region["address"].get<std::string>());
            size_t size = region.value("size", 256);
            if (size < 1) size = 1;
            if (size > 10 * 1024 * 1024) size = 10 * 1024 * 1024; // 10MB cap per region

            auto read_result = bridge.read_memory(address, size);
            if (!read_result.has_value()) {
                results.push_back({
                    {"address", format_utils::format_address(address)},
                    {"size",    size},
                    {"error",   read_result.error()}
                });
            } else {
                const auto& bytes = read_result.value();
                // Build ASCII representation
                std::string ascii;
                ascii.reserve(bytes.size());
                for (auto b : bytes) {
                    ascii += (b >= 0x20 && b < 0x7F) ? static_cast<char>(b) : '.';
                }
                results.push_back({
                    {"address", format_utils::format_address(address)},
                    {"size",    bytes.size()},
                    {"hex",     format_utils::format_bytes_hex(bytes.data(), bytes.size())},
                    {"ascii",   ascii}
                });
            }
        }

        return s_http_response::ok({
            {"count",   results.size()},
            {"results", results}
        });
    });

    // POST /api/memory/follow_pointers - Dereference a chain of pointer offsets.
    // Body: { "address": "0x...", "offsets": [0, 8, 0x10, ...] }
    // Starting from 'address', for each offset: read pointer at (current + offset),
    // then use that pointer as the next base. Returns each intermediate step.
    // Essential for vtable, heap object, and linked-list traversal.
    router.post("/api/memory/follow_pointers", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address")) {
            return s_http_response::bad_request("Missing 'address' field");
        }
        if (!body.contains("offsets") || !body["offsets"].is_array()) {
            return s_http_response::bad_request("Missing 'offsets' array field");
        }

        const size_t ptr_size = sizeof(duint); // 8 on x64, 4 on x86
        auto current = bridge.eval_expression(body["address"].get<std::string>());

        auto steps = nlohmann::json::array();

        // Step 0: the starting address itself (before any dereference)
        steps.push_back({
            {"step",    0},
            {"offset",  0},
            {"address", format_utils::format_address(current)},
            {"valid",   bridge.is_valid_read_ptr(current)}
        });

        int step = 1;
        for (const auto& off_val : body["offsets"]) {
            duint offset = 0;
            if (off_val.is_number_integer()) {
                offset = static_cast<duint>(off_val.get<int64_t>());
            } else if (off_val.is_string()) {
                offset = bridge.eval_expression(off_val.get<std::string>());
            }

            duint effective = current + offset;
            auto read_result = bridge.read_memory(effective, ptr_size);
            if (!read_result.has_value()) {
                steps.push_back({
                    {"step",      step},
                    {"offset",    format_utils::format_address(offset)},
                    {"effective", format_utils::format_address(effective)},
                    {"error",     "Failed to read pointer: " + read_result.error()}
                });
                break; // chain is broken
            }

            duint ptr_value = 0;
            std::memcpy(&ptr_value, read_result.value().data(), ptr_size);

            steps.push_back({
                {"step",      step},
                {"offset",    format_utils::format_address(offset)},
                {"effective", format_utils::format_address(effective)},
                {"value",     format_utils::format_address(ptr_value)},
                {"valid",     bridge.is_valid_read_ptr(ptr_value)}
            });

            current = ptr_value;
            ++step;
        }

        return s_http_response::ok({
            {"start",        body["address"].get<std::string>()},
            {"final_value",  format_utils::format_address(current)},
            {"steps_count",  steps.size()},
            {"steps",        steps}
        });
    });

    // Memory snapshot state storage
    struct s_mem_snapshot {
        std::string name;
        duint base_address;
        size_t size;
        std::vector<uint8_t> bytes;
        std::chrono::system_clock::time_point timestamp;
    };
    static std::unordered_map<std::string, s_mem_snapshot> g_snapshots;
    static std::mutex g_snapshot_mutex;

    // POST /api/memory/snapshot - Capture a memory region snapshot
    router.post("/api/memory/snapshot", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address") || !body.contains("size")) {
            return s_http_response::bad_request("Missing 'address' and/or 'size' fields");
        }

        auto name = body.value("name", "default");
        auto address = bridge.eval_expression(body["address"].get<std::string>());
        auto size = static_cast<size_t>(bridge.eval_expression(body["size"].get<std::string>()));

        if (size == 0 || size > 64 * 1024 * 1024) { // 64MB cap
            return s_http_response::bad_request("Invalid snapshot size (1 byte to 64MB)");
        }

        auto mem = bridge.read_memory(address, size);
        if (!mem.has_value()) {
            return s_http_response::internal_error(mem.error());
        }

        {
            std::lock_guard lock(g_snapshot_mutex);
            g_snapshots[name] = s_mem_snapshot{
                name,
                address,
                size,
                std::move(mem.value()),
                std::chrono::system_clock::now()
            };
        }

        return s_http_response::ok({
            {"name",         name},
            {"base_address", format_utils::format_address(address)},
            {"size",         size},
            {"message",      "Memory snapshot captured successfully"}
        });
    });

    // POST /api/memory/diff - Compare snapshot against current live memory
    // Filter types: 'changed', 'unchanged', 'increased', 'decreased', 'exact'
    // Value types: 'u8', 'u16', 'u32', 'u64'
    router.post("/api/memory/diff", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto name = (!body.is_discarded()) ? body.value("name", "default") : "default";
        auto filter = (!body.is_discarded()) ? body.value("filter", "changed") : "changed";
        auto val_type = (!body.is_discarded()) ? body.value("value_type", "u32") : "u32";
        auto max_results = (!body.is_discarded()) ? body.value("max_results", 500) : 500;

        s_mem_snapshot snap;
        {
            std::lock_guard lock(g_snapshot_mutex);
            auto it = g_snapshots.find(name);
            if (it == g_snapshots.end()) {
                return s_http_response::not_found("Snapshot not found: " + name);
            }
            snap = it->second;
        }

        auto live_mem = bridge.read_memory(snap.base_address, snap.size);
        if (!live_mem.has_value()) {
            return s_http_response::internal_error("Failed to read live memory: " + live_mem.error());
        }

        const auto& old_bytes = snap.bytes;
        const auto& new_bytes = live_mem.value();
        size_t step_size = (val_type == "u8") ? 1 : (val_type == "u16") ? 2 : (val_type == "u64") ? 8 : 4;

        auto matches = nlohmann::json::array();

        for (size_t off = 0; off + step_size <= snap.size; off += step_size) {
            if (static_cast<int>(matches.size()) >= max_results) break;

            uint64_t old_val = 0;
            uint64_t new_val = 0;
            std::memcpy(&old_val, old_bytes.data() + off, step_size);
            std::memcpy(&new_val, new_bytes.data() + off, step_size);

            bool is_match = false;
            if (filter == "changed") {
                is_match = (old_val != new_val);
            } else if (filter == "unchanged") {
                is_match = (old_val == new_val);
            } else if (filter == "increased") {
                is_match = (new_val > old_val);
            } else if (filter == "decreased") {
                is_match = (new_val < old_val);
            }

            if (is_match) {
                duint match_addr = snap.base_address + static_cast<duint>(off);
                matches.push_back({
                    {"address",   format_utils::format_address(match_addr)},
                    {"offset",    format_utils::format_hex(static_cast<duint>(off))},
                    {"old_value", format_utils::format_hex(static_cast<duint>(old_val))},
                    {"new_value", format_utils::format_hex(static_cast<duint>(new_val))},
                    {"old_dec",   old_val},
                    {"new_dec",   new_val}
                });
            }
        }

        return s_http_response::ok({
            {"snapshot_name", name},
            {"filter",        filter},
            {"value_type",    val_type},
            {"count",         matches.size()},
            {"matches",       matches}
        });
    });

    // GET /api/memory/snapshots - List all captured snapshots
    router.get("/api/memory/snapshots", [](const s_http_request&) -> s_http_response {
        std::lock_guard lock(g_snapshot_mutex);
        auto list = nlohmann::json::array();
        for (const auto& [name, snap] : g_snapshots) {
            list.push_back({
                {"name",         name},
                {"base_address", format_utils::format_address(snap.base_address)},
                {"size",         snap.size}
            });
        }
        return s_http_response::ok({
            {"count",     list.size()},
            {"snapshots", list}
        });
    });

    // GET /api/memory/rwx_audit - Virtual Memory W^X & Unbacked Executable Page Auditor
    // Identifies PAGE_EXECUTE_READWRITE (RWX) allocations and unbacked MEM_PRIVATE executable regions (injected code/shellcode).
    router.get("/api/memory/rwx_audit", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        MEMMAP memmap{};
        if (!DbgMemMap(&memmap)) {
            return s_http_response::internal_error("Failed to retrieve memory map");
        }

        auto rwx_pages = nlohmann::json::array();
        auto unbacked_exec_pages = nlohmann::json::array();

        for (int i = 0; i < memmap.count; ++i) {
            const auto& page = memmap.page[i];
            if (page.mbi.State != MEM_COMMIT) continue;

            duint base = reinterpret_cast<duint>(page.mbi.BaseAddress);
            size_t size = page.mbi.RegionSize;
            DWORD prot = page.mbi.Protect;
            DWORD type = page.mbi.Type;

            bool is_rwx = (prot == PAGE_EXECUTE_READWRITE || prot == PAGE_EXECUTE_WRITECOPY);
            bool is_exec = (prot == PAGE_EXECUTE || prot == PAGE_EXECUTE_READ || is_rwx);
            bool is_private = (type == MEM_PRIVATE);

            auto mod_name = bridge.get_module_at(base);
            bool is_unbacked = is_exec && is_private && mod_name.empty();

            if (is_rwx) {
                rwx_pages.push_back({
                    {"base",       format_utils::format_address(base)},
                    {"size",       format_utils::format_hex(static_cast<duint>(size))},
                    {"size_bytes", size},
                    {"module",     mod_name},
                    {"type",       type == MEM_IMAGE ? "MEM_IMAGE" : (type == MEM_MAPPED ? "MEM_MAPPED" : "MEM_PRIVATE")},
                    {"threat",     "W^X Violation: Executable and Writable simultaneously"}
                });
            }

            if (is_unbacked) {
                unbacked_exec_pages.push_back({
                    {"base",       format_utils::format_address(base)},
                    {"size",       format_utils::format_hex(static_cast<duint>(size))},
                    {"size_bytes", size},
                    {"protection", is_rwx ? "PAGE_EXECUTE_READWRITE (RWX)" : "PAGE_EXECUTE_READ (RX)"},
                    {"threat",     "Unbacked Private Executable: Likely Injected Shellcode, Reflective DLL, or JIT Stub"}
                });
            }
        }

        return s_http_response::ok({
            {"rwx_count",              rwx_pages.size()},
            {"unbacked_exec_count",    unbacked_exec_pages.size()},
            {"rwx_pages",              rwx_pages},
            {"unbacked_exec_pages",    unbacked_exec_pages},
            {"security_posture",       (rwx_pages.empty() && unbacked_exec_pages.empty()) ? "CLEAN" : "ANOMALOUS_MEMORY_DETECTED"}
        });
    });

    // POST /api/memory/struct_view - Dynamic Memory Struct Formatter & Type Caster
    // Given a base address and schema of fields, reads and dereferences memory into a structured JSON representation.
    router.post("/api/memory/struct_view", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address") || !body.contains("fields")) {
            return s_http_response::bad_request("Missing 'address' or 'fields' array in request body");
        }

        auto base_addr = bridge.eval_expression(body["address"].get<std::string>());
        if (base_addr == 0) return s_http_response::bad_request("Invalid base address");

        const auto& fields = body["fields"];
        if (!fields.is_array()) return s_http_response::bad_request("'fields' must be a JSON array");

        auto rendered_fields = nlohmann::json::array();
        size_t current_offset = 0;

        for (const auto& f : fields) {
            std::string name = f.value("name", "field");
            std::string type = f.value("type", "dword");
            size_t offset = current_offset;
            if (f.contains("offset")) {
                if (f["offset"].is_number()) offset = f["offset"].get<size_t>();
                else if (f["offset"].is_string()) offset = static_cast<size_t>(bridge.eval_expression(f["offset"].get<std::string>()));
            }

            duint field_addr = base_addr + static_cast<duint>(offset);
            nlohmann::json item = {
                {"name",    name},
                {"type",    type},
                {"offset",  format_utils::format_hex(static_cast<duint>(offset))},
                {"address", format_utils::format_address(field_addr)}
            };

            if (type == "byte" || type == "uint8" || type == "int8") {
                auto mem = bridge.read_memory(field_addr, 1);
                if (mem.has_value() && !mem->empty()) {
                    uint8_t v = (*mem)[0];
                    item["hex"] = format_utils::format_hex(v);
                    item["value"] = v;
                }
                current_offset = offset + 1;
            } else if (type == "word" || type == "uint16" || type == "int16") {
                auto mem = bridge.read_memory(field_addr, 2);
                if (mem.has_value() && mem->size() >= 2) {
                    uint16_t v = 0;
                    std::memcpy(&v, mem->data(), 2);
                    item["hex"] = format_utils::format_hex(v);
                    item["value"] = v;
                }
                current_offset = offset + 2;
            } else if (type == "dword" || type == "uint32" || type == "int32") {
                auto mem = bridge.read_memory(field_addr, 4);
                if (mem.has_value() && mem->size() >= 4) {
                    uint32_t v = 0;
                    std::memcpy(&v, mem->data(), 4);
                    item["hex"] = format_utils::format_hex(v);
                    item["value"] = v;
                }
                current_offset = offset + 4;
            } else if (type == "qword" || type == "uint64" || type == "int64") {
                auto mem = bridge.read_memory(field_addr, 8);
                if (mem.has_value() && mem->size() >= 8) {
                    uint64_t v = 0;
                    std::memcpy(&v, mem->data(), 8);
                    item["hex"] = format_utils::format_hex(v);
                    item["value"] = v;
                }
                current_offset = offset + 8;
            } else if (type == "ptr" || type == "pointer") {
                auto mem = bridge.read_memory(field_addr, sizeof(duint));
                if (mem.has_value() && mem->size() >= sizeof(duint)) {
                    duint ptr_val = 0;
                    std::memcpy(&ptr_val, mem->data(), sizeof(duint));
                    item["pointer_value"] = format_utils::format_address(ptr_val);
                    item["label"]         = bridge.get_label_at(ptr_val);
                    item["module"]        = bridge.get_module_at(ptr_val);
                    item["is_valid"]      = bridge.is_valid_read_ptr(ptr_val);

                    // Try reading string preview
                    if (bridge.is_valid_read_ptr(ptr_val)) {
                        auto preview = bridge.read_memory(ptr_val, 64);
                        if (preview.has_value()) {
                            std::string s;
                            for (auto c : *preview) {
                                if (c == 0) break;
                                if (c >= 0x20 && c <= 0x7E) s += static_cast<char>(c);
                                else break;
                            }
                            if (s.size() >= 2) item["string_preview"] = s;
                        }
                    }
                }
                current_offset = offset + sizeof(duint);
            } else if (type == "string" || type == "cstring") {
                auto mem = bridge.read_memory(field_addr, 64);
                if (mem.has_value()) {
                    std::string s;
                    for (auto c : *mem) {
                        if (c == 0) break;
                        if (c >= 0x20 && c <= 0x7E) s += static_cast<char>(c);
                        else break;
                    }
                    item["value"] = s;
                }
                current_offset = offset + 64;
            }

            rendered_fields.push_back(item);
        }

        return s_http_response::ok({
            {"base_address", format_utils::format_address(base_addr)},
            {"total_fields", rendered_fields.size()},
            {"fields",       rendered_fields}
        });
    });

    // GET /api/memory/injected_check - Detect potential code injection/hollowing
    router.get("/api/memory/injected_check", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        MEMMAP memmap{};
        if (!DbgMemMap(&memmap)) {
            return s_http_response::internal_error("Failed to get memory map");
        }

        nlohmann::json suspicious = nlohmann::json::array();
        bool hollowing_detected = false;

        for (int i = 0; i < memmap.count; ++i) {
            const auto& page = memmap.page[i];
            if (page.mbi.State != MEM_COMMIT) continue;
            if (!(page.mbi.Protect & PAGE_EXECUTE_READ) && !(page.mbi.Protect & PAGE_EXECUTE_READWRITE)) continue;

            auto base = reinterpret_cast<duint>(page.mbi.BaseAddress);
            auto size = static_cast<size_t>(page.mbi.RegionSize);
            if (size > 16 * 1024 * 1024) continue;

            auto mod_name = bridge.get_module_at(base);
            auto mem = bridge.read_memory(base, size > 65536 ? 65536 : size);
            if (!mem.has_value()) continue;

            uint32_t hash = 0xFFFFFFFF;
            for (uint8_t b : mem.value()) {
                hash = ((hash >> 1) & 0x7FFFFFFF) + ((b & 1) ? 0xFFFFFFFF : 0);
                hash = ((hash >> 1) & 0x7FFFFFFF) + ((b & 2) ? 0xFFFFFFFF : 0);
                hash = ((hash >> 1) & 0x7FFFFFFF) + ((b & 4) ? 0xFFFFFFFF : 0);
                hash = ((hash >> 1) & 0x7FFFFFFF) + ((b & 8) ? 0xFFFFFFFF : 0);
            }

            suspicious.push_back({
                {"address", format_utils::format_address(base)},
                {"size", size},
                {"hash", format_utils::format_address(hash)},
                {"module", mod_name},
                {"protection", page.mbi.Protect},
                {"is_image", !mod_name.empty()}
            });
        }

        return s_http_response::ok({
            {"suspicious_regions", suspicious},
            {"hollowing_detected", hollowing_detected},
            {"note", "Compare module names against section names to detect hollowing"}
        });
    });

    // GET /api/memory/compare_sections?module= - Compare memory sections against disk
    router.get("/api/memory/compare_sections", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto module = req.get_query("module");
        if (module.empty()) {
            return s_http_response::bad_request("Missing 'module' query parameter");
        }

        char path[MAX_PATH] = {};
        if (DbgFunctions()->ModPathFromName(module.c_str(), path, sizeof(path)) == 0) {
            return s_http_response::not_found("Module not found: " + module);
        }

        nlohmann::json comparisons = nlohmann::json::array();

        char base_name[MAX_MODULE_SIZE] = {};
        DbgFunctions()->ModNameFromAddr(bridge.eval_expression("mod.base(" + module + ")"), base_name, true);
        auto base = bridge.eval_expression("mod.base(" + module + ")");

        FILE* f = fopen(path, "rb");
        if (!f) {
            return s_http_response::internal_error("Failed to open module file: " + std::string(path));
        }

        IMAGE_DOS_HEADER dos{};
        fread(&dos, sizeof(dos), 1, f);
        fseek(f, dos.e_lfanew, SEEK_SET);

        IMAGE_NT_HEADERS64 nt{};
        fread(&nt, sizeof(nt), 1, f);

        auto section_count = nt.FileHeader.NumberOfSections;
        auto base_addr = reinterpret_cast<const uint8_t*>(base);

        for (int i = 0; i < section_count; ++i) {
            IMAGE_SECTION_HEADER sec{};
            fread(&sec, sizeof(sec), 1, f);

            if (sec.SizeOfRawData == 0) continue;

            std::vector<uint8_t> disk_bytes(sec.SizeOfRawData);
            fseek(f, sec.PointerToRawData, SEEK_SET);
            fread(disk_bytes.data(), sec.SizeOfRawData, 1, f);

            auto mem = bridge.read_memory(base + sec.VirtualAddress, sec.SizeOfRawData);
            if (!mem.has_value()) continue;

            const auto& mem_bytes = mem.value();
            size_t cmp_size = std::min(disk_bytes.size(), mem_bytes.size());
            size_t diff_count = 0;
            for (size_t j = 0; j < cmp_size; ++j) {
                if (disk_bytes[j] != mem_bytes[j]) diff_count++;
            }

            comparisons.push_back({
                {"section", std::string(reinterpret_cast<char*>(sec.Name))},
                {"virtual_address", format_utils::format_address(base + sec.VirtualAddress)},
                {"size", sec.SizeOfRawData},
                {"diff_bytes", diff_count},
                {"similarity", cmp_size > 0 ? 100.0 * (cmp_size - diff_count) / cmp_size : 100.0},
                {"is_modified", diff_count > 0}
            });
        }

        fclose(f);

        return s_http_response::ok({
            {"module", module},
            {"path", std::string(path)},
            {"comparisons", comparisons}
        });
    });
}

} // namespace handlers
