#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <vector>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_patch_routes(c_http_router& router) {
    // GET /api/patches/list - List current patches
    router.get("/api/patches/list", [](const s_http_request&) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        size_t count = 0;
        DbgFunctions()->PatchEnum(nullptr, &count);

        auto patches = nlohmann::json::array();
        if (count > 0) {
            std::vector<DBGPATCHINFO> list(count);
            DbgFunctions()->PatchEnum(list.data(), &count);
            for (size_t i = 0; i < count; ++i) {
                patches.push_back({
                    {"module",   list[i].mod},
                    {"address",  format_utils::format_address(list[i].addr)},
                    {"old_byte", format_utils::format_bytes_compact(&list[i].oldbyte, 1)},
                    {"new_byte", format_utils::format_bytes_compact(&list[i].newbyte, 1)}
                });
            }
        }

        return s_http_response::ok({
            {"patches", patches},
            {"count",   patches.size()}
        });
    });

    // POST /api/patches/apply - Apply byte patch
    router.post("/api/patches/apply", [](const s_http_request& req) -> s_http_response {
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
            return s_http_response::bad_request("No valid bytes to patch");
        }

        // Read original bytes first
        auto original = bridge.read_memory(address, bytes.size());

        // Write the patch
        auto result = bridge.write_memory(address, bytes);
        if (!result.has_value()) {
            return s_http_response::internal_error(result.error());
        }

        nlohmann::json data = {
            {"address",       format_utils::format_address(address)},
            {"bytes_patched", bytes.size()},
            {"new_bytes",     format_utils::format_bytes_hex(bytes.data(), bytes.size())}
        };

        if (original.has_value()) {
            data["original_bytes"] = format_utils::format_bytes_hex(original->data(), original->size());
        }

        return s_http_response::ok(data);
    });

    // POST /api/patches/restore - Restore original bytes
    router.post("/api/patches/restore", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("address")) {
            return s_http_response::bad_request("Missing 'address' field");
        }

        auto address_str = body["address"].get<std::string>();

        // Use x64dbg's patch restore command
        auto cmd = "patchrestore " + address_str;
        bridge.exec_command(cmd);

        return s_http_response::ok({
            {"address", address_str},
            {"message", "Patch restore requested"}
        });
    });

    // POST /api/patches/export - Export patches in various formats (file, c_stub, python, x64dbg_script)
    router.post("/api/patches/export", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        auto format = body.value("format", "script"); // c_stub, python, x64dbg_script, file
        auto module_name = body.value("module", "");
        auto output_path = body.value("path", "");

        size_t count = 0;
        DbgFunctions()->PatchEnum(nullptr, &count);

        std::vector<DBGPATCHINFO> patches;
        if (count > 0) {
            patches.resize(count);
            DbgFunctions()->PatchEnum(patches.data(), &count);
        }

        // Filter by module if specified
        if (!module_name.empty()) {
            patches.erase(std::remove_if(patches.begin(), patches.end(), [&](const DBGPATCHINFO& p) {
                return std::string(p.mod) != module_name;
            }), patches.end());
        }

        if (format == "file") {
            if (output_path.empty()) {
                return s_http_response::bad_request("Missing 'path' field for binary file export");
            }
            char error[MAX_ERROR_SIZE] = {};
            int patched_count = DbgFunctions()->PatchFile(patches.data(), static_cast<int>(patches.size()), output_path.c_str(), error);
            if (patched_count < 0) {
                return s_http_response::internal_error(std::string("Failed to patch file: ") + error);
            }
            return s_http_response::ok({
                {"format",        "file"},
                {"output_path",   output_path},
                {"patches_count", patched_count},
                {"message",       "Successfully patched binary file on disk"}
            });
        }

        // Format code stubs
        std::string generated_code;
        if (format == "c_stub") {
            generated_code = "// Auto-generated x64dbg memory patch stub\n";
            generated_code += "void ApplyPatches(HANDLE hProcess) {\n";
            generated_code += "    SIZE_T written;\n";
            for (const auto& p : patches) {
                char buf[128];
                snprintf(buf, sizeof(buf), "    { uint8_t b = 0x%02X; WriteProcessMemory(hProcess, (LPVOID)0x%llX, &b, 1, &written); } // was 0x%02X\n",
                         p.newbyte, static_cast<unsigned long long>(p.addr), p.oldbyte);
                generated_code += buf;
            }
            generated_code += "}\n";
        } else if (format == "python" || format == "frida") {
            generated_code = "# Auto-generated x64dbg patch script (Frida / Python)\n";
            generated_code += "patches = [\n";
            for (const auto& p : patches) {
                char buf[128];
                snprintf(buf, sizeof(buf), "    {\"addr\": 0x%llX, \"new\": 0x%02X, \"old\": 0x%02X, \"mod\": \"%s\"},\n",
                         static_cast<unsigned long long>(p.addr), p.newbyte, p.oldbyte, p.mod);
                generated_code += buf;
            }
            generated_code += "]\n\n";
            generated_code += "for p in patches:\n";
            generated_code += "    # Frida: Memory.protect(ptr(p['addr']), 1, 'rwx'); ptr(p['addr']).writeU8(p['new'])\n";
            generated_code += "    print(f\"Patching {hex(p['addr'])} -> {hex(p['new'])}\")\n";
        } else {
            // Default: x64dbg script format
            generated_code = "// x64dbg Patch Script\n";
            for (const auto& p : patches) {
                char buf[128];
                snprintf(buf, sizeof(buf), "setbyte 0x%llX, 0x%02X // module: %s, original: 0x%02X\n",
                         static_cast<unsigned long long>(p.addr), p.newbyte, p.mod, p.oldbyte);
                generated_code += buf;
            }
        }

        return s_http_response::ok({
            {"format",        format},
            {"patches_count", patches.size()},
            {"module",        module_name},
            {"code",          generated_code}
        });
    });
}

} // namespace handlers
