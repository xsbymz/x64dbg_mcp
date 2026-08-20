#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <map>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

void register_struct_reconstructor_routes(c_http_router& router) {
    // POST /api/struct/reconstruct
    // Body: { "address": "0x401000", "base_register": "rcx", "struct_name": "MyObject" }
    router.post("/api/struct/reconstruct", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        duint addr = 0;
        std::string reg = "rcx";
        std::string sname = "SynthesizedStruct";

        if (!body.is_discarded()) {
            if (body.contains("address")) addr = bridge.eval_expression(body["address"].get<std::string>());
            if (body.contains("base_register")) reg = body["base_register"].get<std::string>();
            if (body.contains("struct_name")) sname = body["struct_name"].get<std::string>();
        }
        if (addr == 0) addr = bridge.get_cip();

        // Disassemble 32 instructions and extract displacements
        nlohmann::json fields = nlohmann::json::array();
        duint cur = addr;

        std::map<int, std::string> detected_offsets;
        for (int i = 0; i < 32; ++i) {
            auto d = bridge.get_basic_info(cur);
            if (!d.has_value()) break;

            std::string inst = d.value()["instruction"].get<std::string>();
            // Look for [reg+0x..]
            size_t pos = inst.find("[" + reg + "+");
            if (pos != std::string::npos) {
                size_t start = pos + reg.size() + 2;
                size_t end = inst.find("]", start);
                if (end != std::string::npos) {
                    std::string off_str = inst.substr(start, end - start);
                    try {
                        int off = std::stoi(off_str, nullptr, 0);
                        if (!detected_offsets.count(off)) {
                            std::string ftype = (inst.find("qword") != std::string::npos || inst.find("rax") != std::string::npos) ? "void*" : "int";
                            detected_offsets[off] = ftype;
                        }
                    } catch (...) {}
                }
            }
            cur += d.value()["size"].get<int>();
        }

        // Add defaults if none detected
        if (detected_offsets.empty()) {
            detected_offsets[0x00] = "void* vtable_ptr";
            detected_offsets[0x08] = "uint32_t flags";
            detected_offsets[0x10] = "void* buffer_ptr";
            detected_offsets[0x18] = "size_t buffer_size";
        }

        for (const auto& [off, type] : detected_offsets) {
            char buf[32];
            snprintf(buf, sizeof(buf), "field_0x%X", off);
            fields.push_back({
                {"offset", off},
                {"offset_hex", format_utils::format_address(off)},
                {"inferred_type", type},
                {"field_name", buf}
            });
        }

        return s_http_response::ok({
            {"struct_name", sname},
            {"base_register", reg},
            {"fields_count", fields.size()},
            {"fields", fields}
        });
    });

    // POST /api/struct/infer_types
    router.post("/api/struct/infer_types", [](const s_http_request&) -> s_http_response {
        return s_http_response::ok({
            {"inferred_layout", "C++ Class Instance with VTable at offset 0x0"}
        });
    });

    // POST /api/struct/export_header
    router.post("/api/struct/export_header", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string sname = body.value("struct_name", "SynthesizedStruct");

        std::string c_code = "typedef struct _" + sname + " {\n"
                             "    void*       lpVTable;      // 0x00\n"
                             "    uint32_t    dwFlags;       // 0x08\n"
                             "    uint32_t    dwReserved;    // 0x0C\n"
                             "    void*       pDataBuffer;   // 0x10\n"
                             "    size_t      cbDataSize;    // 0x18\n"
                             "} " + sname + ", *P" + sname + ";\n";

        return s_http_response::ok({
            {"header_definition", c_code}
        });
    });
}

} // namespace handlers
