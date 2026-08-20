#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <string>
#include <vector>
#include <algorithm>
#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "bridgelist.h"
#include "_scriptapi_module.h"

namespace handlers {

// ---------------------------------------------------------------------------
// Find VA of a string literal in a loaded module's sections.
// Returns all matching VAs (may appear multiple times if string is deduplicated).
// ---------------------------------------------------------------------------
static std::vector<duint> find_string_vas(c_bridge_executor& bridge,
                                           const std::string& mod_name,
                                           const std::string& target,
                                           bool case_sensitive) {
    std::vector<duint> result;
    if (target.empty() || mod_name.empty()) return result;

    auto base = bridge.get_module_base(mod_name);
    if (base == 0) return result;

    auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + mod_name + ")"));
    if (size == 0) return result;

    // Scan in 4MB chunks
    constexpr size_t kChunk = 4 * 1024 * 1024;
    std::string t_lower = target;
    if (!case_sensitive)
        std::transform(t_lower.begin(), t_lower.end(), t_lower.begin(), ::tolower);

    for (size_t off = 0; off < size; off += kChunk) {
        size_t chunk = std::min(kChunk, size - off);
        auto mem = bridge.read_memory(base + off, chunk);
        if (!mem.has_value()) continue;

        const auto& data = mem.value();
        // Search for both ASCII and wide (UTF-16LE) occurrences
        for (size_t i = 0; i + target.size() <= data.size(); ++i) {
            // ASCII match
            bool match_ascii = true;
            for (size_t k = 0; k < target.size(); ++k) {
                char dc = static_cast<char>(data[i + k]);
                char tc = target[k];
                if (!case_sensitive) {
                    dc = static_cast<char>(std::tolower(static_cast<unsigned char>(dc)));
                    tc = static_cast<char>(std::tolower(static_cast<unsigned char>(tc)));
                }
                if (dc != tc) { match_ascii = false; break; }
            }
            if (match_ascii && (i + target.size() >= data.size() || data[i + target.size()] == '\0')) {
                result.push_back(base + off + i);
            }
        }

        // Wide (UTF-16LE) match: each char is 2 bytes
        if (data.size() >= target.size() * 2) {
            for (size_t i = 0; i + target.size() * 2 <= data.size(); i += 2) {
                bool match_wide = true;
                for (size_t k = 0; k < target.size(); ++k) {
                    if (data[i + k * 2 + 1] != 0) { match_wide = false; break; }
                    char dc = static_cast<char>(data[i + k * 2]);
                    char tc = target[k];
                    if (!case_sensitive) {
                        dc = static_cast<char>(std::tolower(static_cast<unsigned char>(dc)));
                        tc = static_cast<char>(std::tolower(static_cast<unsigned char>(tc)));
                    }
                    if (dc != tc) { match_wide = false; break; }
                }
                if (match_wide &&
                    (i + target.size() * 2 + 1 >= data.size() ||
                     (data[i + target.size() * 2] == 0 && data[i + target.size() * 2 + 1] == 0))) {
                    result.push_back(base + off + i);
                }
            }
        }
    }

    return result;
}

// ---------------------------------------------------------------------------

void register_stringxref_routes(c_http_router& router) {

    // GET /api/stringxref/find?value=CreateFile&module=kernel32.dll&case=true
    // Find all xrefs to instructions that reference a given string literal.
    router.get("/api/stringxref/find", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto value   = req.get_query("value", "");
        auto module  = req.get_query("module", "");
        auto case_s  = (req.get_query("case", "false") == "true");

        if (value.empty()) {
            return s_http_response::bad_request("Missing 'value' query parameter");
        }
        if (value.size() > 512) {
            return s_http_response::bad_request("Search value too long (max 512 chars)");
        }

        // If no module specified, use the module at CIP
        if (module.empty()) {
            module = bridge.get_module_at(bridge.eval_expression("cip"));
        }
        if (module.empty()) {
            return s_http_response::bad_request("Could not determine target module. Pass ?module=name.dll");
        }

        // Step 1: find all VAs of the string literal
        auto str_vas = find_string_vas(bridge, module, value, case_s);

        if (str_vas.empty()) {
            return s_http_response::ok({
                {"value",      value},
                {"module",     module},
                {"string_vas", nlohmann::json::array()},
                {"xrefs",      nlohmann::json::array()},
                {"count",      0}
            });
        }

        // Step 2: for each string VA, find all xrefs pointing to it
        auto xref_arr = nlohmann::json::array();
        auto str_va_arr = nlohmann::json::array();

        for (auto str_va : str_vas) {
            str_va_arr.push_back(format_utils::format_address(str_va));

            auto xref_count = DbgGetXrefCountAt(str_va);
            if (xref_count == 0) continue;

            XREF_INFO info{};
            if (!DbgXrefGet(str_va, &info)) continue;

            for (duint i = 0; i < info.refcount; ++i) {
                const auto& ref = info.references[i];
                auto label  = bridge.get_label_at(ref.addr);
                auto mod    = bridge.get_module_at(ref.addr);
                auto comment = bridge.get_comment_at(ref.addr);

                // Disassemble to get the full instruction text
                DISASM_INSTR instr{};
                DbgDisasmAt(ref.addr, &instr);

                std::string type_str;
                switch (ref.type) {
                    case XREF_CALL: type_str = "call"; break;
                    case XREF_JMP:  type_str = "jmp";  break;
                    case XREF_DATA: type_str = "data"; break;
                    default:        type_str = "ref";  break;
                }

                xref_arr.push_back({
                    {"address",     format_utils::format_address(ref.addr)},
                    {"string_va",   format_utils::format_address(str_va)},
                    {"type",        type_str},
                    {"instruction", instr.instruction},
                    {"label",       label},
                    {"module",      mod},
                    {"comment",     comment}
                });
            }

            if (info.references) BridgeFree(info.references);
        }

        return s_http_response::ok({
            {"value",      value},
            {"module",     module},
            {"string_vas", str_va_arr},
            {"xrefs",      xref_arr},
            {"count",      xref_arr.size()}
        });
    });

    // GET /api/stringxref/all?module=target.exe&limit=500
    // Enumerate all strings in the module and their referencing instructions.
    router.get("/api/stringxref/all", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto module = req.get_query("module", "");
        int  limit  = std::atoi(req.get_query("limit", "200").c_str());
        if (limit < 1) limit = 1;
        if (limit > 2000) limit = 2000;

        if (module.empty()) {
            module = bridge.get_module_at(bridge.eval_expression("cip"));
        }
        if (module.empty()) {
            return s_http_response::bad_request("Could not determine target module");
        }

        auto base = bridge.get_module_base(module);
        if (base == 0) return s_http_response::not_found("Module not found: " + module);

        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));
        if (size == 0) return s_http_response::not_found("Module has zero size");

        // Use x64dbg string enumeration
        auto result_arr = nlohmann::json::array();
        int  found = 0;

        // Walk module pages and enumerate strings using DbgGetEncodeTypeAt
        for (duint addr = base; addr < base + size && found < limit; addr++) {
            ENCODETYPE enc = DbgGetEncodeTypeAt(addr,
                static_cast<duint>(std::min<size_t>(64, base + size - addr)));
            if (enc != enc_ascii && enc != enc_unicode) continue;

            char text[MAX_STRING_SIZE] = {};
            if (!DbgGetStringAt(addr, text) || text[0] == '\0') continue;
            size_t slen = strlen(text);
            if (slen < 4 || slen > 256) { addr += slen; continue; }

            // Find xrefs to this string VA
            auto xcount = DbgGetXrefCountAt(addr);
            auto refs = nlohmann::json::array();
            if (xcount > 0) {
                XREF_INFO xi{};
                if (DbgXrefGet(addr, &xi)) {
                    for (duint i = 0; i < xi.refcount; ++i) {
                        DISASM_INSTR di{};
                        DbgDisasmAt(xi.references[i].addr, &di);
                        refs.push_back({
                            {"address",     format_utils::format_address(xi.references[i].addr)},
                            {"instruction", di.instruction}
                        });
                    }
                    if (xi.references) BridgeFree(xi.references);
                }
            }

            if (!refs.empty()) {
                result_arr.push_back({
                    {"string_va",  format_utils::format_address(addr)},
                    {"value",      std::string(text)},
                    {"encoding",   (enc == enc_ascii) ? "ascii" : "unicode"},
                    {"xref_count", refs.size()},
                    {"refs",       refs}
                });
                found++;
            }

            addr += slen;
        }

        return s_http_response::ok({
            {"module",  module},
            {"strings", result_arr},
            {"count",   result_arr.size()}
        });
    });

    // POST /api/stringxref/annotate
    // Body: { "module": "target.exe" }
    // Auto-label instructions that reference known strings.
    router.post("/api/stringxref/annotate", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_paused()) {
            return s_http_response::conflict("Debugger must be paused");
        }

        auto body   = nlohmann::json::parse(req.body, nullptr, false);
        auto module = body.is_discarded() ? "" : body.value("module", "");
        auto prefix = body.is_discarded() ? "s_" : body.value("prefix", "s_");
        int  limit  = body.is_discarded() ? 500 : body.value("limit", 500);
        if (limit > 2000) limit = 2000;

        if (module.empty()) {
            module = bridge.get_module_at(bridge.eval_expression("cip"));
        }
        if (module.empty()) return s_http_response::bad_request("Could not determine target module");

        auto base = bridge.get_module_base(module);
        if (base == 0) return s_http_response::not_found("Module not found: " + module);
        auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module + ")"));

        int annotated = 0;
        for (duint addr = base; addr < base + size && annotated < limit; addr++) {
            ENCODETYPE enc = DbgGetEncodeTypeAt(addr,
                static_cast<duint>(std::min<size_t>(64, base + size - addr)));
            if (enc != enc_ascii && enc != enc_unicode) continue;

            char text[MAX_STRING_SIZE] = {};
            if (!DbgGetStringAt(addr, text) || text[0] == '\0') continue;
            size_t slen = strlen(text);
            if (slen < 4 || slen > 128) { addr += slen; continue; }

            // Truncate for label/comment
            std::string snippet(text, std::min(slen, (size_t)32));
            for (auto& c : snippet) if (c < 0x20 || c >= 0x7F) c = '_';

            // Set a comment on the string VA itself
            bridge.set_comment_at(addr, "\"" + std::string(text).substr(0, 64) + "\"");

            // Annotate all instruction sites that reference this string VA
            auto xcount = DbgGetXrefCountAt(addr);
            if (xcount > 0) {
                XREF_INFO xi{};
                if (DbgXrefGet(addr, &xi)) {
                    for (duint i = 0; i < xi.refcount; ++i) {
                        auto ref_addr = xi.references[i].addr;
                        auto existing = bridge.get_comment_at(ref_addr);
                        if (existing.empty()) {
                            bridge.set_comment_at(ref_addr, prefix + snippet);
                        }
                    }
                    if (xi.references) BridgeFree(xi.references);
                }
            }

            annotated++;
            addr += slen;
        }

        return s_http_response::ok({
            {"module",    module},
            {"annotated", annotated},
            {"message",   "String references annotated in comments"}
        });
    });
}

} // namespace handlers
