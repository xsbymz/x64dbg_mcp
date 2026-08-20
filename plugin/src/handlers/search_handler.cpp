#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

// Parse a hex byte pattern string (e.g., "C4 CB 75 5B" or "C4CB755B" or "C4 ?? 75 5B")
// Returns pairs of (byte_value, is_wildcard).
// Returns empty vector if the pattern is malformed.
struct pattern_byte {
    uint8_t value = 0;
    bool    is_wildcard = false;
};

static std::vector<pattern_byte> parse_byte_pattern(const std::string& pattern_str) {
    // Strip all spaces to normalize
    std::string cleaned;
    cleaned.reserve(pattern_str.size());
    for (char c : pattern_str) {
        if (c != ' ') cleaned += c;
    }

    if (cleaned.empty() || (cleaned.size() % 2) != 0) {
        return {};
    }

    std::vector<pattern_byte> result;
    result.reserve(cleaned.size() / 2);

    for (size_t i = 0; i + 1 < cleaned.size(); i += 2) {
        char hi = cleaned[i];
        char lo = cleaned[i + 1];

        bool hi_wild = (hi == '?' || hi == '*');
        bool lo_wild = (lo == '?' || lo == '*');

        if (hi_wild || lo_wild) {
            result.push_back({0, true});
        } else {
            // Validate hex chars
            auto is_hex = [](char c) {
                return (c >= '0' && c <= '9') || (c >= 'a' && c <= 'f') || (c >= 'A' && c <= 'F');
            };
            if (!is_hex(hi) || !is_hex(lo)) {
                return {};  // Invalid pattern
            }
            char hex[3] = {hi, lo, '\0'};
            result.push_back({static_cast<uint8_t>(std::stoul(hex, nullptr, 16)), false});
        }
    }

    return result;
}

// Scan a memory buffer for a byte pattern starting at any offset.
// Returns all offsets (relative to buffer start) where the pattern matches.
static std::vector<size_t> scan_buffer(
    const uint8_t* buf, size_t buf_size,
    const std::vector<pattern_byte>& pattern
) {
    std::vector<size_t> hits;
    if (pattern.empty() || buf_size < pattern.size()) return hits;

    const size_t pat_len = pattern.size();
    const size_t search_end = buf_size - pat_len + 1;

    for (size_t i = 0; i < search_end; ++i) {
        bool match = true;
        for (size_t j = 0; j < pat_len; ++j) {
            if (!pattern[j].is_wildcard && buf[i + j] != pattern[j].value) {
                match = false;
                break;
            }
        }
        if (match) {
            hits.push_back(i);
        }
    }

    return hits;
}

void register_search_routes(c_http_router& router) {
    // POST /api/search/pattern - AOB/byte pattern scan
    // Returns ALL matches (up to max_results). Supports wildcard bytes (??)
    // Optional pagination: limit + offset for large result sets.
    router.post("/api/search/pattern", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("pattern")) {
            return s_http_response::bad_request("Missing 'pattern' field");
        }

        auto pattern_str = body["pattern"].get<std::string>();
        auto pattern = parse_byte_pattern(pattern_str);

        if (pattern.empty()) {
            return s_http_response::bad_request(
                "Invalid pattern '" + pattern_str + "'. Use hex bytes (e.g. 'C4 CB 75 5B' or 'C4CB755B'), wildcards as '?"
                "?'");
        }

        auto max_results = body.value("max_results", 1000);
        if (max_results < 1) max_results = 1;
        if (max_results > 10000) max_results = 10000;

        // Pagination
        auto limit  = body.value("limit",  max_results);
        auto offset = body.value("offset", 0);
        if (limit < 1) limit = 1;
        if (limit > max_results) limit = max_results;
        if (offset < 0) offset = 0;

        // Optional: restrict to a specific memory range
        std::string address_str = body.value("address", "");
        std::string size_str    = body.value("size", "");

        // Collect all matches (up to max_results total before pagination)
        std::vector<duint> all_matches;
        all_matches.reserve(512);

        if (!address_str.empty() && !size_str.empty()) {
            // Scan a specific range
            auto base = bridge.eval_expression(address_str);
            auto range_size = static_cast<size_t>(bridge.eval_expression(size_str));

            if (range_size == 0 || range_size > 256 * 1024 * 1024) {
                return s_http_response::bad_request("Invalid size (must be 1 byte - 256MB)");
            }

            auto mem = bridge.read_memory(base, range_size);
            if (mem.has_value()) {
                auto hits = scan_buffer(mem.value().data(), mem.value().size(), pattern);
                for (auto off : hits) {
                    if (static_cast<int>(all_matches.size()) >= max_results) break;
                    all_matches.push_back(base + static_cast<duint>(off));
                }
            }
        } else {
            // Scan all mapped memory pages (read + execute pages)
            MEMMAP memmap{};
            if (!DbgMemMap(&memmap)) {
                return s_http_response::internal_error("Failed to get memory map");
            }

            // Read each page and scan. prev_tail captures the last (pattern.size()-1)
            // bytes of the previous page so cross-page matches are detected.
            // IMPORTANT: to avoid reporting the same hit twice, when scanning the
            // combined (tail + page) buffer we only emit matches whose start offset
            // falls within the *current* page, i.e. offset >= prev_tail.size().
            const size_t overlap = pattern.size() > 1 ? pattern.size() - 1 : 0;
            std::vector<uint8_t> prev_tail;

            for (int i = 0; i < memmap.count && static_cast<int>(all_matches.size()) < max_results; ++i) {
                const auto& page = memmap.page[i];
                auto page_base = reinterpret_cast<duint>(page.mbi.BaseAddress);
                auto page_size = static_cast<size_t>(page.mbi.RegionSize);

                // Skip non-committed or non-readable pages
                if (page.mbi.State != MEM_COMMIT) {
                    prev_tail.clear();
                    continue;
                }
                if (page.mbi.Protect == PAGE_NOACCESS || page.mbi.Protect == 0) {
                    prev_tail.clear();
                    continue;
                }

                // Read the page (limit single reads to 64MB)
                const size_t read_size = (page_size > 64 * 1024 * 1024) ? 64 * 1024 * 1024 : page_size;
                auto mem = bridge.read_memory(page_base, read_size);
                if (!mem.has_value()) {
                    prev_tail.clear();
                    continue;
                }

                const auto& buf = mem.value();

                if (!prev_tail.empty() && overlap > 0) {
                    // Build combined buffer and scan, but only report matches that
                    // START within the current page (offset >= prev_tail.size()).
                    // This prevents re-reporting hits that were already found when
                    // scanning the previous page's full buffer.
                    std::vector<uint8_t> combined;
                    combined.reserve(prev_tail.size() + buf.size());
                    combined.insert(combined.end(), prev_tail.begin(), prev_tail.end());
                    combined.insert(combined.end(), buf.begin(), buf.end());

                    auto hits = scan_buffer(combined.data(), combined.size(), pattern);
                    for (auto off : hits) {
                        if (static_cast<int>(all_matches.size()) >= max_results) break;
                        // Only emit if the match starts in the current page's data
                        if (off >= prev_tail.size()) {
                            duint abs_addr = page_base + static_cast<duint>(off - prev_tail.size());
                            all_matches.push_back(abs_addr);
                        }
                    }
                } else {
                    auto hits = scan_buffer(buf.data(), buf.size(), pattern);
                    for (auto off : hits) {
                        if (static_cast<int>(all_matches.size()) >= max_results) break;
                        all_matches.push_back(page_base + static_cast<duint>(off));
                    }
                }

                // Save tail for next iteration (cross-page match detection)
                if (buf.size() >= overlap && overlap > 0) {
                    prev_tail.assign(buf.end() - static_cast<ptrdiff_t>(overlap), buf.end());
                } else {
                    prev_tail = buf;
                }
            }

            if (memmap.page) {
                BridgeFree(memmap.page);
            }
        }

        // Apply pagination
        int total = static_cast<int>(all_matches.size());
        int page_start = std::min(offset, total);
        int page_end   = std::min(page_start + limit, total);

        auto matches = nlohmann::json::array();
        for (int i = page_start; i < page_end; ++i) {
            matches.push_back(format_utils::format_address(all_matches[i]));
        }

        bool found = total > 0;
        nlohmann::json data = {
            {"pattern",      pattern_str},
            {"found",        found},
            {"total_count",  total},
            {"count",        matches.size()},
            {"offset",       page_start},
            {"has_more",     page_end < total},
            {"matches",      matches},
        };

        // Backwards-compat: first_match field
        if (found) {
            data["first_match"] = format_utils::format_address(all_matches[0]);
        } else {
            data["first_match"] = "";
        }

        return s_http_response::ok(data);
    });

    // POST /api/search/string - String search
    // When no module is specified, performs a full memory scan (returns all matches).
    // Supports pagination via limit/offset.
    router.post("/api/search/string", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("text")) {
            return s_http_response::bad_request("Missing 'text' field");
        }

        auto text = body["text"].get<std::string>();
        auto module_name = body.value("module", "");
        auto encoding = body.value("encoding", "utf8"); // utf8, ascii, unicode

        // Pagination
        auto limit  = body.value("limit",  1000);
        auto offset = body.value("offset", 0);
        if (limit < 1) limit = 1;
        if (limit > 5000) limit = 5000;
        if (offset < 0) offset = 0;

        // Convert string to byte pattern
        std::string byte_pattern;
        if (encoding == "unicode" || encoding == "utf16") {
            // UTF-16LE encoding
            for (char c : text) {
                char buf[8];
                snprintf(buf, sizeof(buf), "%02X 00 ", static_cast<unsigned char>(c));
                byte_pattern += buf;
            }
        } else {
            // ASCII / UTF-8
            for (char c : text) {
                char buf[4];
                snprintf(buf, sizeof(buf), "%02X ", static_cast<unsigned char>(c));
                byte_pattern += buf;
            }
        }

        // Trim trailing space
        if (!byte_pattern.empty() && byte_pattern.back() == ' ') {
            byte_pattern.pop_back();
        }

        auto pattern = parse_byte_pattern(byte_pattern);
        if (pattern.empty()) {
            return s_http_response::bad_request("Empty or invalid string text");
        }

        // Collect all matches via the same scan logic as pattern search
        std::vector<duint> all_matches;
        all_matches.reserve(64);
        constexpr int kMaxResults = 5000;

        if (!module_name.empty()) {
            // Module-scoped scan
            auto base = bridge.get_module_base(module_name);
            if (base == 0) {
                return s_http_response::not_found("Module not found: " + module_name);
            }
            auto range = static_cast<size_t>(bridge.eval_expression("mod.size(" + module_name + ")"));
            if (range > 0) {
                auto mem = bridge.read_memory(base, range);
                if (mem.has_value()) {
                    auto hits = scan_buffer(mem.value().data(), mem.value().size(), pattern);
                    for (auto off : hits) {
                        if (static_cast<int>(all_matches.size()) >= kMaxResults) break;
                        all_matches.push_back(base + static_cast<duint>(off));
                    }
                }
            }
        } else {
            // Full memory scan — same chunk approach as pattern search
            MEMMAP memmap{};
            if (!DbgMemMap(&memmap)) {
                return s_http_response::internal_error("Failed to get memory map");
            }

            const size_t overlap = pattern.size() > 1 ? pattern.size() - 1 : 0;
            std::vector<uint8_t> prev_tail;

            for (int i = 0; i < memmap.count && static_cast<int>(all_matches.size()) < kMaxResults; ++i) {
                const auto& page = memmap.page[i];
                auto page_base = reinterpret_cast<duint>(page.mbi.BaseAddress);
                auto page_size = static_cast<size_t>(page.mbi.RegionSize);

                if (page.mbi.State != MEM_COMMIT) { prev_tail.clear(); continue; }
                if (page.mbi.Protect == PAGE_NOACCESS || page.mbi.Protect == 0) { prev_tail.clear(); continue; }

                const size_t read_size = (page_size > 64 * 1024 * 1024) ? 64 * 1024 * 1024 : page_size;
                auto mem = bridge.read_memory(page_base, read_size);
                if (!mem.has_value()) { prev_tail.clear(); continue; }

                const auto& buf = mem.value();

                if (!prev_tail.empty() && overlap > 0) {
                    std::vector<uint8_t> combined;
                    combined.reserve(prev_tail.size() + buf.size());
                    combined.insert(combined.end(), prev_tail.begin(), prev_tail.end());
                    combined.insert(combined.end(), buf.begin(), buf.end());

                    auto hits = scan_buffer(combined.data(), combined.size(), pattern);
                    for (auto off : hits) {
                        if (static_cast<int>(all_matches.size()) >= kMaxResults) break;
                        if (off >= prev_tail.size()) {
                            all_matches.push_back(page_base + static_cast<duint>(off - prev_tail.size()));
                        }
                    }
                } else {
                    auto hits = scan_buffer(buf.data(), buf.size(), pattern);
                    for (auto off : hits) {
                        if (static_cast<int>(all_matches.size()) >= kMaxResults) break;
                        all_matches.push_back(page_base + static_cast<duint>(off));
                    }
                }

                if (buf.size() >= overlap && overlap > 0) {
                    prev_tail.assign(buf.end() - static_cast<ptrdiff_t>(overlap), buf.end());
                } else {
                    prev_tail = buf;
                }
            }

            if (memmap.page) BridgeFree(memmap.page);
        }

        // Apply pagination
        int total = static_cast<int>(all_matches.size());
        int page_start = std::min(offset, total);
        int page_end   = std::min(page_start + limit, total);

        auto matches = nlohmann::json::array();
        for (int i = page_start; i < page_end; ++i) {
            matches.push_back(format_utils::format_address(all_matches[i]));
        }

        return s_http_response::ok({
            {"text",        text},
            {"encoding",    encoding},
            {"pattern",     byte_pattern},
            {"found",       total > 0},
            {"total_count", total},
            {"count",       matches.size()},
            {"offset",      page_start},
            {"has_more",    page_end < total},
            {"matches",     matches},
            {"first_match", total > 0 ? format_utils::format_address(all_matches[0]) : ""}
        });
    });

    // GET /api/search/string_at?address=&encoding=auto&max_length=256 - Get string at address
    // encoding: auto (default), ascii, unicode
    router.get("/api/search/string_at", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto encoding = req.get_query("encoding", "auto");
        auto max_length_str = req.get_query("max_length", "256");
        auto max_length = static_cast<size_t>(std::stoull(max_length_str));
        if (max_length < 1) max_length = 1;
        if (max_length > 4096) max_length = 4096;

        auto address = bridge.eval_expression(address_str);

        nlohmann::json data = {
            {"address",  format_utils::format_address(address)},
            {"encoding", encoding}
        };

        // Always read raw bytes for transparency
        auto raw_mem = bridge.read_memory(address, max_length);
        if (raw_mem.has_value()) {
            const auto& raw = raw_mem.value();
            data["raw_hex"] = format_utils::format_bytes_hex(raw.data(), raw.size());

            if (encoding == "unicode" || encoding == "utf16") {
                // Read as UTF-16LE and encode to UTF-8 properly (BMP range).
                // Previously non-ASCII chars were replaced with '?' which mangled
                // non-English strings (Cyrillic, CJK, etc.).
                std::string utf8_str;
                for (size_t i = 0; i + 1 < raw.size(); i += 2) {
                    uint32_t wc = raw[i] | (static_cast<uint32_t>(raw[i + 1]) << 8);
                    if (wc == 0) break;
                    if (wc < 0x80) {
                        utf8_str += static_cast<char>(wc);
                    } else if (wc < 0x800) {
                        utf8_str += static_cast<char>(0xC0 | (wc >> 6));
                        utf8_str += static_cast<char>(0x80 | (wc & 0x3F));
                    } else {
                        utf8_str += static_cast<char>(0xE0 | (wc >> 12));
                        utf8_str += static_cast<char>(0x80 | ((wc >> 6) & 0x3F));
                        utf8_str += static_cast<char>(0x80 | (wc & 0x3F));
                    }
                }
                data["text"] = utf8_str;
                data["found"] = !utf8_str.empty();
            } else if (encoding == "ascii") {
                // Read as null-terminated ASCII
                std::string ascii_str;
                for (size_t i = 0; i < raw.size(); ++i) {
                    if (raw[i] == 0) break;
                    ascii_str += static_cast<char>(raw[i]);
                }
                data["text"] = ascii_str;
                data["found"] = !ascii_str.empty();
            } else {
                // Auto-detect: use DbgGetStringAt first, then cross-check
                char dbg_text[MAX_STRING_SIZE] = {};
                auto found = DbgGetStringAt(address, dbg_text);
                data["text"] = std::string(dbg_text);
                data["found"] = found;

                // Also attempt raw ASCII read for comparison
                std::string raw_ascii;
                for (size_t i = 0; i < raw.size(); ++i) {
                    if (raw[i] == 0) break;
                    uint8_t b = raw[i];
                    if (b >= 0x20 && b < 0x7F) {
                        raw_ascii += static_cast<char>(b);
                    } else {
                        break;  // Stop at non-printable
                    }
                }
                if (!raw_ascii.empty()) {
                    data["raw_ascii"] = raw_ascii;
                }
            }
        } else {
            // Fallback to DbgGetStringAt only
            char text[MAX_STRING_SIZE] = {};
            auto found = DbgGetStringAt(address, text);
            data["found"] = found;
            data["text"]  = std::string(text);
        }

        return s_http_response::ok(data);
    });

    // POST /api/search/auto_complete - Symbol auto-complete
    router.post("/api/search/auto_complete", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("search")) {
            return s_http_response::bad_request("Missing 'search' field");
        }

        auto search = body["search"].get<std::string>();
        auto max_results = body.value("max_results", 20);

        // Allocate buffer for results
        std::vector<char*> buffer(max_results, nullptr);
        auto count = DbgFunctions()->SymAutoComplete(search.c_str(), buffer.data(), max_results);

        auto results = nlohmann::json::array();
        for (int i = 0; i < count && i < max_results; ++i) {
            if (buffer[i]) {
                results.push_back(std::string(buffer[i]));
                BridgeFree(buffer[i]);
            }
        }

        return s_http_response::ok({
            {"search",  search},
            {"results", results},
            {"count",   results.size()}
        });
    });

    // GET /api/search/encode_type?address= - Get encode type at address
    router.get("/api/search/encode_type", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto address_str = req.get_query("address");
        if (address_str.empty()) {
            return s_http_response::bad_request("Missing 'address' query parameter");
        }

        auto size_str = req.get_query("size", "1");
        auto address = bridge.eval_expression(address_str);
        auto size = bridge.eval_expression(size_str);

        auto encode_type = DbgGetEncodeTypeAt(address, size);

        std::string type_str;
        switch (encode_type) {
            case enc_unknown: type_str = "unknown"; break;
            case enc_byte:    type_str = "byte"; break;
            case enc_word:    type_str = "word"; break;
            case enc_dword:   type_str = "dword"; break;
            case enc_fword:   type_str = "fword"; break;
            case enc_qword:   type_str = "qword"; break;
            case enc_tbyte:   type_str = "tbyte"; break;
            case enc_oword:   type_str = "oword"; break;
            case enc_mmword:  type_str = "mmword"; break;
            case enc_xmmword: type_str = "xmmword"; break;
            case enc_ymmword: type_str = "ymmword"; break;
            case enc_real4:   type_str = "real4"; break;
            case enc_real8:   type_str = "real8"; break;
            case enc_real10:  type_str = "real10"; break;
            case enc_ascii:   type_str = "ascii"; break;
            case enc_unicode: type_str = "unicode"; break;
            case enc_code:    type_str = "code"; break;
            case enc_middle:  type_str = "middle"; break;
            default:          type_str = "unknown"; break;
        }

        return s_http_response::ok({
            {"address",     format_utils::format_address(address)},
            {"encode_type", type_str},
            {"type_id",     static_cast<int>(encode_type)}
        });
    });

    // POST /api/crypto/scan - FindCrypt cryptographic signature scanner
    // Scans memory or a specific module for standard cryptographic constants.
    router.post("/api/crypto/scan", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string module_name = (!body.is_discarded() && body.contains("module")) ? body["module"].get<std::string>() : "";

        struct crypto_sig {
            const char* name;
            const char* algorithm;
            const char* pattern;
        };

        const crypto_sig signatures[] = {
            {"AES Forward S-Box",            "AES",             "63 7C 77 7B F2 6B 6F C5 30 01 67 2B FE D7 AB 76"},
            {"AES Inverse S-Box",            "AES",             "52 09 6A D5 30 36 A5 38 BF 40 A3 9E 81 F3 D7 FB"},
            {"AES Round Constants (Rcon)",   "AES",             "01 02 04 08 10 20 40 80 1B 36"},
            {"MD5 Initial Constants",        "MD5",             "01 23 45 67 89 AB CD EF FE DC BA 98 76 54 32 10"},
            {"SHA-1 Initial Hash Values",    "SHA-1",           "67 45 23 01 EF CD AB 89 98 BA DC FE 10 32 54 76 C3 D2 E1 F0"},
            {"SHA-256 Initial Constants",    "SHA-256",         "6A 09 E6 67 BB 67 AE 85 3C 6E F3 72 A5 4F F5 3A"},
            {"SHA-256 K Constants",          "SHA-256",         "42 8A 2F 98 71 37 44 91 B5 C0 FB CF E9 B5 DB A5"},
            {"SHA-512 K Constants (first 16B)", "SHA-512",      "28 AE 60 42 87 E3 23 D4 AB FB 98 15 5B D2 C9 F4"},
            {"ChaCha20/Salsa20 32B Sigma",   "ChaCha20/Salsa20", "65 78 70 61 6E 64 20 33 32 2D 62 79 74 65 20 6B"},
            {"ChaCha20/Salsa20 16B Tau",     "ChaCha20/Salsa20", "65 78 70 61 6E 64 20 31 36 2D 62 79 74 65 20 6B"},
            {"CRC32 Lookup Table (first 16B)", "CRC32",          "00 00 00 00 77 07 30 96 EE 0E 61 2C 99 09 51 BA"},
            {"Base64 Alphabet (A..P)",       "Base64",          "41 42 43 44 45 46 47 48 49 4A 4B 4C 4D 4E 4F 50"},
            {"TEA / XTEA Delta Constant",    "TEA/XTEA",        "B9 79 37 9E"}
        };

        // Determine scan boundaries
        std::vector<std::pair<duint, size_t>> scan_ranges;

        if (!module_name.empty()) {
            auto base = bridge.get_module_base(module_name);
            if (base == 0) return s_http_response::not_found("Module not found: " + module_name);
            auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module_name + ")"));
            if (size > 0) scan_ranges.emplace_back(base, size);
        } else {
            MEMMAP memmap{};
            if (DbgMemMap(&memmap)) {
                for (int i = 0; i < memmap.count; ++i) {
                    const auto& page = memmap.page[i];
                    if (page.mbi.State == MEM_COMMIT && page.mbi.Protect != PAGE_NOACCESS && page.mbi.Protect != 0) {
                        scan_ranges.emplace_back(reinterpret_cast<duint>(page.mbi.BaseAddress), static_cast<size_t>(page.mbi.RegionSize));
                    }
                }
                if (memmap.page) BridgeFree(memmap.page);
            }
        }

        auto matches = nlohmann::json::array();

        // Perform scan for each signature
        for (const auto& sig : signatures) {
            auto pat = parse_byte_pattern(sig.pattern);
            if (pat.empty()) continue;

            for (const auto& [range_base, range_size] : scan_ranges) {
                // Read range in chunks of up to 16MB
                constexpr size_t kChunkSize = 16 * 1024 * 1024;
                for (size_t offset = 0; offset < range_size; offset += kChunkSize) {
                    size_t chunk_len = std::min(kChunkSize, range_size - offset);
                    auto mem = bridge.read_memory(range_base + offset, chunk_len);
                    if (!mem.has_value()) continue;

                    auto hits = scan_buffer(mem->data(), mem->size(), pat);
                    for (auto hit_off : hits) {
                        duint hit_addr = range_base + offset + static_cast<duint>(hit_off);
                        auto label = bridge.get_label_at(hit_addr);
                        auto mod = bridge.get_module_at(hit_addr);

                        matches.push_back({
                            {"algorithm", sig.algorithm},
                            {"name",      sig.name},
                            {"address",   format_utils::format_address(hit_addr)},
                            {"module",    mod},
                            {"label",     label}
                        });
                    }
                }
            }
        }

        return s_http_response::ok({
            {"count",   matches.size()},
            {"matches", matches}
        });
    });

    // POST /api/search/xor_scan - XOR Brute-force String Scanner
    // Searches for a target string encoded with any 1-byte XOR key (0x01..0xFF).
    router.post("/api/search/xor_scan", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        if (body.is_discarded() || !body.contains("text")) {
            return s_http_response::bad_request("Missing 'text' field");
        }

        auto text = body["text"].get<std::string>();
        if (text.empty()) return s_http_response::bad_request("Target text cannot be empty");

        auto module_name = body.value("module", "");
        auto max_results = body.value("max_results", 100);

        // Precompute 255 pattern byte vectors (keys 1 to 255)
        std::vector<std::vector<pattern_byte>> patterns(256);
        for (int key = 1; key <= 255; ++key) {
            std::vector<pattern_byte> pat;
            pat.reserve(text.size());
            for (char c : text) {
                pat.push_back({static_cast<uint8_t>(static_cast<uint8_t>(c) ^ key), false});
            }
            patterns[key] = std::move(pat);
        }

        // Determine scan boundaries
        std::vector<std::pair<duint, size_t>> scan_ranges;
        if (!module_name.empty()) {
            auto base = bridge.get_module_base(module_name);
            if (base == 0) return s_http_response::not_found("Module not found: " + module_name);
            auto size = static_cast<size_t>(bridge.eval_expression("mod.size(" + module_name + ")"));
            if (size > 0) scan_ranges.emplace_back(base, size);
        } else {
            MEMMAP memmap{};
            if (DbgMemMap(&memmap)) {
                for (int i = 0; i < memmap.count; ++i) {
                    const auto& page = memmap.page[i];
                    if (page.mbi.State == MEM_COMMIT && page.mbi.Protect != PAGE_NOACCESS && page.mbi.Protect != 0) {
                        scan_ranges.emplace_back(reinterpret_cast<duint>(page.mbi.BaseAddress), static_cast<size_t>(page.mbi.RegionSize));
                    }
                }
                if (memmap.page) BridgeFree(memmap.page);
            }
        }

        auto matches = nlohmann::json::array();

        for (const auto& [range_base, range_size] : scan_ranges) {
            if (static_cast<int>(matches.size()) >= max_results) break;

            constexpr size_t kChunkSize = 8 * 1024 * 1024;
            for (size_t offset = 0; offset < range_size; offset += kChunkSize) {
                if (static_cast<int>(matches.size()) >= max_results) break;
                size_t chunk_len = std::min(kChunkSize, range_size - offset);
                auto mem = bridge.read_memory(range_base + offset, chunk_len);
                if (!mem.has_value()) continue;

                for (int key = 1; key <= 255; ++key) {
                    if (static_cast<int>(matches.size()) >= max_results) break;
                    auto hits = scan_buffer(mem->data(), mem->size(), patterns[key]);
                    for (auto hit_off : hits) {
                        if (static_cast<int>(matches.size()) >= max_results) break;
                        duint hit_addr = range_base + offset + static_cast<duint>(hit_off);

                        matches.push_back({
                            {"address",   format_utils::format_address(hit_addr)},
                            {"xor_key",   format_utils::format_hex(static_cast<uint8_t>(key))},
                            {"xor_dec",   key},
                            {"target",    text},
                            {"module",    bridge.get_module_at(hit_addr)},
                            {"label",     bridge.get_label_at(hit_addr)}
                        });
                    }
                }
            }
        }

        return s_http_response::ok({
            {"target",  text},
            {"count",   matches.size()},
            {"matches", matches}
        });
    });
}

} // namespace handlers
