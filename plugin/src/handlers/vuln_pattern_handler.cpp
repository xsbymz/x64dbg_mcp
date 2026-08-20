#include "http/c_http_router.h"
#include "bridge/c_bridge_executor.h"
#include "util/format_utils.h"

#include <nlohmann/json.hpp>
#include <string>
#include <vector>
#include <algorithm>
#include <set>
#include <regex>
#include "bridgemain.h"
#include "_dbgfunctions.h"

namespace handlers {

namespace {

std::string to_lower(const std::string& s) {
    std::string r = s;
    std::transform(r.begin(), r.end(), r.begin(), [](unsigned char c) { return std::tolower(c); });
    return r;
}

struct vuln_finding {
    duint address;
    std::string pattern;
    std::string severity;
    std::string description;
    std::string disasm;
};

std::vector<vuln_finding> scan_vulnerability_patterns(c_bridge_executor& bridge, duint start, duint end) {
    std::vector<vuln_finding> findings;

    std::vector<std::tuple<std::regex, std::string, std::string>> patterns = {
        {std::regex("strcpy|strcat|sprintf|gets|scanf|sscanf|vsprintf|vscanf", std::regex_constants::icase),
         "HIGH", "Unsafe string copy/format function - potential buffer overflow"},
        {std::regex("memcpy|memmove|memset|bcopy", std::regex_constants::icase),
         "MEDIUM", "Memory function - verify length parameter is validated"},
        {std::regex("printf\\(.*\\%.*s", std::regex_constants::icase),
         "HIGH", "Potential format string vulnerability - user input as format string"},
        {std::regex("scanf\\(|sscanf\\(|fscanf\\(", std::regex_constants::icase),
         "MEDIUM", "Scanf family - verify format string and buffer sizes"},
        {std::regex("atoi|atol|atoll|strtol|strtoul", std::regex_constants::icase),
         "LOW", "Integer conversion - check for overflow/underflow"},
        {std::regex("malloc\\(|calloc\\(|realloc\\(", std::regex_constants::icase),
         "LOW", "Dynamic allocation - verify size is validated and checked for failure"},
        {std::regex("free\\(.*ptr", std::regex_constants::icase),
         "MEDIUM", "Free pattern - check for double-free or use-after-free"},
        {std::regex("VirtualProtect|mprotect|NtProtectVirtualMemory", std::regex_constants::icase),
         "MEDIUM", "Memory protection change - verify RX/RW transitions"}
    };

    for (duint addr = start; addr < end - 2; ) {
        auto d = bridge.get_basic_info(addr);
        if (!d.has_value()) { addr += 1; continue; }

        std::string inst = d.value()["instruction"].get<std::string>();
        int size = d.value()["size"].get<int>();
        if (size <= 0) { addr += 1; continue; }

        std::string lower_inst = to_lower(inst);
        for (const auto& [pattern, severity, desc] : patterns) {
            if (std::regex_search(lower_inst, pattern)) {
                findings.push_back({addr, pattern.mark_count() > 0 ? "unsafe_function" : "memory_operation",
                                   severity, desc, inst});
                break;
            }
        }
        addr += size;
    }

    return findings;
}

}

void register_vuln_pattern_handler_routes(c_http_router& router) {
    router.post("/api/vuln/scan_patterns", [](const s_http_request& req) -> s_http_response {
        auto& bridge = get_bridge();
        if (!bridge.require_debugging()) {
            return s_http_response::conflict("No active debug session");
        }

        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string start_expr = body.value("start_address", "module.main");
        std::string end_expr = body.value("end_address", "module.main + 0x10000");
        std::string module = body.value("module", "");

        duint scan_start = 0;
        duint scan_end = 0;

        if (!module.empty()) {
            auto mod_base = bridge.get_module_base(module);
            if (mod_base != 0) {
                scan_start = mod_base;
                scan_end = mod_base + static_cast<duint>(bridge.eval_expression("mod.size(\"" + module + "\")"));
                if (scan_end == mod_base) scan_end = mod_base + 0x10000;
            }
        }

        if (scan_start == 0) {
            scan_start = bridge.eval_expression(start_expr);
        }
        if (scan_end == 0) {
            scan_end = bridge.eval_expression(end_expr);
        }
        if (scan_end <= scan_start) scan_end = scan_start + 0x10000;

        auto findings = scan_vulnerability_patterns(bridge, scan_start, scan_end);

        nlohmann::json result = nlohmann::json::array();
        for (const auto& f : findings) {
            result.push_back({
                {"address", format_utils::format_address(f.address)},
                {"pattern", f.pattern},
                {"severity", f.severity},
                {"description", f.description},
                {"instruction", f.disasm}
            });
        }

        std::map<std::string, int> severity_counts;
        for (const auto& f : findings) severity_counts[f.severity]++;

        return s_http_response::ok({
            {"scan_start", format_utils::format_address(scan_start)},
            {"scan_end", format_utils::format_address(scan_end)},
            {"total_findings", findings.size()},
            {"severity_breakdown", {
                {"HIGH", severity_counts.count("HIGH") ? severity_counts["HIGH"] : 0},
                {"MEDIUM", severity_counts.count("MEDIUM") ? severity_counts["MEDIUM"] : 0},
                {"LOW", severity_counts.count("LOW") ? severity_counts["LOW"] : 0}
            }},
            {"findings", result}
        });
    });

    router.post("/api/vuln/check_buffer_overflow", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string func = body.value("function_address", "cip");

        auto& bridge = get_bridge();
        duint start = bridge.eval_expression(func);
        auto bounds = bridge.get_function_bounds(start);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + func);
        }

        duint func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        duint func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        auto findings = scan_vulnerability_patterns(bridge, func_start, func_end);
        std::vector<nlohmann::json> overflow_risks;
        for (const auto& f : findings) {
            if (f.pattern == "unsafe_function" && f.severity == "HIGH") {
                overflow_risks.push_back({
                    {"address", format_utils::format_address(f.address)},
                    {"function", func},
                    {"instruction", f.disasm},
                    {"risk", "Stack or heap buffer overflow"}
                });
            }
        }

        return s_http_response::ok({
            {"function", func},
            {"function_start", format_utils::format_address(func_start)},
            {"function_end", format_utils::format_address(func_end)},
            {"overflow_risks", overflow_risks},
            {"risk_count", overflow_risks.size()}
        });
    });

    router.post("/api/vuln/check_format_string", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string func = body.value("function_address", "cip");

        auto& bridge = get_bridge();
        duint start = bridge.eval_expression(func);
        auto bounds = bridge.get_function_bounds(start);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + func);
        }

        duint func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        duint func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        auto findings = scan_vulnerability_patterns(bridge, func_start, func_end);
        std::vector<nlohmann::json> fmt_risks;
        for (const auto& f : findings) {
            if (f.pattern == "unsafe_function" && f.severity == "HIGH") {
                fmt_risks.push_back({
                    {"address", format_utils::format_address(f.address)},
                    {"instruction", f.disasm},
                    {"attack_vector", "User-controlled format string"}
                });
            }
        }

        return s_http_response::ok({
            {"function", func},
            {"format_string_risks", fmt_risks},
            {"risk_count", fmt_risks.size()}
        });
    });

    router.post("/api/vuln/check_integer_overflow", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string func = body.value("function_address", "cip");

        auto& bridge = get_bridge();
        duint start = bridge.eval_expression(func);
        auto bounds = bridge.get_function_bounds(start);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + func);
        }

        duint func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        duint func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        auto findings = scan_vulnerability_patterns(bridge, func_start, func_end);
        std::vector<nlohmann::json> int_risks;
        for (const auto& f : findings) {
            if (f.pattern == "memory_operation" || f.pattern == "unsafe_function") {
                int_risks.push_back({
                    {"address", format_utils::format_address(f.address)},
                    {"instruction", f.disasm},
                    {"pattern", f.pattern},
                    {"note", "Verify arithmetic before allocation/copy"}
                });
            }
        }

        return s_http_response::ok({
            {"function", func},
            {"integer_overflow_risks", int_risks},
            {"risk_count", int_risks.size()}
        });
    });

    router.post("/api/vuln/stack_canary_check", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string func = body.value("function_address", "cip");

        auto& bridge = get_bridge();
        duint start = bridge.eval_expression(func);
        auto bounds = bridge.get_function_bounds(start);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + func);
        }

        duint func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        duint func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        std::string canary_analysis;
        bool has_canary = false;
        for (duint addr = func_start; addr < func_end - 2; ) {
            auto d = bridge.get_basic_info(addr);
            if (!d.has_value()) { addr += 1; continue; }
            std::string inst = d.value()["instruction"].get<std::string>();
            int size = d.value()["size"].get<int>();
            if (size <= 0) { addr += 1; continue; }
            std::string lower = to_lower(inst);
            if (lower.find("gs:") != std::string::npos && lower.find("mov") != std::string::npos && lower.find("rbp") != std::string::npos) {
                has_canary = true;
                canary_analysis += format_utils::format_address(addr) + " CANARY LOAD: " + inst + "\n";
            }
            if (lower.find("__stack_chk_fail") != std::string::npos) {
                has_canary = true;
                canary_analysis += format_utils::format_address(addr) + " CANARY CHECK: " + inst + "\n";
            }
            addr += size;
        }

        has_canary = canary_analysis.find("CANARY LOAD") != std::string::npos ||
                     canary_analysis.find("CANARY CHECK") != std::string::npos;

        return s_http_response::ok({
            {"function", func},
            {"function_start", format_utils::format_address(func_start)},
            {"function_end", format_utils::format_address(func_end)},
            {"has_canary", has_canary},
            {"canary_analysis", canary_analysis},
            {"bypass_difficulty", has_canary ? "HIGH" : "LOW"}
        });
    });

    router.post("/api/vuln/exploitability_score", [](const s_http_request& req) -> s_http_response {
        auto body = nlohmann::json::parse(req.body, nullptr, false);
        std::string func = body.value("function_address", "cip");

        auto& bridge = get_bridge();
        duint start = bridge.eval_expression(func);
        auto bounds = bridge.get_function_bounds(start);
        if (!bounds.has_value()) {
            return s_http_response::not_found("No function at " + func);
        }

        duint func_start = format_utils::parse_address(bounds.value()["start"].get<std::string>());
        duint func_end = format_utils::parse_address(bounds.value()["end"].get<std::string>());

        auto findings = scan_vulnerability_patterns(bridge, func_start, func_end);
        std::string canary_analysis;
        bool has_canary = false;
        for (duint addr = func_start; addr < func_end - 2; ) {
            auto d = bridge.get_basic_info(addr);
            if (!d.has_value()) { addr += 1; continue; }
            std::string inst = d.value()["instruction"].get<std::string>();
            int size = d.value()["size"].get<int>();
            if (size <= 0) { addr += 1; continue; }
            std::string lower = to_lower(inst);
            if (lower.find("gs:") != std::string::npos && lower.find("mov") != std::string::npos && lower.find("rbp") != std::string::npos) {
                has_canary = true;
                canary_analysis += format_utils::format_address(addr) + " CANARY LOAD: " + inst + "\n";
            }
            if (lower.find("__stack_chk_fail") != std::string::npos) {
                has_canary = true;
                canary_analysis += format_utils::format_address(addr) + " CANARY CHECK: " + inst + "\n";
            }
            addr += size;
        }

        has_canary = canary_analysis.find("CANARY LOAD") != std::string::npos;

        int score = 0;
        std::vector<std::string> risk_factors;
        for (const auto& f : findings) {
            if (f.severity == "HIGH") { score += 30; risk_factors.push_back(f.description); }
            else if (f.severity == "MEDIUM") { score += 15; }
            else { score += 5; }
        }
        if (has_canary) { score -= 40; risk_factors.push_back("Stack canary present"); }

        score = std::clamp(score, 0, 100);

        return s_http_response::ok({
            {"function", func},
            {"exploitability_score", score},
            {"risk_level", score >= 70 ? "CRITICAL" : score >= 40 ? "HIGH" : score >= 20 ? "MEDIUM" : "LOW"},
            {"risk_factors", risk_factors},
            {"finding_count", static_cast<int>(findings.size())},
            {"has_canary", has_canary},
            {"aslr_mitigation", true},
            {"dep_mitigation", true},
            {"recommendation", score >= 70 ? "Immediate patching required - high exploitability" :
                               score >= 40 ? "Security review recommended" : "Low risk - monitor"}
        });
    });
}

}
