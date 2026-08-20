#pragma once

#include <string>
#include <cstdint>
#include <algorithm>
#include <cctype>

class c_input_sanitizer {
public:
    // Check if a string contains any characters from the dangerous_chars set.
    [[nodiscard]] static bool contains_dangerous_chars(const std::string& s, const char* dangerous_chars) {
        if (s.empty() || !dangerous_chars) return false;
        for (size_t i = 0; i < s.size(); ++i) {
            for (size_t j = 0; dangerous_chars[j] != '\0'; ++j) {
                if (s[i] == dangerous_chars[j]) return true;
            }
        }
        return false;
    }

    // Validate that an expression is safe for x64dbg evaluation.
    // Allowed pattern: [0-9a-fA-Fx]+\.[\w\.]* (hex numbers, register-like names, dotted module.function paths)
    [[nodiscard]] static bool is_safe_expression(const std::string& expr) {
        if (expr.empty()) return false;

        static const char* DANGEROUS_CHARS = ";|&$(){}[]<>!@#%^*+=,?'\"`~\\";
        if (contains_dangerous_chars(expr, DANGEROUS_CHARS)) return false;

        size_t i = 0;
        if (i >= expr.size()) return false;

        if (!((expr[i] >= '0' && expr[i] <= '9') ||
              (expr[i] >= 'a' && expr[i] <= 'f') ||
              (expr[i] >= 'A' && expr[i] <= 'F') ||
              expr[i] == 'x' || expr[i] == 'X')) {
            return false;
        }
        ++i;

        while (i < expr.size() &&
               ((expr[i] >= '0' && expr[i] <= '9') ||
                (expr[i] >= 'a' && expr[i] <= 'f') ||
                (expr[i] >= 'A' && expr[i] <= 'F') ||
                expr[i] == 'x' || expr[i] == 'X')) {
            ++i;
        }

        if (i < expr.size() && expr[i] == '.') {
            ++i;
        }

        while (i < expr.size()) {
            char c = expr[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '.') {
                ++i;
            } else {
                return false;
            }
        }

        return true;
    }

    // Validate that a command is one of the allowed x64dbg commands.
    // Rejects semicolons, pipes, and any command not in the whitelist.
    [[nodiscard]] static bool is_safe_command(const std::string& cmd) {
        if (cmd.empty()) return false;

        static const char* DANGEROUS_CHARS = ";|";
        if (contains_dangerous_chars(cmd, DANGEROUS_CHARS)) return false;

        static const std::string ALLOWED_COMMANDS[] = {
            "run", "pause", "stepinto", "stepover", "stepout", "stop", "restart",
            "bp", "bphws", "bphwc", "bphwd",
            "set", "setcip", "dump", "analyze",
            "modpath", "modbase", "modsize",
            "TraceIntoConditional", "TraceSetLog", "AnimateCommand"
        };

        for (const auto& allowed : ALLOWED_COMMANDS) {
            if (cmd == allowed) return true;
        }
        return false;
    }

    // Strip all non-hexadecimal characters from a string and cap length at 4096.
    [[nodiscard]] static std::string sanitize_hex_string(const std::string& input) {
        std::string result;
        result.reserve(std::min(input.size(), static_cast<size_t>(4096)));

        for (size_t i = 0; i < input.size() && result.size() < 4096; ++i) {
            char c = input[i];
            if ((c >= '0' && c <= '9') ||
                (c >= 'a' && c <= 'f') ||
                (c >= 'A' && c <= 'F')) {
                result.push_back(c);
            }
        }
        return result;
    }

    // Safely convert a string to uint64_t with min/max bounds checking.
    [[nodiscard]] static uint64_t safe_stoull(const std::string& str, uint64_t min_val, uint64_t max_val, bool& ok) {
        ok = false;
        if (str.empty()) return 0;

        try {
            size_t idx = 0;
            uint64_t value = std::stoull(str, &idx, 0);

            if (idx != str.size()) return 0; // trailing junk

            if (value >= min_val && value <= max_val) {
                ok = true;
                return value;
            }
            return 0;
        } catch (...) {
            return 0;
        }
    }

    // Parse a size string with fallback default and max cap.
    [[nodiscard]] static size_t safe_size(const std::string& str, size_t default_val, size_t max_val) {
        if (str.empty()) return default_val;

        bool ok = false;
        uint64_t value = safe_stoull(str, 0, max_val, ok);
        if (!ok) return default_val;

        return static_cast<size_t>(value);
    }

private:
    c_input_sanitizer() = delete;
    ~c_input_sanitizer() = delete;
    c_input_sanitizer(const c_input_sanitizer&) = delete;
    c_input_sanitizer& operator=(const c_input_sanitizer&) = delete;
};
