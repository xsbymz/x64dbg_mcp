#pragma once

#include <string>
#include <cstdint>
#include <algorithm>
#include <cctype>
#include <windows.h>

class c_path_sanitizer {
public:
    // Resolve a user-provided path against a base directory, rejecting traversal,
    // double backslashes, and paths outside the base.
    [[nodiscard]] static std::string sanitize_path(const std::string& user_path, const std::string& base_dir) {
        if (user_path.empty() || base_dir.empty()) return "";

        if (user_path.find("..") != std::string::npos) return "";
        if (user_path.find("\\\\") != std::string::npos) return "";

        char full_path[MAX_PATH] = {0};
        DWORD len = GetFullPathNameA(user_path.c_str(), MAX_PATH, full_path, nullptr);
        if (len == 0 || len >= MAX_PATH) return "";

        std::string resolved(full_path);

        if (resolved.find("..") != std::string::npos) return "";
        if (resolved.find("\\\\") != std::string::npos) return "";

        std::string normalized_base = base_dir;
        if (!normalized_base.empty() && normalized_base.back() != '\\') {
            normalized_base.push_back('\\');
        }

        if (resolved.size() < normalized_base.size()) return "";
        if (resolved.compare(0, normalized_base.size(), normalized_base) != 0) return "";

        return resolved;
    }

    // Verify that a resolved path is within the allowed base directory.
    [[nodiscard]] static bool is_path_safe(const std::string& resolved_path, const std::string& base_dir) {
        if (resolved_path.empty() || base_dir.empty()) return false;

        std::string normalized_base = base_dir;
        if (!normalized_base.empty() && normalized_base.back() != '\\') {
            normalized_base.push_back('\\');
        }

        if (resolved_path.size() < normalized_base.size()) return false;
        if (resolved_path.compare(0, normalized_base.size(), normalized_base) != 0) return false;

        return true;
    }

    // Extract a safe filename from a user-provided path.
    // Strips directory components, rejects empty names, caps at 255 chars,
    // and allows only [a-zA-Z0-9_.-].
    [[nodiscard]] static std::string get_safe_filename(const std::string& user_filename) {
        if (user_filename.empty()) return "";

        size_t sep1 = user_filename.find_last_of("\\/");
        std::string name = (sep1 == std::string::npos) ? user_filename : user_filename.substr(sep1 + 1);

        size_t colon = name.find(':');
        if (colon != std::string::npos) {
            name = name.substr(colon + 1);
        }

        if (name.empty()) return "";

        std::string safe;
        safe.reserve(std::min(name.size(), static_cast<size_t>(255)));
        for (size_t i = 0; i < name.size() && safe.size() < 255; ++i) {
            char c = name[i];
            if ((c >= 'a' && c <= 'z') || (c >= 'A' && c <= 'Z') ||
                (c >= '0' && c <= '9') || c == '_' || c == '.' || c == '-') {
                safe.push_back(c);
            }
        }

        return safe;
    }

    // Get the x64dbg dump directory from settings, falling back to the current directory.
    [[nodiscard]] static std::string get_dump_directory() {
        char buf[MAX_PATH] = {0};
        if (BridgeSettingGet("Dump", "Directory", buf)) {
            std::string dir(buf);
            if (!dir.empty()) {
                if (dir.back() != '\\') dir.push_back('\\');
                return dir;
            }
        }

        char cwd[MAX_PATH] = {0};
        GetCurrentDirectoryA(MAX_PATH, cwd);
        std::string dir(cwd);
        if (!dir.empty() && dir.back() != '\\') {
            dir.push_back('\\');
        }
        return dir;
    }

private:
    c_path_sanitizer() = delete;
    ~c_path_sanitizer() = delete;
    c_path_sanitizer(const c_path_sanitizer&) = delete;
    c_path_sanitizer& operator=(const c_path_sanitizer&) = delete;
};
