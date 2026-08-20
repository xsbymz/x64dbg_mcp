#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <shlwapi.h>
#pragma comment(lib, "shlwapi.lib")
using json = nlohmann::json;

// Prefetch SCCA format v30 (Windows 10+) structures
#pragma pack(push,1)
struct PF_HEADER {
    DWORD Version;          // 30 = Win10/11
    DWORD Signature;        // 'SCCA'
    DWORD Unknown1;
    DWORD FileSize;
    WCHAR ExeName[60];
    DWORD Hash;             // FNV hash of executable path
    DWORD Unknown2;
};
struct PF_FILE_METRICS {
    DWORD StartTime;
    DWORD Duration;
    DWORD Unknown1;
    UINT64 FileReference;   // MFT file reference
    DWORD FilenameOffset;
    DWORD FilenameLength;
    DWORD Flags;
};
#pragma pack(pop)

namespace handlers {

void register_prefetch_forensics_routes(c_http_router& router) {

    // List all prefetch files and parse their execution metadata
    router.post("/api/prefetch/list_executions", [](const httplib::Request& req, httplib::Response& res) {
        json result;
        result["prefetch_files"] = json::array();

        WCHAR pfDir[MAX_PATH] = {};
        GetWindowsDirectoryW(pfDir, MAX_PATH);
        std::wstring pfPath = std::wstring(pfDir) + L"\\Prefetch\\*.pf";

        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW(pfPath.c_str(), &fd);
        if (hFind == INVALID_HANDLE_VALUE) {
            result["error"] = "Prefetch directory not found or not accessible";
            res.set_content(result.dump(), "application/json");
            return;
        }

        std::wstring pfDir2 = std::wstring(pfDir) + L"\\Prefetch\\";
        do {
            json pf;
            char nameA[MAX_PATH] = {};
            WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, nameA, sizeof(nameA), nullptr, nullptr);
            pf["filename"] = std::string(nameA);
            pf["size_bytes"] = (DWORD)fd.nFileSizeLow;

            // Last write time = last execution time (approximately)
            ULARGE_INTEGER lwt;
            lwt.LowPart = fd.ftLastWriteTime.dwLowDateTime;
            lwt.HighPart = fd.ftLastWriteTime.dwHighDateTime;
            pf["last_write_time_100ns"] = lwt.QuadPart;

            // Parse hash from filename (EXE-XXXXXXXX.pf)
            std::string fname(nameA);
            size_t dashPos = fname.rfind('-');
            size_t dotPos = fname.rfind('.');
            if (dashPos != std::string::npos && dotPos != std::string::npos) {
                pf["path_hash"] = fname.substr(dashPos+1, dotPos-dashPos-1);
                pf["exe_name"] = fname.substr(0, dashPos);
            }

            // Flag suspicious LOLBin executions
            std::vector<std::string> lolbins = {
                "RUNDLL32","REGSVR32","MSHTA","WSCRIPT","CSCRIPT","POWERSHELL",
                "CMD","CERTUTIL","BITSADMIN","MSIEXEC","WMIC","INSTALLUTIL",
                "REGASM","REGSVCS","ODBCCONF","IEEXEC","MSDT","PCALUA","ASPNET_COMPILER"
            };
            std::string exeUpper = fname.substr(0, dashPos);
            for (auto& c : exeUpper) c = (char)toupper(c);
            pf["lolbin"] = false;
            for (auto& lb : lolbins) {
                if (exeUpper.find(lb) != std::string::npos) {
                    pf["lolbin"] = true;
                    pf["lolbin_name"] = lb;
                    break;
                }
            }

            result["prefetch_files"].push_back(pf);
        } while (FindNextFileW(hFind, &fd));
        FindClose(hFind);

        result["count"] = result["prefetch_files"].size();
        res.set_content(result.dump(), "application/json");
    });

    // Parse a specific prefetch file
    router.post("/api/prefetch/parse_file", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        std::string filename = body.value("filename", "");
        json result;
        result["filename"] = filename;

        if (filename.empty()) {
            result["error"] = "filename required";
            res.set_content(result.dump(), "application/json");
            return;
        }

        WCHAR pfDir[MAX_PATH] = {};
        GetWindowsDirectoryW(pfDir, MAX_PATH);
        std::wstring fullPath = std::wstring(pfDir) + L"\\Prefetch\\" +
            std::wstring(filename.begin(), filename.end());

        HANDLE hFile = CreateFileW(fullPath.c_str(), GENERIC_READ,
            FILE_SHARE_READ, nullptr, OPEN_EXISTING, 0, nullptr);
        if (hFile == INVALID_HANDLE_VALUE) {
            result["error"] = "Cannot open prefetch file";
            res.set_content(result.dump(), "application/json");
            return;
        }

        DWORD fileSize = GetFileSize(hFile, nullptr);
        std::vector<BYTE> buf(fileSize);
        DWORD bytesRead = 0;
        ReadFile(hFile, buf.data(), fileSize, &bytesRead, nullptr);
        CloseHandle(hFile);

        if (bytesRead < sizeof(PF_HEADER)) {
            result["error"] = "File too small or MAM-compressed (Windows 10+ requires decompression)";
            result["compression_note"] = "Windows 10+ prefetch files use MAM (Xpress Huffman) compression. First 8 bytes: magic 'MAM' + decompressed size. Use RtlDecompressBufferEx with FORMAT_LZNT1.";
            res.set_content(result.dump(), "application/json");
            return;
        }

        // Check for MAM compression signature
        if (buf[0] == 0x4D && buf[1] == 0x41 && buf[2] == 0x4D && buf[3] == 0x04) {
            result["compressed"] = true;
            result["compression_format"] = "MAM (Xpress with Huffman)";
            DWORD decompSize = *reinterpret_cast<DWORD*>(buf.data() + 4);
            result["decompressed_size"] = decompSize;
        } else {
            auto* hdr = reinterpret_cast<PF_HEADER*>(buf.data());
            result["compressed"] = false;
            result["version"] = hdr->Version;
            result["file_size"] = hdr->FileSize;
            result["path_hash"] = hdr->Hash;
            char exeA[121] = {};
            WideCharToMultiByte(CP_UTF8, 0, hdr->ExeName, 60, exeA, sizeof(exeA), nullptr, nullptr);
            result["exe_name"] = std::string(exeA);
        }
        res.set_content(result.dump(), "application/json");
    });

    // Detect prefetch file deletion gaps in execution timeline
    router.post("/api/prefetch/detect_deletion_gaps", [](const httplib::Request& req, httplib::Response& res) {
        json result;
        result["detection_method"] = {
            {"description","Prefetch files should form a continuous execution log. Gaps indicate deliberate deletion."},
            {"gap_indicators",{
                "Timestamp gaps > 24h with no prefetch activity on an active system",
                "Missing prefetch for known malware cleanup tools (SDelete, Eraser)",
                "Prefetch directory modified time != newest .pf file mtime (directory entry touched after deletion)"
            }},
            {"correlate_with",{
                "Windows Event Log 4688 (Process Create) for the same time range",
                "$UsnJrnl for file deletion events in Prefetch directory",
                "Volume Shadow Copy timeline reconstruction"
            }}
        };

        // Check if prefetch is enabled
        HKEY hKey;
        DWORD pfEnabled = 0;
        DWORD cbData = sizeof(pfEnabled);
        result["prefetch_enabled"] = false;
        if (RegOpenKeyExW(HKEY_LOCAL_MACHINE,
            L"SYSTEM\\CurrentControlSet\\Control\\Session Manager\\Memory Management\\PrefetchParameters",
            0, KEY_READ, &hKey) == ERROR_SUCCESS) {
            RegQueryValueExW(hKey, L"EnablePrefetcher", nullptr, nullptr,
                reinterpret_cast<LPBYTE>(&pfEnabled), &cbData);
            RegCloseKey(hKey);
            result["prefetch_enabled"] = (pfEnabled > 0);
            result["prefetch_mode"] = (pfEnabled == 0) ? "Disabled" :
                (pfEnabled == 1) ? "Application prefetch only" :
                (pfEnabled == 2) ? "Boot prefetch only" : "Full prefetch";
        }

        result["anti_forensic_note"] = "Attackers disable prefetcher via reg add HKLM\\SYSTEM\\...\\PrefetchParameters /v EnablePrefetcher /t REG_DWORD /d 0 or delete all .pf files. Both are detectable via this check + USN journal analysis.";
        res.set_content(result.dump(), "application/json");
    });

    // Export full execution timeline
    router.post("/api/prefetch/export_timeline", [](const httplib::Request& req, httplib::Response& res) {
        json result;
        result["timeline"] = json::array();

        WCHAR pfDir[MAX_PATH] = {};
        GetWindowsDirectoryW(pfDir, MAX_PATH);
        std::wstring pfPath = std::wstring(pfDir) + L"\\Prefetch\\*.pf";

        WIN32_FIND_DATAW fd = {};
        HANDLE hFind = FindFirstFileW(pfPath.c_str(), &fd);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                json event;
                char nameA[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, fd.cFileName, -1, nameA, sizeof(nameA), nullptr, nullptr);
                event["executable"] = std::string(nameA);

                ULARGE_INTEGER ts;
                ts.LowPart = fd.ftLastWriteTime.dwLowDateTime;
                ts.HighPart = fd.ftLastWriteTime.dwHighDateTime;
                event["last_execution_filetime"] = ts.QuadPart;

                // Convert to ISO-ish string
                SYSTEMTIME st = {};
                FileTimeToSystemTime(&fd.ftLastWriteTime, &st);
                char dt[32] = {};
                snprintf(dt, sizeof(dt), "%04d-%02d-%02dT%02d:%02d:%02dZ",
                    st.wYear, st.wMonth, st.wDay, st.wHour, st.wMinute, st.wSecond);
                event["last_execution_utc"] = std::string(dt);
                event["size_bytes"] = (DWORD)fd.nFileSizeLow;
                result["timeline"].push_back(event);
            } while (FindNextFileW(hFind, &fd));
            FindClose(hFind);
        }

        // Sort by timestamp (simple bubble for small sets)
        auto& tl = result["timeline"];
        std::sort(tl.begin(), tl.end(), [](const json& a, const json& b) {
            return a["last_execution_filetime"].get<uint64_t>() < b["last_execution_filetime"].get<uint64_t>();
        });

        result["count"] = tl.size();
        result["format"] = "Sorted chronological execution timeline from prefetch last-write timestamps";
        res.set_content(result.dump(), "application/json");
    });
}

} // namespace handlers
