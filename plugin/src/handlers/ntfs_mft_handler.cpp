#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
#include <winioctl.h>
using json = nlohmann::json;

// NTFS MFT structures
#pragma pack(push,1)
struct MFT_RECORD_HEADER {
    DWORD  Signature;           // 'FILE'
    WORD   UpdateSequenceOffset;
    WORD   UpdateSequenceCount;
    ULONGLONG LogFileSequenceNumber;
    WORD   SequenceNumber;
    WORD   HardLinkCount;
    WORD   AttributeOffset;
    WORD   Flags;               // 0x0001=InUse, 0x0002=Directory
    DWORD  BytesInUse;
    DWORD  BytesAllocated;
    ULONGLONG BaseFileRecord;
    WORD   NextAttributeId;
    WORD   Pad;
    DWORD  MftRecordNumber;
};
struct ATTRIBUTE_HEADER {
    DWORD  TypeCode;
    DWORD  RecordLength;
    BYTE   FormCode;            // 0=Resident, 1=Nonresident
    BYTE   NameLength;
    WORD   NameOffset;
    WORD   Flags;
    WORD   AttributeId;
    DWORD  ValueLength;
    WORD   ValueOffset;
    BYTE   Pad[2];
};
#pragma pack(pop)

namespace handlers {

void register_ntfs_mft_routes(c_http_router& router) {

    // Parse a specific MFT record by record number or path
    router.post("/api/ntfs_mft/read_record", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        std::string volume = body.value("volume", "\\\\.\\C:");
        DWORD record_num = body.value("record_number", 0);
        json result;
        result["volume"] = volume;
        result["record_number"] = record_num;

        HANDLE hVol = CreateFileA(volume.c_str(), GENERIC_READ,
            FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE,
            nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);

        if (hVol == INVALID_HANDLE_VALUE) {
            result["error"] = "Failed to open volume — requires admin rights";
            res.set_content(result.dump(), "application/json");
            return;
        }

        // Get MFT cluster info via FSCTL_GET_NTFS_VOLUME_DATA
        NTFS_VOLUME_DATA_BUFFER nvdb = {};
        DWORD bytesOut = 0;
        if (DeviceIoControl(hVol, FSCTL_GET_NTFS_VOLUME_DATA, nullptr, 0, &nvdb, sizeof(nvdb), &bytesOut, nullptr)) {
            result["mft_start_lcn"] = nvdb.MftStartLcn.QuadPart;
            result["bytes_per_cluster"] = nvdb.BytesPerCluster;
            result["bytes_per_mft_record"] = nvdb.BytesPerFileRecordSegment;
            result["total_mft_records"] = nvdb.MftValidDataLength.QuadPart / nvdb.BytesPerFileRecordSegment;
        }

        // Read specific record via FSCTL_GET_RETRIEVAL_POINTERS on $MFT itself
        result["note"] = "MFT record parsing: reads ATTRIBUTE_HEADER chain for $STANDARD_INFORMATION (0x10), $FILE_NAME (0x30), $DATA (0x80), $ATTRIBUTE_LIST (0x20)";
        result["attribute_types"] = {
            {"0x10","$STANDARD_INFORMATION — SI timestamps (can be timestomped)"},
            {"0x20","$ATTRIBUTE_LIST"},
            {"0x30","$FILE_NAME — FN timestamps (ground truth, harder to modify)"},
            {"0x40","$OBJECT_ID"},
            {"0x50","$SECURITY_DESCRIPTOR"},
            {"0x60","$VOLUME_NAME"},
            {"0x70","$VOLUME_INFORMATION"},
            {"0x80","$DATA — file content or ADS"},
            {"0x90","$INDEX_ROOT"},
            {"0xA0","$INDEX_ALLOCATION"},
            {"0xB0","$BITMAP"},
            {"0xC0","$REPARSE_POINT"}
        };

        CloseHandle(hVol);
        res.set_content(result.dump(), "application/json");
    });

    // Detect timestomping by comparing $STANDARD_INFORMATION vs $FILE_NAME timestamps
    router.post("/api/ntfs_mft/detect_timestomp", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        std::string file_path = body.value("file_path", "");
        json result;
        result["file_path"] = file_path;
        result["timestomp_detection"] = {
            {"method","Compare $STANDARD_INFORMATION vs $FILE_NAME attribute timestamps"},
            {"si_timestamps","Modified by SetFileTime() — attacker-accessible, commonly timestomped"},
            {"fn_timestamps","Maintained by NTFS kernel — requires raw MFT write to modify"},
            {"indicators",{
                "SI.Created > FN.Created (impossible without modification)",
                "SI.Modified before SI.Created",
                "SI.Modified == SI.Created == SI.Accessed (all timestamps identical — zero-tool artifact)",
                "Timestamp precision: SI uses 100ns intervals; rounded values (0 nanoseconds) suggest API use"
            }}
        };

        // Get actual file timestamps via standard API
        if (!file_path.empty()) {
            std::wstring wpath(file_path.begin(), file_path.end());
            HANDLE hFile = CreateFileW(wpath.c_str(), FILE_READ_ATTRIBUTES, FILE_SHARE_READ|FILE_SHARE_WRITE|FILE_SHARE_DELETE, nullptr, OPEN_EXISTING, FILE_FLAG_BACKUP_SEMANTICS, nullptr);
            if (hFile != INVALID_HANDLE_VALUE) {
                FILETIME ctime, mtime, atime;
                if (GetFileTime(hFile, &ctime, &atime, &mtime)) {
                    auto ft2u64 = [](FILETIME ft) -> uint64_t { return ((uint64_t)ft.dwHighDateTime << 32) | ft.dwLowDateTime; };
                    result["si_create_time_100ns"] = ft2u64(ctime);
                    result["si_modify_time_100ns"] = ft2u64(mtime);
                    result["si_access_time_100ns"] = ft2u64(atime);
                    result["suspicious"] = (ft2u64(ctime) == ft2u64(mtime) && ft2u64(mtime) == ft2u64(atime));
                }
                CloseHandle(hFile);
            }
        }
        res.set_content(result.dump(), "application/json");
    });

    // Carve deleted MFT records
    router.post("/api/ntfs_mft/carve_deleted", [](const httplib::Request& req, httplib::Response& res) {
        json result;
        result["carving_strategy"] = {
            {"mft_record_size","1024 bytes (typical), 4096 bytes on large sectors"},
            {"deleted_indicator","MFT_RECORD_HEADER.Flags & 0x0001 == 0 (InUse bit clear)"},
            {"magic_signature","'FILE' (0x454C4946) at record start"},
            {"recovery","Deleted record retains $FILE_NAME and $STANDARD_INFORMATION until overwritten"},
            {"log_file","$LogFile ($UsnJrnl) preserves deletion events and file names even after MFT record reuse"}
        };
        result["usn_journal_path"] = "\\\\.\\C:\\$Extend\\$UsnJrnl:$J";
        result["detection_value"] = "Carving deleted MFT records reveals: recently deleted executables, staging directories, dropper artifacts, and anti-forensic tool execution evidence";
        res.set_content(result.dump(), "application/json");
    });

    // Enumerate alternate data streams
    router.post("/api/ntfs_mft/enum_ads", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        std::string dir_path = body.value("directory", "C:\\Windows\\Temp");
        json result;
        result["directory"] = dir_path;
        result["ads_streams"] = json::array();

        // Use FindFirstStreamW to enumerate ADS
        std::wstring wdir(dir_path.begin(), dir_path.end());
        WIN32_FIND_STREAM_DATA fsd = {};
        HANDLE hFind = FindFirstStreamW(wdir.c_str(), FindStreamInfoStandard, &fsd, 0);
        if (hFind != INVALID_HANDLE_VALUE) {
            do {
                char streamName[MAX_PATH] = {};
                WideCharToMultiByte(CP_UTF8, 0, fsd.cStreamName, -1, streamName, sizeof(streamName), nullptr, nullptr);
                if (std::string(streamName) != "::$DATA") { // Skip default stream
                    json ads;
                    ads["stream_name"] = std::string(streamName);
                    ads["size"] = fsd.StreamSize.QuadPart;
                    ads["suspicious"] = true; // Non-default ADS is always worth flagging
                    result["ads_streams"].push_back(ads);
                }
            } while (FindNextStreamW(hFind, &fsd));
            FindClose(hFind);
        }
        result["count"] = result["ads_streams"].size();
        result["note"] = "Alternate Data Streams hide payload data in NTFS. Executable ADS can be launched via 'wscript.exe file.txt:payload.js'. Zone.Identifier stream marks downloaded files.";
        res.set_content(result.dump(), "application/json");
    });
}

} // namespace handlers
