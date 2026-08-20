#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
#include <winternl.h>
using json = nlohmann::json;

namespace handlers {

void register_kernel_pool_feng_shui_routes(c_http_router& router) {

    // Scan pool tags via NtQuerySystemInformation(SystemBigPoolInformation)
    router.post("/api/pool/scan_tags", [](const s_http_request& req) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        std::string filter_tag = body.value("tag_filter", "");
        json result;
        result["pool_entries"] = json::array();

        typedef struct _SYSTEM_BIGPOOL_ENTRY {
            ULONG_PTR VirtualAddress;
            SIZE_T SizeInBytes;
            UCHAR Tag[4];
            ULONG EntryType;
        } SYSTEM_BIGPOOL_ENTRY;

        typedef struct _SYSTEM_BIGPOOL_INFORMATION {
            ULONG Count;
            SYSTEM_BIGPOOL_ENTRY AllocatedInfo[1];
        } SYSTEM_BIGPOOL_INFORMATION;

        ULONG bufLen = 0;
        NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)66 /*SystemBigPoolInformation*/, nullptr, 0, &bufLen);
        if (bufLen > 0) {
            std::vector<BYTE> buf(bufLen + 4096);
            if (NT_SUCCESS(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)66, buf.data(), (ULONG)buf.size(), &bufLen))) {
                auto* info = reinterpret_cast<SYSTEM_BIGPOOL_INFORMATION*>(buf.data());
                for (ULONG i = 0; i < info->Count && i < 256; i++) {
                    auto& e = info->AllocatedInfo[i];
                    char tag[5] = {};
                    memcpy(tag, e.Tag, 4);
                    std::string tagStr(tag);
                    if (!filter_tag.empty() && tagStr.find(filter_tag) == std::string::npos) continue;
                    json entry;
                    entry["virtual_address"] = (uintptr_t)e.VirtualAddress;
                    entry["size"] = (uintptr_t)e.SizeInBytes;
                    entry["tag"] = tagStr;
                    entry["entry_type"] = e.EntryType;
                    entry["type_name"] = (e.EntryType == 1) ? "NonPagedPool" : (e.EntryType == 2) ? "PagedPool" : "Unknown";
                    result["pool_entries"].push_back(entry);
                }
            }
        }
        result["count"] = result["pool_entries"].size();
        result["note"] = "Big pool entries from NtQuerySystemInformation(SystemBigPoolInformation). For grooming: identify chunk sizes and tags of target kernel objects (_EPROCESS tag 'Proc', _TOKEN tag 'Toke', _FILE_OBJECT tag 'File').";
        return s_http_response::ok(result.dump());;
    });

    // Layout analysis for groom planning
    router.post("/api/pool/groom_layout", [](const s_http_request& req) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        json result;
        result["known_object_tags"] = {
            {"tag","Proc"},{"object","_EPROCESS"},{"pool","NonPagedPool"},{"typical_size","0xB80"}
        };
        result["groom_strategy"] = {
            {"step1","Spray target pool with same-size controlled objects to fill free slots"},
            {"step2","Free every other object to create alternating free/busy pattern"},
            {"step3","Trigger vulnerable allocation — lands adjacent to your controlled object"},
            {"step4","Overflow/underflow into adjacent free chunk or controlled data"},
            {"step5","Corrupt _LIST_ENTRY Flink/Blink in freed chunk for arbitrary write"}
        };
        result["useful_spray_objects"] = {
            {"IoCompletionReserve","NtCreateIoCompletion — size 0x60, NonPagedPool"},
            {"ThreadPool","NtCreateThreadpoolWork — controllable size"},
            {"Event","NtCreateEvent — size 0x40, NonPagedPool"}
        };
        result["note"] = "Kernel pool feng shui grooming strategy reference for pool overflow exploitation.";
        return s_http_response::ok(result.dump());;
    });

    // Detect pool corruption indicators
    router.post("/api/pool/detect_corruption", [](const s_http_request& req) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        json result;
        result["corruption_indicators"] = json::array();

        // Use NtQuerySystemInformation(SystemPoolTagInformation) to look for anomalies
        ULONG bufLen = 0;
        NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)22 /*SystemPoolTagInformation*/, nullptr, 0, &bufLen);

        typedef struct _SYSTEM_POOL_TAG_INFO {
            ULONG Tag;
            ULONG PagedAllocs;
            ULONG PagedFrees;
            SIZE_T PagedUsed;
            ULONG NonPagedAllocs;
            ULONG NonPagedFrees;
            SIZE_T NonPagedUsed;
        } SYSTEM_POOL_TAG_INFO;

        typedef struct _SYSTEM_POOLTAG_INFORMATION {
            ULONG Count;
            SYSTEM_POOL_TAG_INFO TagInfo[1];
        } SYSTEM_POOLTAG_INFORMATION;

        if (bufLen > 0) {
            std::vector<BYTE> buf(bufLen + 4096);
            if (NT_SUCCESS(NtQuerySystemInformation((SYSTEM_INFORMATION_CLASS)22, buf.data(), (ULONG)buf.size(), &bufLen))) {
                auto* info = reinterpret_cast<SYSTEM_POOLTAG_INFORMATION*>(buf.data());
                for (ULONG i = 0; i < info->Count && i < 512; i++) {
                    auto& t = info->TagInfo[i];
                    // Alloc/Free mismatch > 1000 may indicate corruption or leak
                    long diff = (long)t.PagedAllocs - (long)t.PagedFrees;
                    if (diff > 1000 || diff < -100) {
                        json indicator;
                        char tag[5] = {};
                        memcpy(tag, &t.Tag, 4);
                        indicator["tag"] = std::string(tag);
                        indicator["paged_allocs"] = t.PagedAllocs;
                        indicator["paged_frees"] = t.PagedFrees;
                        indicator["alloc_free_delta"] = diff;
                        indicator["paged_used_bytes"] = (uintptr_t)t.PagedUsed;
                        indicator["anomaly"] = (diff < 0) ? "More frees than allocs — double-free candidate" : "Large unfreed alloc count — pool leak or spray";
                        result["corruption_indicators"].push_back(indicator);
                    }
                }
            }
        }
        result["count"] = result["corruption_indicators"].size();
        return s_http_response::ok(result.dump());;
    });
}

} // namespace handlers


