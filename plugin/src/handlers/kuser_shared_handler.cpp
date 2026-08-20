#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

// KUSER_SHARED_DATA layout (simplified, Windows 10/11 x64)
// Located at 0x7FFE0000 in user-mode (read-only shared page)
#pragma pack(push,1)
struct KUSER_SHARED_DATA_PARTIAL {
    ULONG TickCountLowDeprecated;           // 0x000
    ULONG TickCountMultiplier;              // 0x004
    ULONG InterruptTime_LowPart;           // 0x008
    ULONG InterruptTime_High1Time;         // 0x00C
    ULONG InterruptTime_High2Time;         // 0x010
    ULONG SystemTime_LowPart;             // 0x014
    ULONG SystemTime_High1Time;           // 0x018
    ULONG SystemTime_High2Time;           // 0x01C
    ULONG TimeZoneBias_LowPart;           // 0x020
    ULONG TimeZoneBias_High1Time;         // 0x024
    ULONG TimeZoneBias_High2Time;         // 0x028
    WORD  ImageNumberLow;                  // 0x02C
    WORD  ImageNumberHigh;                 // 0x02E
    WCHAR NtSystemRoot[260];               // 0x030
    ULONG MaxStackTraceDepth;              // 0x238
    ULONG CryptoExponent;                  // 0x23C
    ULONG TimeZoneId;                      // 0x240
    ULONG LargePageMinimum;                // 0x244
    ULONG AitSamplingValue;                // 0x248
    ULONG AppCompatFlag;                   // 0x24C
    ULONGLONG RNGSeedVersion;              // 0x250
    ULONG GlobalValidationRunlevel;        // 0x258
    LONG  TimeZoneBiasStamp;              // 0x25C
    ULONG NtBuildNumber;                   // 0x260
    ULONG NtProductType;                   // 0x264
    BYTE  ProductTypeIsValid;              // 0x268
    BYTE  Reserved0[3];
    USHORT NativeProcessorArchitecture;    // 0x26C
    ULONG NtMajorVersion;                  // 0x26E (wrong offset, illustrative)
    ULONG NtMinorVersion;
    // ... KdDebuggerEnabled at 0x2D4
};
#pragma pack(pop)

namespace handlers {

void register_kuser_shared_routes(c_http_router& router) {

    // Dump all KUSER_SHARED_DATA fields
    router.post("/api/kuser_shared/dump_fields", [](const httplib::Request& req, httplib::Response& res) {
        json result;

        // Access KUSER_SHARED_DATA at its well-known fixed user-mode VA
        const volatile BYTE* kusd = reinterpret_cast<const volatile BYTE*>(0x7FFE0000);

        try {
            // Read key fields at known offsets (Windows 10/11 x64)
            result["base_address"] = "0x7FFE0000";
            result["fields"] = json::object();

            auto read32 = [&](size_t off) -> ULONG {
                return *reinterpret_cast<const volatile ULONG*>(kusd + off);
            };
            auto read64 = [&](size_t off) -> ULONGLONG {
                return *reinterpret_cast<const volatile ULONGLONG*>(kusd + off);
            };
            auto read16 = [&](size_t off) -> USHORT {
                return *reinterpret_cast<const volatile USHORT*>(kusd + off);
            };
            auto read8 = [&](size_t off) -> BYTE {
                return *reinterpret_cast<const volatile BYTE*>(kusd + off);
            };

            result["fields"]["TickCountMultiplier"]         = read32(0x004);
            result["fields"]["NtBuildNumber"]               = read32(0x260);
            result["fields"]["NtMajorVersion"]              = read32(0x26C);
            result["fields"]["NtMinorVersion"]              = read32(0x270);
            result["fields"]["NativeProcessorArchitecture"] = read16(0x26A);
            result["fields"]["KdDebuggerEnabled"]           = read8(0x2D4);
            result["fields"]["KdDebuggerNotPresent"]        = read8(0x2D5);
            result["fields"]["SystemCall"]                  = read32(0x308); // SYSCALL dispatch
            result["fields"]["TickCount_LowPart"]          = read32(0x320);
            result["fields"]["TickCount_High1Time"]        = read32(0x324);
            result["fields"]["Cookie"]                      = read32(0x330);
            result["fields"]["ConsoleSessionForegroundProcessId"] = read64(0x3C0);

            // Read NtSystemRoot
            const volatile WCHAR* sysroot = reinterpret_cast<const volatile WCHAR*>(kusd + 0x030);
            char sysrootA[MAX_PATH] = {};
            WCHAR tmp[260] = {};
            for (int i = 0; i < 259; i++) { tmp[i] = sysroot[i]; if (!tmp[i]) break; }
            WideCharToMultiByte(CP_UTF8, 0, tmp, -1, sysrootA, sizeof(sysrootA), nullptr, nullptr);
            result["fields"]["NtSystemRoot"] = std::string(sysrootA);

        } catch (...) {
            result["error"] = "Access fault reading KUSER_SHARED_DATA";
        }

        result["arch_note"] = "0x7FFE0000 = user-mode RO alias of kernel 0xFFDF0000 (x86) / KUSER_SHARED_DATA_VA (x64)";
        res.set_content(result.dump(), "application/json");
    });

    // Detect debugger-presence flags in KUSER_SHARED_DATA
    router.post("/api/kuser_shared/detect_debugger_flags", [](const httplib::Request& req, httplib::Response& res) {
        json result;

        const volatile BYTE* kusd = reinterpret_cast<const volatile BYTE*>(0x7FFE0000);
        BYTE kdEnabled = *reinterpret_cast<const volatile BYTE*>(kusd + 0x2D4);
        BYTE kdNotPresent = *reinterpret_cast<const volatile BYTE*>(kusd + 0x2D5);

        result["KdDebuggerEnabled"]    = (int)kdEnabled;
        result["KdDebuggerNotPresent"] = (int)kdNotPresent;
        result["kernel_debugger_attached"] = (kdEnabled != 0 && kdNotPresent == 0);
        result["antidebug_check"] = "Malware reads KdDebuggerEnabled from 0x7FFE02D4 as an anti-analysis check — faster than NtQuerySystemInformation and harder to hook";

        result["bypass_techniques"] = {
            "Patch byte at 0x7FFE02D4 to 0x00 and 0x7FFE02D5 to 0x01 in the process address space",
            "Note: page is read-only — requires NtProtectVirtualMemory to PAGE_READWRITE first",
            "Alternative: hook NtQuerySystemInformation(SystemKernelDebuggerInformation)"
        };

        // Also check IsDebuggerPresent (PEB.BeingDebugged)
        BOOL isDebuggedPEB = IsDebuggerPresent();
        result["peb_being_debugged"] = (bool)isDebuggedPEB;
        result["ntglobalflag_check"] = "PEB.NtGlobalFlag should be 0x70 under debugger (FLG_HEAP_ENABLE_TAIL_CHECK | FLG_HEAP_ENABLE_FREE_CHECK | FLG_HEAP_VALIDATE_PARAMETERS)";

        res.set_content(result.dump(), "application/json");
    });

    // Monitor TickCount drift for hypervisor timing jitter
    router.post("/api/kuser_shared/monitor_tick_drift", [](const httplib::Request& req, httplib::Response& res) {
        json body;
        try { body = json::parse(req.body); } catch (...) { body = json::object(); }

        int iterations = std::min(body.value("iterations", 10), 100);
        json result;
        result["samples"] = json::array();

        const volatile BYTE* kusd = reinterpret_cast<const volatile BYTE*>(0x7FFE0000);
        auto readTick = [&]() -> ULONGLONG {
            // TickCount.QuadPart = (High1Time << 32) | LowPart, with High2Time guard
            ULONG lo = *reinterpret_cast<const volatile ULONG*>(kusd + 0x320);
            ULONG hi = *reinterpret_cast<const volatile ULONG*>(kusd + 0x324);
            return ((ULONGLONG)hi << 32) | lo;
        };

        LARGE_INTEGER freq, t0, t1;
        QueryPerformanceFrequency(&freq);
        ULONGLONG prevTick = readTick();
        for (int i = 0; i < iterations; i++) {
            QueryPerformanceCounter(&t0);
            Sleep(10);
            QueryPerformanceCounter(&t1);
            ULONGLONG curTick = readTick();

            json sample;
            sample["iteration"] = i;
            sample["tick_delta"] = (LONGLONG)(curTick - prevTick);
            sample["qpc_elapsed_ms"] = (double)(t1.QuadPart - t0.QuadPart) * 1000.0 / freq.QuadPart;
            sample["jitter_ms"] = sample["qpc_elapsed_ms"].get<double>() - 10.0;
            result["samples"].push_back(sample);
            prevTick = curTick;
        }

        result["note"] = "Large QPC/TickCount jitter > 2ms indicates hypervisor-introduced timing interference or hardware performance throttling. Used to detect VM environments.";
        result["systemcall_dispatch"] = {
            {"offset","0x308"},
            {"value_0","SYSCALL (native x64)"},
            {"value_1","INT 2E (WOW64/legacy)"},
            {"heaven_gate_note","SystemCall=0 with WOW64 process means Heaven's Gate (32->64 far call 0x33:addr) is available"}
        };
        res.set_content(result.dump(), "application/json");
    });
}

} // namespace handlers
