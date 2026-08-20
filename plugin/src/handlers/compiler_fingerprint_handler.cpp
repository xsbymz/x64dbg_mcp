#include "plugin.h"
#include "http/c_http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_compiler_fingerprint_routes(c_http_router& router) {
    router.post("/api/compiler_fp/identify_toolchain", [](const s_http_request& req) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string moduleName = body.value("module_name", "");
        json result;
        result["module_name"] = moduleName;
        result["compiler_signatures"] = {
            {"MSVC", "__tmainCRTStartup / mainCRTStartup entry pattern, .CRT$XIA section, __GSHandlerCheck security cookie"},
            {"GCC_MinGW", "__gxx_personality_v0, .init_array / .fini_array, ___main runtime initialization"},
            {"Clang_LLVM", "LLVM-specific instruction selection idioms, specific register allocation order, llvm.org PDB paths"},
            {"Rust", "rust_panic / core::panicking, .rustc section, mangled names with _R prefix (v0 mangling)"},
            {"Go", "runtime.main, runtime.gopanic, .gopclntab pclntab function metadata table"},
            {"Delphi", "PChar / ShortString runtime helpers, InitTable in DATA section, Delphi VMT headers"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/compiler_fp/extract_version_indicators", [](const s_http_request& req) {
        json result;
        result["version_indicators"] = {
            {"Rich_Header", "Contains ProdID / BuildID mapping to exact Visual Studio toolchain build version"},
            {"_MSC_VER_Signatures", "Specific CRT library routines (e.g. ucrtbase.dll vs msvcr120.dll vs msvcrt.dll)"},
            {"Default_Alignment", "Section alignment and file alignment defaults across compiler versions"}
        };
        return s_http_response::ok(result.dump());;
    });

    router.post("/api/compiler_fp/detect_obfuscated_compiler_trails", [](const s_http_request& req) {
        json result;
        result["obfuscation_indicators"] = {
            "Stripped or fake Rich Header with invalid XOR checksum",
            "Mismatched CRT runtime vs reported PE linker version",
            "Deliberately wiped PDB debug directory with non-zero TimeDateStamp"
        };
        return s_http_response::ok(result.dump());;
    });
}
} // namespace handlers

