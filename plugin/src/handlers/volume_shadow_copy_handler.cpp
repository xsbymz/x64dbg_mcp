#include "plugin.h"
#include "../http_router.h"
#include <nlohmann/json.hpp>
using json = nlohmann::json;

namespace handlers {
void register_volume_shadow_copy_routes(c_http_router& router) {
    router.post("/api/vss/enumerate_snapshots", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["vss_device_namespace"] = "\\\\?\\GLOBALROOT\\Device\\HarddiskVolumeShadowCopy*";
        result["vss_management_interfaces"] = {
            {"VSS_COM_API", "IVssBackupComponents, IVssAsync, IVssEnumObject"},
            {"WMI_Provider", "SELECT * FROM Win32_ShadowCopy"},
            {"VSSADMIN_CLI", "vssadmin list shadows / vssadmin delete shadows /all /quiet"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/vss/detect_deletion_attempts", [](const httplib::Request&, httplib::Response& res) {
        json result;
        result["ransomware_vss_deletion_techniques"] = {
            {"CLI_vssadmin", "vssadmin.exe delete shadows /all /quiet"},
            {"CLI_wmic", "wmic.exe shadowcopy delete"},
            {"PowerShell_WMI", "Get-WmiObject Win32_ShadowCopy | ForEach-Object { $_.Delete() }"},
            {"CLI_wbadmin", "wbadmin.exe delete catalog -quiet / delete systemstatebackup"},
            {"CLI_bcdedit", "bcdedit.exe /set {default} recoveryenabled No / bootstatuspolicy ignoreallfailures"},
            {"Direct_IOCTL", "Sending IOCTL_VOLSNAP_DELETE_OLDEST_SNAPSHOT directly to \\Device\\VolSnap driver"}
        };
        res.set_content(result.dump(), "application/json");
    });

    router.post("/api/vss/mount_and_read_previous_version", [](const httplib::Request& req, httplib::Response& res) {
        json body; try { body = json::parse(req.body); } catch(...) { body = json::object(); }
        std::string filePath = body.value("file_path", "");
        json result;
        result["file_path"] = filePath;
        result["recovery_workflow"] = "Create symbolic link or mount volume shadow copy endpoint to extract unencrypted prior versions of files targeted by ransomware encryption";
        res.set_content(result.dump(), "application/json");
    });
}
} // namespace handlers
