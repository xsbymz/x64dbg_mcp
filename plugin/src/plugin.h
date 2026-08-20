#pragma once

#include <windows.h>
#include <winternl.h>
#include <iphlpapi.h>
#include <ws2tcpip.h>
#include <ntstatus.h>
#include <wincrypt.h>
#include <netfw.h>
#include <intrin.h>
#include <tlhelp32.h>
#include <dbghelp.h>

#include "bridgemain.h"
#include "_dbgfunctions.h"
#include "_scriptapi.h"
#include "_scriptapi_memory.h"
#include "_plugins.h"

#pragma comment(lib, "iphlpapi.lib")
#pragma comment(lib, "ws2_32.lib")
#pragma comment(lib, "advapi32.lib")
#pragma comment(lib, "crypt32.lib")
#pragma comment(lib, "dbghelp.lib")

#define PLUGIN_NAME "x64dbg_mcp"
#define PLUGIN_VERSION 0x020600
#define PLUGIN_VERSION_STR "2.6.0"
#define PLUGIN_AUTHOR "x64dbg_mcp contributors"
#define PLUGIN_URL "https://github.com/x64dbg/x64dbg_mcp"
