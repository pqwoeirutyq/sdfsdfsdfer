#include "plugin.h"

#include <memory>

std::unique_ptr<CPlugin> plugin;

BOOL APIENTRY DllMain(HMODULE hModule, DWORD dwReason, LPVOID lpReserved)
{
    if (dwReason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hModule);
        
        plugin = std::make_unique<CPlugin>(hModule);
    }
    else if (dwReason == DLL_PROCESS_DETACH)
        plugin.reset();
    
    return TRUE;
}