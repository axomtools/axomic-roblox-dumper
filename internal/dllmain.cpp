#include <windows.h>
#include <iostream>
#include "../common/patternscanner.h"
#include "../common/memoryutils.h"

void dumpoffsetinternal()
{
    void* base = getmodulebaseinternal("RobloxPlayerBeta.exe");
    if (!base) return;

    unsigned long long dmsig = finddatamodelheuristicinternal(base);
    if (!dmsig) { std::cout << "datamodel not found\n"; return; }
    unsigned long long datamodel = resolveoffset(dmsig, 3);

    unsigned long long gamebase = readaddressinternal(datamodel + 0x8);
    unsigned long long localplayer = readaddressinternal(gamebase + 0x418);
    unsigned long long character = localplayer ? readaddressinternal(localplayer + 0x180) : 0;
    unsigned long long humanoid = character ? readaddressinternal(character + 0x178) : 0;

    std::cout << "[internal] base        : 0x" << std::hex << (unsigned long long)base << '\n';
    std::cout << "[internal] datamodel   : 0x" << datamodel << '\n';
    std::cout << "[internal] gamebase    : 0x" << gamebase << '\n';
    std::cout << "[internal] localplayer : 0x" << localplayer << '\n';
    std::cout << "[internal] character   : 0x" << character << '\n';
    std::cout << "[internal] humanoid    : 0x" << humanoid << '\n';
}

BOOL APIENTRY DllMain(HMODULE hmodule, unsigned long reason, void* reserved)
{
    if (reason == DLL_PROCESS_ATTACH)
    {
        DisableThreadLibraryCalls(hmodule);
        CreateThread(nullptr, 0, (LPTHREAD_START_ROUTINE)dumpoffsetinternal, nullptr, 0, nullptr);
    }
    return TRUE;
}
