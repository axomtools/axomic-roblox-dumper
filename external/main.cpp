#include <windows.h>
#include <psapi.h>
#include <iostream>
#include "../common/patternscanner.h"
#include "../common/memoryutils.h"

void dumpoffsetexternal(void* process, void* base)
{
    unsigned long long dmsig = finddatamodelheuristicexternal(process, base);
    if (!dmsig) { std::cout << "datamodel not found\n"; return; }
    unsigned long long datamodel = resolveoffset(dmsig, 3);

    unsigned long long gamebase = readaddressexternal(process, datamodel + 0x8);
    unsigned long long localplayer = readaddressexternal(process, gamebase + 0x418);
    unsigned long long character = localplayer ? readaddressexternal(process, localplayer + 0x180) : 0;
    unsigned long long humanoid = character ? readaddressexternal(process, character + 0x178) : 0;

    std::cout << "[external] base        : 0x" << std::hex << (unsigned long long)base << '\n';
    std::cout << "[external] datamodel   : 0x" << datamodel << '\n';
    std::cout << "[external] gamebase    : 0x" << gamebase << '\n';
    std::cout << "[external] localplayer : 0x" << localplayer << '\n';
    std::cout << "[external] character   : 0x" << character << '\n';
    std::cout << "[external] humanoid    : 0x" << humanoid << '\n';
}

int main()
{
    unsigned long pid = getprocessid("RobloxPlayerBeta.exe");
    if (!pid) { std::cout << "roblox not running\n"; return 1; }

    void* process = OpenProcess(PROCESS_VM_READ | PROCESS_QUERY_INFORMATION, FALSE, pid);
    if (!process) { std::cout << "open process failed\n"; return 1; }

    void* base = getmodulebaseexternal(process, "RobloxPlayerBeta.exe");
    if (!base) { std::cout << "module not found\n"; CloseHandle((HANDLE)process); return 1; }

    dumpoffsetexternal(process, base);
    CloseHandle((HANDLE)process);
    return 0;
}
