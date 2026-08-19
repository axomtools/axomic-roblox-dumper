#include "memoryutils.h"
#include <tlhelp32.h>
#include <psapi.h>

unsigned long getprocessid(const char* name)
{
    unsigned long pid = 0;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPPROCESS, 0);
    PROCESSENTRY32 pe = { sizeof(PROCESSENTRY32) };
    if (Process32First(snap, &pe))
    {
        do {
            if (!_stricmp(pe.szExeFile, name))
            {
                pid = pe.th32ProcessID;
                break;
            }
        } while (Process32Next(snap, &pe));
    }
    CloseHandle(snap);
    return pid;
}

void* getmodulebaseexternal(void* process, const char* name)
{
    HMODULE modules[1024];
    unsigned long needed;
    if (EnumProcessModules((HANDLE)process, modules, sizeof(modules), &needed))
    {
        for (size_t i = 0; i < needed / sizeof(HMODULE); ++i)
        {
            char modname[MAX_PATH];
            if (GetModuleBaseNameA((HANDLE)process, modules[i], modname, sizeof(modname)))
            {
                if (!_stricmp(modname, name))
                    return modules[i];
            }
        }
    }
    return nullptr;
}

void* getmodulebaseinternal(const char* name)
{
    HMODULE mod = GetModuleHandleA(name);
    if (mod) return mod;
    HANDLE snap = CreateToolhelp32Snapshot(TH32CS_SNAPMODULE, GetCurrentProcessId());
    MODULEENTRY32 me = { sizeof(MODULEENTRY32) };
    if (Module32First(snap, &me))
    {
        do {
            if (!_stricmp(me.szModule, name))
            {
                CloseHandle(snap);
                return me.hModule;
            }
        } while (Process32Next(snap, &me));
    }
    CloseHandle(snap);
    return nullptr;
}
