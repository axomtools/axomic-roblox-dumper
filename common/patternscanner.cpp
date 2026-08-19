#include "patternscanner.h"
#include <windows.h>
#include <psapi.h>
#include <cstdio>
#include <algorithm>

std::vector<unsigned char> parsepattern(const std::string& text)
{
    std::vector<unsigned char> result;
    for (size_t i = 0; i < text.length(); )
    {
        if (text[i] == ' ') { ++i; continue; }
        if (text[i] == '?')
        {
            result.push_back(0xCC);
            if (i + 1 < text.length() && text[i + 1] == '?') ++i;
            ++i;
        }
        else
        {
            unsigned int val;
            sscanf_s(text.c_str() + i, "%2x", &val);
            result.push_back((unsigned char)val);
            i += 2;
        }
    }
    return result;
}

std::string makemask(const std::vector<unsigned char>& pattern)
{
    std::string mask;
    for (auto b : pattern)
        mask.push_back((b == 0xCC) ? '?' : 'x');
    return mask;
}

static unsigned long long scanpattern(const unsigned char* data, size_t size, const std::vector<unsigned char>& pattern, const std::string& mask)
{
    for (size_t i = 0; i <= size - pattern.size(); ++i)
    {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j)
        {
            if (mask[j] == 'x' && data[i + j] != pattern[j])
            {
                found = false;
                break;
            }
        }
        if (found) return i;
    }
    return 0;
}

unsigned long long scanpatternexternal(void* process, void* module, const std::vector<unsigned char>& pattern, const std::string& mask)
{
    MODULEINFO info;
    if (!GetModuleInformation((HANDLE)process, (HMODULE)module, &info, sizeof(info))) return 0;
    unsigned long long start = (unsigned long long)module;
    unsigned long long end = start + info.SizeOfImage;

    const size_t pagesize = 4096;
    std::vector<unsigned char> buffer(pagesize);

    for (unsigned long long addr = start; addr < end; addr += pagesize)
    {
        size_t toread = (std::min)(pagesize, (size_t)(end - addr));
        SIZE_T bytesread;
        if (!ReadProcessMemory((HANDLE)process, (LPCVOID)addr, buffer.data(), toread, &bytesread))
            continue;
        if (bytesread < pattern.size()) continue;

        unsigned long long offset = scanpattern(buffer.data(), bytesread, pattern, mask);
        if (offset) return addr + offset;
    }
    return 0;
}

unsigned long long scanpatterninternal(void* module, const std::vector<unsigned char>& pattern, const std::string& mask)
{
    MODULEINFO info;
    GetModuleInformation(GetCurrentProcess(), (HMODULE)module, &info, sizeof(info));
    unsigned long long start = (unsigned long long)module;
    unsigned long long end = start + info.SizeOfImage;

    for (unsigned long long addr = start; addr < end; ++addr)
    {
        bool found = true;
        for (size_t j = 0; j < pattern.size(); ++j)
        {
            if (mask[j] == 'x')
            {
                if (*(unsigned char*)(addr + j) != pattern[j])
                {
                    found = false;
                    break;
                }
            }
        }
        if (found) return addr;
    }
    return 0;
}

unsigned long long resolveoffset(unsigned long long address, int offset)
{
    int32_t disp = *(int32_t*)(address + offset);
    return address + offset + 4 + disp;
}

unsigned long long readaddressexternal(void* process, unsigned long long address)
{
    unsigned long long value;
    ReadProcessMemory((HANDLE)process, (LPCVOID)address, &value, sizeof(value), nullptr);
    return value;
}

unsigned long long readaddressinternal(unsigned long long address)
{
    return *(unsigned long long*)address;
}

static unsigned long long heuristicsearchinternal(void* module, unsigned long long start, unsigned long long end)
{
    for (unsigned long long addr = start; addr < end; ++addr)
    {
        if (*(unsigned short*)addr == 0x058B && *(unsigned char*)(addr + 2) == 0x48)
        {
            unsigned long long target = resolveoffset(addr, 3);
            if (target > 0x10000)
            {
                unsigned long long vtable = readaddressinternal(target);
                if (vtable >= (unsigned long long)module && vtable < end)
                {
                    unsigned long long firstfunc = readaddressinternal(vtable);
                    if (firstfunc >= (unsigned long long)module && firstfunc < end)
                        return addr;
                }
            }
        }
    }
    return 0;
}

static unsigned long long heuristicsearchexternal(void* process, void* module, unsigned long long start, unsigned long long end)
{
    std::vector<unsigned char> buffer(4096);
    for (unsigned long long addr = start; addr < end; addr += 4096)
    {
        size_t toread = (std::min)((size_t)4096, (size_t)(end - addr));
        SIZE_T bytesread;
        if (!ReadProcessMemory((HANDLE)process, (LPCVOID)addr, buffer.data(), toread, &bytesread))
            continue;
        for (size_t i = 0; i < bytesread - 6; ++i)
        {
            if (buffer[i] == 0x48 && buffer[i+1] == 0x8B && buffer[i+2] == 0x05)
            {
                unsigned long long ripaddr = addr + i;
                unsigned long long target = resolveoffset(ripaddr, 3);
                if (target > 0x10000)
                {
                    unsigned long long vtable = readaddressexternal(process, target);
                    if (vtable >= (unsigned long long)module && vtable < end)
                    {
                        unsigned long long firstfunc = readaddressexternal(process, vtable);
                        if (firstfunc >= (unsigned long long)module && firstfunc < end)
                            return ripaddr;
                    }
                }
            }
        }
    }
    return 0;
}

unsigned long long finddatamodelheuristicinternal(void* module)
{
    MODULEINFO info;
    GetModuleInformation(GetCurrentProcess(), (HMODULE)module, &info, sizeof(info));
    unsigned long long start = (unsigned long long)module;
    unsigned long long end = start + info.SizeOfImage;
    return heuristicsearchinternal(module, start, end);
}

unsigned long long finddatamodelheuristicexternal(void* process, void* module)
{
    MODULEINFO info;
    GetModuleInformation((HANDLE)process, (HMODULE)module, &info, sizeof(info));
    unsigned long long start = (unsigned long long)module;
    unsigned long long end = start + info.SizeOfImage;
    return heuristicsearchexternal(process, module, start, end);
}
