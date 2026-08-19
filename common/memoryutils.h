#pragma once
#include <windows.h>
#include <cstdint>

unsigned long getprocessid(const char* name);
void* getmodulebaseexternal(void* process, const char* name);
void* getmodulebaseinternal(const char* name);
