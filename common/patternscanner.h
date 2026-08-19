#pragma once
#include <vector>
#include <string>
#include <cstdint>

std::vector<unsigned char> parsepattern(const std::string& text);
std::string makemask(const std::vector<unsigned char>& pattern);

unsigned long long scanpatternexternal(void* process, void* module, const std::vector<unsigned char>& pattern, const std::string& mask);
unsigned long long scanpatterninternal(void* module, const std::vector<unsigned char>& pattern, const std::string& mask);

unsigned long long resolveoffset(unsigned long long address, int offset);
unsigned long long readaddressexternal(void* process, unsigned long long address);
unsigned long long readaddressinternal(unsigned long long address);

unsigned long long finddatamodelheuristicinternal(void* module);
unsigned long long finddatamodelheuristicexternal(void* process, void* module);
