// pattern_scanner.cpp

#include <iostream>
#include <Windows.h>
#include <Psapi.h>
#include <vector>

using namespace std;

HMODULE get_default_hmodule(const char *module_name)
{
    if (!module_name || strcmp(module_name, "") == 0)
    {
        return GetModuleHandleW(PCWSTR(module_name));
    }
    else
    {
        return GetModuleHandle(nullptr);
    }
}

extern "C"
{
    // CSGOSimple's pattern scan
    // https://github.com/OneshotGH/CSGOSimple-master/blob/master/CSGOSimple/helpers/utils.cpp
    std::uint8_t *pattern_scan(const char *signature, const char *module_name)
    {

        HMODULE hmodule = get_default_hmodule(module_name);
        MODULEINFO modInfo = {nullptr, 0, nullptr};

        if (GetModuleInformation(GetCurrentProcess(), hmodule, &modInfo, sizeof(MODULEINFO)))
        {

            static auto pattern_to_byte = [](const char *pattern)
            {
                auto bytes = std::vector<int>{};
                auto start = const_cast<char *>(pattern);
                auto end = const_cast<char *>(pattern) + strlen(pattern);

                for (auto current = start; current < end; ++current)
                {
                    if (*current == '?')
                    {
                        ++current;
                        if (*current == '?')
                            ++current;
                        bytes.push_back(-1);
                    }
                    else
                    {
                        bytes.push_back(strtoul(current, &current, 16));
                    }
                }
                return bytes;
            };

            auto dosHeader = (PIMAGE_DOS_HEADER)hmodule;
            auto ntHeaders = (PIMAGE_NT_HEADERS)((std::uint8_t *)hmodule + dosHeader->e_lfanew);

            auto sizeOfImage = ntHeaders->OptionalHeader.SizeOfImage;
            auto patternBytes = pattern_to_byte(signature);
            auto scanBytes = reinterpret_cast<std::uint8_t *>(hmodule);

            auto s = patternBytes.size();
            auto d = patternBytes.data();

            for (auto i = 0ul; i < sizeOfImage - s; ++i)
            {
                bool found = true;

                for (auto j = 0ul; j < s; ++j)
                {
                    if (scanBytes[i + j] != d[j] && d[j] != -1)
                    {
                        found = false;
                        break;
                    }
                }
                if (found)
                {
                    return &scanBytes[i];
                }
            }
        };
        return nullptr;
    }
}