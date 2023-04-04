#pragma once
#include <Windows.h>
#include <format>
#include <string>
#include <vector>

template<>
struct std::formatter<std::vector<std::uint8_t>>
{
    constexpr auto parse(std::format_parse_context& ctx)
    {
        return ctx.begin();
    }
    auto format(const std::vector<std::uint8_t>& obj, std::format_context& ctx)
    {
        std::format_to(ctx.out(), "<BINARY>");
        for (auto it = obj.begin(); it != obj.end(); it++)
        {
            std::format_to(ctx.out(), "{}", (char)*it);
        }

        return std::format_to(ctx.out(), "</BINARY>");
    }
};

template<>
struct std::formatter<CONTEXT>
{
    constexpr auto parse(std::format_parse_context& ctx)
    {
        return ctx.begin();
    }
    auto format(const CONTEXT& obj, std::format_context& ctx)
    {
        return std::format_to(ctx.out(),
                              "ContextFlags: {:#010x}\n"

                              "\t\t\tEdi: {:#010x}, "
                              "Esi: {:#010x}, "
                              "Ebx: {:#010x}, "
                              "Edx: {:#010x}, "
                              "Ecx: {:#010x}, "
                              "Eax: {:#010x}, "
                              "Ebp: {:#010x}, "
                              "Eip: {:#010x}, "
                              "Esp: {:#010x},\n"

                              "\t\t\tSegGs: {:#010x}, "
                              "SegFs: {:#010x}, "
                              "SegEs: {:#010x}, "
                              "SegDs: {:#010x}, "
                              "SegSs: {:#010x},\n"

                              "\t\t\tDr0: {:#010x}, "
                              "Dr1: {:#010x}, "
                              "Dr2: {:#010x}, "
                              "Dr3: {:#010x}, "
                              "Dr6: {:#010x}, "
                              "Dr7: {:#010x}",

                              obj.ContextFlags,
                              obj.Edi,
                              obj.Esi,
                              obj.Ebx,
                              obj.Edx,
                              obj.Ecx,
                              obj.Eax,
                              obj.Ebp,
                              obj.Eip,
                              obj.Esp,
                              obj.SegGs,
                              obj.SegFs,
                              obj.SegEs,
                              obj.SegDs,
                              obj.SegSs,
                              obj.Dr0,
                              obj.Dr1,
                              obj.Dr2,
                              obj.Dr3,
                              obj.Dr6,
                              obj.Dr7);
    }
};
