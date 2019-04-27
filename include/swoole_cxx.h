#pragma once

#include "swoole.h"

#include <memory>
#include <string>
#include <cstdio>

namespace swoole
{
namespace cpp_string
{
template<typename ... Args>
inline std::string format(const std::string& format, Args ... args)
{
    size_t size = snprintf(nullptr, 0, format.c_str(), args ...) + 1; // Extra space for '\0'
    std::unique_ptr<char[]> buf(new char[size]);
    snprintf(buf.get(), size, format.c_str(), args ...);
    return std::string(buf.get(), buf.get() + size - 1); // We don't want the '\0' inside
}
}
namespace log
{
static inline void hex_dump(const char *data, size_t length)
{
    swDebug("+----------+------------+-----------+-----------+------------+------------------+");
    for (size_t of = 0; of < length; of += 16)
    {
        char hex[16 * 3 + 1];
        char str[16 + 1];
        size_t i, hof = 0, sof = 0;
        for (i = of; i < of + 16 && i < length; i++)
        {
            hof += sprintf(hex + hof, "%02x ", (data)[i] & 0xff);
            sof += sprintf(str + sof, "%c", isprint((int) (data)[i]) ? (data)[i] : '.');
        }
        swDebug("| %08x | %-48s| %-16s |", of, hex, str);
    }
    swDebug("+----------+------------+-----------+-----------+------------+------------------+");
}
}
}
