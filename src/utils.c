#include <stdarg.h>
#include "resources.h"
#include <string.h>
#include <stdio.h>

char *fstring(char *format, ...)
{
    static char buffer[1024];
    memset(buffer, 0, sizeof(buffer));
    
    va_list args;
    va_start(args, format);
    unsigned long count_char_writen = vsnprintf(buffer, sizeof(buffer), format, args);
    va_end(args);

    if (count_char_writen > sizeof(buffer))
    {
        clean_exit_failure("Failed to write formatted string");
    }
    
    return buffer;
}