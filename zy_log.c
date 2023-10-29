/*
 * Copyright 2023 Alexandre Fernandez <alex@fernandezfamily.email>
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 *    http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */
#include "zy_log.h"
#include <stdarg.h>
#include <stdio.h>
#include <string.h>
#include <time.h>
#include <unistd.h>

struct zy_log_s
{
    const char *const alloc;
    const int fd;
    size_t length;
    zy_log_type_t type;
    zy_format_t format;
    const char *time_string;
};

int zy_log_construct(zy_log_t **log, const zy_alloc_t *alloc, int file_descriptor)
{
    int r = zy_malloc(alloc, sizeof(zy_log_t), (void **)log);
    if (r == ZY_OK)
    {
        const zy_log_t log_init = {.alloc = (const char *const)alloc,
                                   .fd = file_descriptor,
                                   .length = ZY_LOG_LENGTH_DEFAULT,
                                   .type = ZY_ERROR,
                                   .format = ZY_FORMAT_PLAIN,
                                   .time_string = ZY_LOG_TIME_FORMAT_DEFAULT};
        memcpy((void *)*log, &log_init, sizeof(zy_log_t));
    }
    return r;
}

void zy_log_destruct(zy_log_t **log)
{
    if (*log != nullptr)
    {
        zy_free((const zy_alloc_t *)(*log)->alloc, (void **)log);
    }
}

bool zy_log_set_length(zy_log_t *log, size_t length)
{
    log->length = length;
    return true;
}

size_t zy_log_get_length(const zy_log_t *log)
{
    return log->length;
}

bool zy_log_set_filter(zy_log_t *log, zy_log_type_t max)
{
    if (max <= ZY_LOG_TYPE_MAX)
    {
        log->type = max;
        return true;
    }
    return false;
}

zy_log_type_t zy_log_get_filter(const zy_log_t *log)
{
    return log->type;
}

bool zy_log_set_format(zy_log_t *log, zy_format_t format)
{
    if (format <= ZY_LOG_FORMAT_MAX)
    {
        log->format = format;
        return true;
    }
    return false;
}

zy_format_t zy_log_get_format(const zy_log_t *log)
{
    return log->format;
}

bool zy_log_set_time_format(zy_log_t *log, const char *format)
{
    log->time_string = format;
    return true;
}
const char *zy_log_get_time_format(const zy_log_t *log)
{
    return log->time_string;
}

/*
 * Print message
 * TIME, FILE, LINE, FUNCTION, SEVERITY, MESSAGE
 */
int zy__log_write(const zy_log_t *log, zy_log_type_t type, const char *file, size_t line, const char *function,
                  const char *format, ...)
{
    if (type <= log->type)
    {
        char *msg;
        size_t offset = 0;
        int r = zy_malloc((const zy_alloc_t *)log->alloc, log->length, (void **)&msg);
        if (r == ZY_OK)
        {
            time_t now;
            struct tm tm;
            va_list args;

            now = time(NULL);
            localtime_r(&now, &tm);

            switch (log->format)
            {
            case ZY_FORMAT_PLAIN:
                offset += strftime(msg, log->length, log->time_string, &tm);
                offset += snprintf(msg + offset, log->length - offset, " %s:%zu (%s) ", file, line, function);
                switch (type)
                {
                case ZY_ERROR:
                    offset += snprintf(msg + offset, log->length - offset, "[ERROR] ");
                    break;
                case ZY_WARN:
                    offset += snprintf(msg + offset, log->length - offset, "[WARNING] ");
                    break;
                case ZY_INFO:
                    offset += snprintf(msg + offset, log->length - offset, "[INFO] ");
                    break;
                default:
                    break;
                }
                va_start(args, format);
                offset += vsnprintf(msg + offset, log->length - offset, format, args);
                va_end(args);
                break;
            case ZY_FORMAT_CSV:
                offset += strftime(msg, log->length, log->time_string, &tm);
                offset += snprintf(msg + offset, log->length - offset, ",%s,%zu,%s,", file, line, function);
                switch (type)
                {
                case ZY_ERROR:
                    offset += snprintf(msg + offset, log->length - offset, "ERROR,");
                    break;
                case ZY_WARN:
                    offset += snprintf(msg + offset, log->length - offset, "WARNING,");
                    break;
                case ZY_INFO:
                    offset += snprintf(msg + offset, log->length - offset, "INFO,");
                    break;
                default:
                    break;
                }
                va_start(args, format);
                offset += vsnprintf(msg + offset, log->length - offset, format, args);
                va_end(args);
                break;
            case ZY_FORMAT_XML:
                switch (type)
                {
                case ZY_ERROR:
                    offset += snprintf(msg + offset, log->length - offset, "<log type=\"error\">\n\t<date>");
                    break;
                case ZY_WARN:
                    offset += snprintf(msg + offset, log->length - offset, "<log type=\"warning\">\n\t<date>");
                    break;
                case ZY_INFO:
                    offset += snprintf(msg + offset, log->length - offset, "<log type=\"info\">\n\t<date>");
                    break;
                default:
                    break;
                }
                offset += strftime(msg, log->length, log->time_string, &tm);
                offset += snprintf(msg + offset, log->length - offset,
                                   "</date>\n\t<location>\n\t\t<file>%s</file>\n\t\t<line>%zu</"
                                   "line>\n\t\t<function>%s</function>\n\t</location>\n\t<message>",
                                   file, line, function);
                va_start(args, format);
                offset += vsnprintf(msg + offset, log->length - offset, format, args);
                va_end(args);
                offset += snprintf(msg + offset, log->length - offset, "</message>\n</log>");
                break;
            default:
                break;
            }
            write(log->fd, msg, offset);
        }
        zy_free((const zy_alloc_t *)log->alloc, (void **)&msg);
        return r;
    }
    return ZY_OK;
}
