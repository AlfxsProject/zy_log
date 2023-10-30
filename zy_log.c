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
#include <pthread.h>
#include <stdarg.h>
#include <stdio.h>
#include <time.h>
#include <unistd.h>

struct zy_log_s
{
    const zy_alloc_t *alloc;
    int fd;
    size_t message_size;
    zy_log_message_type_t max_message_type;
    zy_format_t output_format;
    const char *time_format;
    pthread_mutex_t message_size_mutex;
    pthread_mutex_t max_message_type_mutex;
    pthread_mutex_t output_format_mutex;
    pthread_mutex_t time_format_mutex;
};

int zy_log_construct(zy_log_t **log, const zy_alloc_t *alloc, int file_descriptor)
{
    int r = zy_malloc(alloc, sizeof(zy_log_t), (void **)log);
    if (r == ZY_OK)
    {
        (*log)->alloc = alloc;
        (*log)->fd = file_descriptor;
        (*log)->message_size = ZY_LOG_MAX_MESSAGE_SIZE_DEFAULT;
        (*log)->max_message_type = ZY_LOG_MESSAGE_TYPE_DEFAULT;
        (*log)->output_format = ZY_LOG_OUTPUT_FORMAT_DEFAULT;
        (*log)->time_format = ZY_LOG_TIME_FORMAT_DEFAULT;
        pthread_mutex_init(&(*log)->message_size_mutex, nullptr);
        pthread_mutex_init(&(*log)->max_message_type_mutex, nullptr);
        pthread_mutex_init(&(*log)->output_format_mutex, nullptr);
        pthread_mutex_init(&(*log)->time_format_mutex, nullptr);
    }
    return r;
}

void zy_log_destruct(zy_log_t **log)
{
    if (*log != nullptr)
    {
        pthread_mutex_destroy(&(*log)->message_size_mutex);
        pthread_mutex_destroy(&(*log)->max_message_type_mutex);
        pthread_mutex_destroy(&(*log)->output_format_mutex);
        pthread_mutex_destroy(&(*log)->time_format_mutex);
        zy_free((const zy_alloc_t *)(*log)->alloc, (void **)log);
    }
}

bool zy_log_set_max_message_size(zy_log_t *log, size_t size)
{
    bool r = false;
    pthread_mutex_lock(&log->message_size_mutex);
    if (size >= ZY_LOG_MAX_MESSAGE_SIZE_MIN && size <= ZY_LOG_MAX_MESSAGE_SIZE_MAX)
    {
        log->message_size = size;
        r = true;
    }
    pthread_mutex_unlock(&log->message_size_mutex);
    return r;
}

size_t zy_log_get_max_message_size(const zy_log_t *log)
{
    pthread_mutex_lock((pthread_mutex_t *)&log->message_size_mutex);
    size_t message_size = log->message_size;
    pthread_mutex_unlock((pthread_mutex_t *)&log->message_size_mutex);
    return message_size;
}

bool zy_log_set_max_message_type(zy_log_t *log, zy_log_message_type_t max)
{
    if (max <= ZY_LOG_MESSAGE_TYPE_MAX)
    {
        pthread_mutex_lock((pthread_mutex_t *)&log->max_message_type_mutex);
        log->max_message_type = max;
        pthread_mutex_unlock((pthread_mutex_t *)&log->max_message_type_mutex);
        return true;
    }
    return false;
}

zy_log_message_type_t zy_log_get_max_message_type(const zy_log_t *log)
{
    pthread_mutex_lock((pthread_mutex_t *)&log->max_message_type_mutex);
    zy_log_message_type_t max_message_type = log->max_message_type;
    pthread_mutex_unlock((pthread_mutex_t *)&log->max_message_type_mutex);
    return max_message_type;
}

bool zy_log_set_output_format(zy_log_t *log, zy_format_t format)
{
    if (format <= ZY_LOG_OUTPUT_FORMAT_MAX)
    {
        pthread_mutex_lock((pthread_mutex_t *)&log->output_format_mutex);
        log->output_format = format;
        pthread_mutex_unlock((pthread_mutex_t *)&log->output_format_mutex);
        return true;
    }
    return false;
}

zy_format_t zy_log_get_output_format(const zy_log_t *log)
{
    pthread_mutex_lock((pthread_mutex_t *)&log->output_format_mutex);
    zy_format_t output_format = log->output_format;
    pthread_mutex_unlock((pthread_mutex_t *)&log->output_format_mutex);
    return output_format;
}

bool zy_log_set_time_format(zy_log_t *log, const char *format)
{
    pthread_mutex_lock((pthread_mutex_t *)&log->time_format_mutex);
    log->time_format = format;
    pthread_mutex_unlock((pthread_mutex_t *)&log->time_format_mutex);
    return true;
}
const char *zy_log_get_time_format(const zy_log_t *log)
{
    pthread_mutex_lock((pthread_mutex_t *)&log->time_format_mutex);
    const char *const time_format = log->time_format;
    pthread_mutex_unlock((pthread_mutex_t *)&log->time_format_mutex);
    return time_format;
}

/*
 * Print message
 * TIME, FILE, LINE, FUNCTION, SEVERITY, MESSAGE
 */
int zy__log_write(const zy_log_t *log, zy_log_message_type_t type, const char *file, size_t line, const char *function,
                  const char *format, ...)
{
    zy_log_message_type_t max_message_type;
    zy_format_t output_format;
    const char * time_format;

    pthread_mutex_lock((pthread_mutex_t *)&log->max_message_type_mutex);
    max_message_type = log->max_message_type;
    pthread_mutex_unlock((pthread_mutex_t *)&log->max_message_type_mutex);

    pthread_mutex_lock((pthread_mutex_t *)&log->output_format_mutex);
    output_format = log->output_format;
    pthread_mutex_unlock((pthread_mutex_t *)&log->output_format_mutex);

    pthread_mutex_lock((pthread_mutex_t *)&log->time_format_mutex);
    time_format = log->time_format;
    pthread_mutex_unlock((pthread_mutex_t *)&log->time_format_mutex);

    if (type <= max_message_type)
    {
        char *msg;
        size_t offset = 0;
        int r = zy_malloc((const zy_alloc_t *)log->alloc, log->message_size, (void **)&msg);
        if (r == ZY_OK)
        {
            time_t now;
            struct tm tm;
            va_list args;
            bool b_time;

            now = time(NULL);
            b_time = localtime_r(&now, &tm) != nullptr;

            pthread_mutex_lock((pthread_mutex_t *)&log->message_size_mutex);

            switch (output_format)
            {
            case ZY_FORMAT_CSV:
                if (b_time)
                {
                    offset = strftime(msg, log->message_size, time_format, &tm);
                }

                offset += snprintf(msg + offset, log->message_size - offset, ",%s,%zu,%s,", file, line, function);
                switch (type)
                {
                case ZY_ERROR:
                    offset += snprintf(msg + offset, log->message_size - offset, "ERROR,");
                    break;
                case ZY_WARN:
                    offset += snprintf(msg + offset, log->message_size - offset, "WARNING,");
                    break;
                case ZY_INFO:
                    offset += snprintf(msg + offset, log->message_size - offset, "INFO,");
                    break;
                default:
                    break;
                }
                va_start(args, format);
                offset += vsnprintf(msg + offset, log->message_size - offset, format, args);
                va_end(args);
                break;
            case ZY_FORMAT_XML:
                switch (type)
                {
                case ZY_ERROR:
                    offset = snprintf(msg, log->message_size, "<log max_message_type=\"error\">\n\t<date>");
                    break;
                case ZY_WARN:
                    offset = snprintf(msg, log->message_size, "<log max_message_type=\"warning\">\n\t<date>");
                    break;
                case ZY_INFO:
                    offset = snprintf(msg, log->message_size, "<log max_message_type=\"info\">\n\t<date>");
                    break;
                default:
                    break;
                }
                if (b_time)
                {
                    offset += strftime(msg + offset, log->message_size - offset, time_format, &tm);
                }
                offset += snprintf(msg + offset, log->message_size - offset,
                                   "</date>\n\t<location>\n\t\t<file>%s</file>\n\t\t<line>%zu</"
                                   "line>\n\t\t<function>%s</function>\n\t</location>\n\t<message>",
                                   file, line, function);
                va_start(args, format);
                offset += vsnprintf(msg + offset, log->message_size - offset, format, args);
                va_end(args);
                offset += snprintf(msg + offset, log->message_size - offset, "</message>\n</log>\n");
                break;
            default:
            case ZY_FORMAT_PLAIN:
                if (b_time)
                {
                    offset = strftime(msg, log->message_size, time_format, &tm);
                }
                offset += snprintf(msg + offset, log->message_size - offset, " %s:%zu (%s) ", file, line, function);
                switch (type)
                {
                case ZY_ERROR:
                    offset += snprintf(msg + offset, log->message_size - offset, "[ERROR] ");
                    break;
                case ZY_WARN:
                    offset += snprintf(msg + offset, log->message_size - offset, "[WARNING] ");
                    break;
                case ZY_INFO:
                    offset += snprintf(msg + offset, log->message_size - offset, "[INFO] ");
                    break;
                default:
                    break;
                }
                va_start(args, format);
                offset += vsnprintf(msg + offset, log->message_size - offset, format, args);
                va_end(args);
                break;
            }

            pthread_mutex_unlock((pthread_mutex_t *)&log->message_size_mutex);

            write(log->fd, msg, offset);
        }
        zy_free((const zy_alloc_t *)log->alloc, (void **)&msg);
        return r;
    }
    return ZY_OK;
}
