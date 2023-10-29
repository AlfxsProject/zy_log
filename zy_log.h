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
#pragma once
#include <stdbool.h>
#include <zy_alloc.h>

/*
 * Types
 */

typedef struct zy_log_s zy_log_t;

typedef enum zy_log_type_e
{
    ZY_ERROR,
    ZY_WARN,
    ZY_INFO
} zy_log_type_t;

#ifndef ZY_FORMAT
#define ZY_FORMAT
typedef enum zy_format_e
{
    ZY_FORMAT_PLAIN,
    ZY_FORMAT_CSV,
    ZY_FORMAT_XML
} zy_format_t;
#endif

/*
 * Constants
 */

#define ZY_LOG_TYPE_MAX (ZY_INFO)
#define ZY_LOG_FORMAT_MAX (ZY_FORMAT_XML)
#define ZY_LOG_LENGTH_DEFAULT (8192U)
#define ZY_LOG_TIME_FORMAT_DEFAULT ("%a %b %d %H:%M:%S %Z %Y")

/*
 * Macros
 */

#define zy_log_error(log, format, ...) zy__log_write(log, ZY_ERROR, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define zy_log_warn(log, format, ...) zy__log_write(log, ZY_WARN, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)
#define zy_log_info(log, format, ...) zy__log_write(log, ZY_INFO, __FILE__, __LINE__, __func__, format, ##__VA_ARGS__)

/*
 * Functions
 */

#ifdef __cplusplus
extern "C"
{
#endif

    __attribute__((nonnull)) int zy_log_construct(zy_log_t **log, const zy_alloc_t *alloc, int file_descriptor);
    __attribute__((nonnull)) void zy_log_destruct(zy_log_t **log);
    __attribute__((nonnull)) bool zy_log_set_length(zy_log_t *log, size_t length);
    __attribute__((nonnull)) size_t zy_log_get_length(const zy_log_t *log);
    __attribute__((nonnull)) bool zy_log_set_filter(zy_log_t *log, zy_log_type_t max);
    __attribute__((nonnull)) zy_log_type_t zy_log_get_filter(const zy_log_t *log);
    __attribute__((nonnull)) bool zy_log_set_output_format(zy_log_t *log, zy_format_t format);
    __attribute__((nonnull)) zy_format_t zy_log_get_output_format(const zy_log_t *log);
    __attribute__((nonnull)) bool zy_log_set_time_format(zy_log_t *log, const char *format);
    __attribute__((nonnull)) const char *zy_log_get_time_format(const zy_log_t *log);

    /* Internal Use Only. */
    __attribute__((nonnull)) __attribute__((format(printf, 6, 7))) int zy__log_write(const zy_log_t *log,
                                                                                     zy_log_type_t type,
                                                                                     const char *file, size_t line,
                                                                                     const char *function,
                                                                                     const char *format, ...);

#ifdef __cplusplus
}
#endif