// SPDX-License-Identifier: Apache-2.0
// Copyright 2026 Stefan Schmidt

#pragma once

#ifdef ENABLE_LOGGING

#include <stdio.h>

#define LOG_DEBUG(fmt, ...) fprintf(stderr, "[DEBUG] " fmt "\n", ##__VA_ARGS__)
#define LOG_INFO(fmt, ...) fprintf(stderr, "[INFO]  " fmt "\n", ##__VA_ARGS__)
#define LOG_ERROR(fmt, ...) fprintf(stderr, "[ERROR] %s() : " fmt "\n", __func__, ##__VA_ARGS__)
#define LOG_ENTRY(fmt, ...) fprintf(stderr, "[INFO]  +++ %s() " fmt "\n", __func__, ##__VA_ARGS__)
#define LOG_EXIT(fmt, ...) fprintf(stderr, "[INFO]  --- %s() " fmt "\n", __func__, ##__VA_ARGS__)
#define LOG_EXCEPTION(e) fprintf(stderr, "[ERROR] %s\n", e)

#else

#define LOG_DEBUG(fmt, ...)
#define LOG_INFO(fmt, ...)
#define LOG_ERROR(fmt, ...)
#define LOG_ENTRY(fmt, ...)
#define LOG_EXIT(fmt, ...)
#define LOG_EXCEPTION(e)

#endif
