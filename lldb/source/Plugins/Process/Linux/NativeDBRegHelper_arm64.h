//===-- NativeHardwareDebugRegisterLinux_arm64.h ---------------*- C++-*-===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//

#include "lldb/Utility/Status.h"
#include <sys/types.h>
#if defined(__arm64__) || defined(__aarch64__)
#ifndef lldb_NativeDBRegHelper_arm64_h
#define lldb_NativeDBRegHelper_arm64_h

namespace lldb_private::process_linux::arm64 {

enum DREGType { eDREGTypeWATCH = 0, eDREGTypeBREAK };

static Status ReadHardwareDebugInfoHelper(::pid_t tid, int regset,
                                          uint32_t &result);

static Status WriteHardwareDebugRegsHelper(::pid_t tid, DREGType hwbType,
                                           std::array);

} // namespace lldb_private::process_linux::arm64

#endif

#endif