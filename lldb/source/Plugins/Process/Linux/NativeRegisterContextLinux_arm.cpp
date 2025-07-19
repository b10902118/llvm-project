//===-- NativeRegisterContextLinux_arm.cpp --------------------------------===//
//
// Part of the LLVM Project, under the Apache License v2.0 with LLVM Exceptions.
// See https://llvm.org/LICENSE.txt for license information.
// SPDX-License-Identifier: Apache-2.0 WITH LLVM-exception
//
//===----------------------------------------------------------------------===//
#if defined(__arm__) || defined(__arm64__) || defined(__aarch64__)

#include "NativeRegisterContextLinux_arm.h"

#include "Plugins/Process/Linux/NativeProcessLinux.h"
#include "Plugins/Process/Linux/Procfs.h"
#include "Plugins/Process/POSIX/ProcessPOSIXLog.h"
#include "Plugins/Process/Utility/RegisterInfoPOSIX_arm.h"
#include "lldb/Host/HostInfo.h"
#include "lldb/Utility/DataBufferHeap.h"
#include "lldb/Utility/Log.h"
#include "lldb/Utility/RegisterValue.h"
#include "lldb/Utility/Status.h"

#include <elf.h>
#include <sys/uio.h>

#if defined(__arm64__) || defined(__aarch64__)
#include "lldb/Host/linux/Ptrace.h"
#include <asm/ptrace.h>
#endif

#define REG_CONTEXT_SIZE (GetGPRSize() + sizeof(m_fpr))

#ifndef PTRACE_GETVFPREGS
#define PTRACE_GETVFPREGS 27
#define PTRACE_SETVFPREGS 28
#endif
#if defined(__arm__) && !defined(PTRACE_GETHBPREGS)
#define PTRACE_GETHBPREGS 29
#define PTRACE_SETHBPREGS 30
#endif
#if !defined(PTRACE_TYPE_ARG3)
#define PTRACE_TYPE_ARG3 void *
#endif
#if !defined(PTRACE_TYPE_ARG4)
#define PTRACE_TYPE_ARG4 void *
#endif

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_linux;

#if defined(__arm__)

std::unique_ptr<NativeRegisterContextLinux>
NativeRegisterContextLinux::CreateHostNativeRegisterContextLinux(
    const ArchSpec &target_arch, NativeThreadLinux &native_thread) {
  return std::make_unique<NativeRegisterContextLinux_arm>(target_arch,
                                                           native_thread);
}

llvm::Expected<ArchSpec>
NativeRegisterContextLinux::DetermineArchitecture(lldb::tid_t tid) {
  return HostInfo::GetArchitecture();
}

#endif // defined(__arm__)

NativeRegisterContextLinux_arm::NativeRegisterContextLinux_arm(
    const ArchSpec &target_arch, NativeThreadProtocol &native_thread)
    : NativeRegisterContextRegisterInfo(native_thread,
                                        new RegisterInfoPOSIX_arm(target_arch)),
      NativeRegisterContextLinux(native_thread),
      NativeRegisterContextDBReg(/*enable_bit=*/0x1U)  {
  assert(target_arch.GetMachine() == llvm::Triple::arm);

  ::memset(&m_fpr, 0, sizeof(m_fpr));
  ::memset(&m_gpr_arm, 0, sizeof(m_gpr_arm));
  ::memset(&m_hwp_regs, 0, sizeof(m_hwp_regs));
  ::memset(&m_hbp_regs, 0, sizeof(m_hbp_regs));

  // 16 is just a maximum value, query hardware for actual watchpoint count
  m_max_hwp_supported = 16;
  m_max_hbp_supported = 16;
  m_refresh_hwdebug_info = true;
}

RegisterInfoPOSIX_arm &NativeRegisterContextLinux_arm::GetRegisterInfo() const {
  return static_cast<RegisterInfoPOSIX_arm &>(*m_register_info_interface_up);
}

uint32_t NativeRegisterContextLinux_arm::GetRegisterSetCount() const {
  return GetRegisterInfo().GetRegisterSetCount();
}

uint32_t NativeRegisterContextLinux_arm::GetUserRegisterCount() const {
  uint32_t count = 0;
  for (uint32_t set_index = 0; set_index < GetRegisterSetCount(); ++set_index)
    count += GetRegisterSet(set_index)->num_registers;
  return count;
}

const RegisterSet *
NativeRegisterContextLinux_arm::GetRegisterSet(uint32_t set_index) const {
  return GetRegisterInfo().GetRegisterSet(set_index);
}

Status
NativeRegisterContextLinux_arm::ReadRegister(const RegisterInfo *reg_info,
                                             RegisterValue &reg_value) {
  Status error;

  if (!reg_info) {
    error = Status::FromErrorString("reg_info NULL");
    return error;
  }

  const uint32_t reg = reg_info->kinds[lldb::eRegisterKindLLDB];

  if (IsFPR(reg)) {
    error = ReadFPR();
    if (error.Fail())
      return error;
  } else {
    uint32_t full_reg = reg;
    bool is_subreg = reg_info->invalidate_regs &&
                     (reg_info->invalidate_regs[0] != LLDB_INVALID_REGNUM);

    if (is_subreg) {
      // Read the full aligned 64-bit register.
      full_reg = reg_info->invalidate_regs[0];
    }

    error = ReadRegisterRaw(full_reg, reg_value);

    if (error.Success()) {
      // If our read was not aligned (for ah,bh,ch,dh), shift our returned
      // value one byte to the right.
      if (is_subreg && (reg_info->byte_offset & 0x1))
        reg_value.SetUInt64(reg_value.GetAsUInt64() >> 8);

      // If our return byte size was greater than the return value reg size,
      // then use the type specified by reg_info rather than the uint64_t
      // default
      if (reg_value.GetByteSize() > reg_info->byte_size)
        reg_value.SetType(*reg_info);
    }
    return error;
  }

  // Get pointer to m_fpr variable and set the data from it.
  uint32_t fpr_offset = CalculateFprOffset(reg_info);
  assert(fpr_offset < sizeof m_fpr);
  uint8_t *src = (uint8_t *)&m_fpr + fpr_offset;
  switch (reg_info->byte_size) {
  case 2:
    reg_value.SetUInt16(*(uint16_t *)src);
    break;
  case 4:
    reg_value.SetUInt32(*(uint32_t *)src);
    break;
  case 8:
    reg_value.SetUInt64(*(uint64_t *)src);
    break;
  case 16:
    reg_value.SetBytes(src, 16, GetByteOrder());
    break;
  default:
    assert(false && "Unhandled data size.");
    error = Status::FromErrorStringWithFormat("unhandled byte size: %" PRIu32,
                                              reg_info->byte_size);
    break;
  }

  return error;
}

Status
NativeRegisterContextLinux_arm::WriteRegister(const RegisterInfo *reg_info,
                                              const RegisterValue &reg_value) {
  if (!reg_info)
    return Status::FromErrorString("reg_info NULL");

  const uint32_t reg_index = reg_info->kinds[lldb::eRegisterKindLLDB];
  if (reg_index == LLDB_INVALID_REGNUM)
    return Status::FromErrorStringWithFormat(
        "no lldb regnum for %s",
        reg_info && reg_info->name ? reg_info->name : "<unknown register>");

  if (IsGPR(reg_index))
    return WriteRegisterRaw(reg_index, reg_value);

  if (IsFPR(reg_index)) {
    // Get pointer to m_fpr variable and set the data to it.
    uint32_t fpr_offset = CalculateFprOffset(reg_info);
    assert(fpr_offset < sizeof m_fpr);
    uint8_t *dst = (uint8_t *)&m_fpr + fpr_offset;
    ::memcpy(dst, reg_value.GetBytes(), reg_info->byte_size);

    return WriteFPR();
  }

  return Status::FromErrorString(
      "failed - register wasn't recognized to be a GPR or an FPR, "
      "write strategy unknown");
}

Status NativeRegisterContextLinux_arm::ReadAllRegisterValues(
    lldb::WritableDataBufferSP &data_sp) {
  Status error;

  data_sp.reset(new DataBufferHeap(REG_CONTEXT_SIZE, 0));
  error = ReadGPR();
  if (error.Fail())
    return error;

  error = ReadFPR();
  if (error.Fail())
    return error;

  uint8_t *dst = data_sp->GetBytes();
  ::memcpy(dst, &m_gpr_arm, GetGPRSize());
  dst += GetGPRSize();
  ::memcpy(dst, &m_fpr, sizeof(m_fpr));

  return error;
}

Status NativeRegisterContextLinux_arm::WriteAllRegisterValues(
    const lldb::DataBufferSP &data_sp) {
  Status error;

  if (!data_sp) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_arm::%s invalid data_sp provided",
        __FUNCTION__);
    return error;
  }

  if (data_sp->GetByteSize() != REG_CONTEXT_SIZE) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_arm::%s data_sp contained mismatched "
        "data size, expected %" PRIu64 ", actual %" PRIu64,
        __FUNCTION__, (uint64_t)REG_CONTEXT_SIZE, data_sp->GetByteSize());
    return error;
  }

  const uint8_t *src = data_sp->GetBytes();
  if (src == nullptr) {
    error = Status::FromErrorStringWithFormat(
        "NativeRegisterContextLinux_arm::%s "
        "DataBuffer::GetBytes() returned a null "
        "pointer",
        __FUNCTION__);
    return error;
  }
  ::memcpy(&m_gpr_arm, src, GetRegisterInfoInterface().GetGPRSize());

  error = WriteGPR();
  if (error.Fail())
    return error;

  src += GetRegisterInfoInterface().GetGPRSize();
  ::memcpy(&m_fpr, src, sizeof(m_fpr));

  error = WriteFPR();
  if (error.Fail())
    return error;

  return error;
}

bool NativeRegisterContextLinux_arm::IsGPR(unsigned reg) const {
  if (GetRegisterInfo().GetRegisterSetFromRegisterIndex(reg) ==
      RegisterInfoPOSIX_arm::GPRegSet)
    return true;
  return false;
}

bool NativeRegisterContextLinux_arm::IsFPR(unsigned reg) const {
  if (GetRegisterInfo().GetRegisterSetFromRegisterIndex(reg) ==
      RegisterInfoPOSIX_arm::FPRegSet)
    return true;
  return false;
}

std::optional<NativeRegisterContextDBReg::WatchpointDetails>
  NativeRegisterContextLinux_arm::AdjustWatchpoint(const WatchpointDetails &details){
    size_t size = details.size;
  lldb::addr_t addr = details.addr;

  if (size == 0 || size > 4)
    return std::nullopt;

  // Check 4-byte alignment for hardware watchpoint target address. Below is a
  // hack to recalculate address and size in order to make sure we can watch
  // non 4-byte aligned addresses as well.
  if (addr & 0x03) {
    uint8_t watch_mask = (addr & 0x03) + size;

    if (watch_mask > 0x04)
      return std::nullopt;
    else if (watch_mask <= 0x02)
      size = 2;
    else
      size = 4;

    addr = addr & (~0x03);
  }
    return WatchpointDetails{size, addr};
}

uint32_t NativeRegisterContextLinux_arm::MakeBreakControlValue(size_t size){
  // copied from NativeRegisterContextDBReg_arm64::MakeBreakControlValue
  // only difference in effect is the pac_bits 

  // PAC (bits 2:1): 0b10
  const uint32_t pac_bits = 2 << 1;

  // BAS (bits 12:5) hold a bit-mask of addresses to watch
  // e.g. 0b00000001 means 1 byte at address
  //      0b00000011 means 2 bytes (addr..addr+1)
  //      ...
  //      0b11111111 means 8 bytes (addr..addr+7)
  size_t encoded_size = ((1 << size) - 1) << 5;

  // Return encoded hardware breakpoint control value.
  return m_hw_dbg_enable_bit | pac_bits | encoded_size;
}

uint32_t NativeRegisterContextLinux_arm::MakeWatchControlValue(size_t size, uint32_t watch_flags){
  // copied from NativeRegisterContextDBReg_arm64::MakeWatchControlValue
  // only difference in effect is the pac_bits 

  // PAC (bits 2:1): 0b10
  const uint32_t pac_bits = 2 << 1;

  // BAS (bits 12:5) hold a bit-mask of addresses to watch
  // e.g. 0b00000001 means 1 byte at address
  //      0b00000011 means 2 bytes (addr..addr+1)
  //      ...
  //      0b11111111 means 8 bytes (addr..addr+7)
  size_t encoded_size = ((1 << size) - 1) << 5;

  // Return encoded hardware watchpoint control value.
  return m_hw_dbg_enable_bit | pac_bits | encoded_size | (watch_flags << 3);
}

uint32_t NativeRegisterContextLinux_arm::GetWatchpointSize(uint32_t wp_index) {
  // TODO: check whether 8-byte watchpoints are supported in arm64
  Log *log = GetLog(POSIXLog::Watchpoints);
  LLDB_LOG(log, "wp_index: {0}", wp_index);

  switch ((m_hwp_regs[wp_index].control >> 5) & 0x0f) {
  case 0x01:
    return 1;
  case 0x03:
    return 2;
  case 0x07:
    return 3;
  case 0x0f:
    return 4;
  default:
    return 0;
  }
}

llvm::Error NativeRegisterContextLinux_arm::ReadHardwareDebugInfo() {
  Status error;

  if (!m_refresh_hwdebug_info) {
    return llvm::Error::success();
  }

#ifdef __arm__
  unsigned int cap_val;

  error = NativeProcessLinux::PtraceWrapper(PTRACE_GETHBPREGS, m_thread.GetID(),
                                            nullptr, &cap_val,
                                            sizeof(unsigned int));

  if (error.Fail())
    return error.ToError();

  m_max_hwp_supported = (cap_val >> 8) & 0xff;
  m_max_hbp_supported = cap_val & 0xff;
  m_refresh_hwdebug_info = false;

  return error.ToError();
#else  // __aarch64__
  ::pid_t tid = m_thread.GetID();

  int regset = NT_ARM_HW_WATCH;
  struct iovec ioVec;
  struct user_hwdebug_state dreg_state;

  ioVec.iov_base = &dreg_state;
  ioVec.iov_len = sizeof(dreg_state);

  error = NativeProcessLinux::PtraceWrapper(PTRACE_GETREGSET, tid, &regset,
                                            &ioVec, ioVec.iov_len);

  if (error.Fail())
    return error.ToError();

  m_max_hwp_supported = dreg_state.dbg_info & 0xff;

  regset = NT_ARM_HW_BREAK;
  error = NativeProcessLinux::PtraceWrapper(PTRACE_GETREGSET, tid, &regset,
                                            &ioVec, ioVec.iov_len);

  if (error.Fail())
    return error.ToError();

  m_max_hbp_supported = dreg_state.dbg_info & 0xff;
  m_refresh_hwdebug_info = false;

  return llvm::Error::success();
#endif // __arm__
}

#ifdef __arm__
Status NativeRegisterContextLinux_arm::WriteHardwareDebugReg(DREGType hwbType, int hwb_index){
  Status error;

  lldb::addr_t *addr_buf;
  uint32_t *ctrl_buf;

  if (hwbType == eDREGTypeWATCH) {
    addr_buf = &m_hwp_regs[hwb_index].address;
    ctrl_buf = &m_hwp_regs[hwb_index].control;

    error = NativeProcessLinux::PtraceWrapper(
        PTRACE_SETHBPREGS, m_thread.GetID(),
        (PTRACE_TYPE_ARG3)(intptr_t) - ((hwb_index << 1) + 1), addr_buf,
        sizeof(unsigned int));

    if (error.Fail())
      return error;

    error = NativeProcessLinux::PtraceWrapper(
        PTRACE_SETHBPREGS, m_thread.GetID(),
        (PTRACE_TYPE_ARG3)(intptr_t) - ((hwb_index << 1) + 2), ctrl_buf,
        sizeof(unsigned int));
  } else {
    addr_buf = &m_hbp_regs[hwb_index].address;
    ctrl_buf = &m_hbp_regs[hwb_index].control;

    error = NativeProcessLinux::PtraceWrapper(
        PTRACE_SETHBPREGS, m_thread.GetID(),
        (PTRACE_TYPE_ARG3)(intptr_t)((hwb_index << 1) + 1), addr_buf,
        sizeof(unsigned int));

    if (error.Fail())
      return error;

    error = NativeProcessLinux::PtraceWrapper(
        PTRACE_SETHBPREGS, m_thread.GetID(),
        (PTRACE_TYPE_ARG3)(intptr_t)((hwb_index << 1) + 2), ctrl_buf,
        sizeof(unsigned int));
  }
  return error;
}

llvm::Error NativeRegisterContextLinux_arm::WriteHardwareDebugRegs(DREGType hwbType) {
  int hwb_max_supported = (hwbType == eDREGTypeWATCH) ? m_max_hwp_supported
                                 : m_max_hbp_supported;
  for (int hwb_index = 0; hwb_index < hwb_max_supported; hwb_index++) {
    Status error = WriteHardwareDebugReg(hwbType, hwb_index);
    if (error.Fail())
      return error.ToError();
  }

  return llvm::Error::success();
}
#else  // __aarch64__
llvm::Error NativeRegisterContextLinux_arm::WriteHardwareDebugRegs(DREGType hwbType){
  struct iovec ioVec;
  struct user_hwdebug_state dreg_state;
  int regset;

  memset(&dreg_state, 0, sizeof(dreg_state));
  ioVec.iov_base = &dreg_state;

  switch (hwbType) {
  case eDREGTypeWATCH:
    regset = NT_ARM_HW_WATCH;
    ioVec.iov_len = sizeof(dreg_state.dbg_info) + sizeof(dreg_state.pad) +
                    (sizeof(dreg_state.dbg_regs[0]) * m_max_hwp_supported);

    for (uint32_t i = 0; i < m_max_hwp_supported; i++) {
      dreg_state.dbg_regs[i].addr = m_hwp_regs[i].address;
      dreg_state.dbg_regs[i].ctrl = m_hwp_regs[i].control;
    }
    break;
  case eDREGTypeBREAK:
    regset = NT_ARM_HW_BREAK;
    ioVec.iov_len = sizeof(dreg_state.dbg_info) + sizeof(dreg_state.pad) +
                    (sizeof(dreg_state.dbg_regs[0]) * m_max_hbp_supported);

    for (uint32_t i = 0; i < m_max_hbp_supported; i++) {
      dreg_state.dbg_regs[i].addr = m_hbp_regs[i].address;
      dreg_state.dbg_regs[i].ctrl = m_hbp_regs[i].control;
    }
    break;
  }

  return NativeProcessLinux::PtraceWrapper(PTRACE_SETREGSET, m_thread.GetID(),
                                           &regset, &ioVec, ioVec.iov_len).ToError();
}
#endif // __arm__

uint32_t NativeRegisterContextLinux_arm::CalculateFprOffset(
    const RegisterInfo *reg_info) const {
  return reg_info->byte_offset - GetGPRSize();
}

Status NativeRegisterContextLinux_arm::DoReadRegisterValue(
    uint32_t offset, const char *reg_name, uint32_t size,
    RegisterValue &value) {
  // PTRACE_PEEKUSER don't work in the aarch64 linux kernel used on android
  // devices (always return "Bad address"). To avoid using PTRACE_PEEKUSER we
  // read out the full GPR register set instead. This approach is about 4 times
  // slower but the performance overhead is negligible in comparison to
  // processing time in lldb-server.
  assert(offset % 4 == 0 && "Try to write a register with unaligned offset");
  if (offset + sizeof(uint32_t) > sizeof(m_gpr_arm))
    return Status::FromErrorString(
        "Register isn't fit into the size of the GPR area");

  Status error = ReadGPR();
  if (error.Fail())
    return error;

  value.SetUInt32(m_gpr_arm[offset / sizeof(uint32_t)]);
  return Status();
}

Status NativeRegisterContextLinux_arm::DoWriteRegisterValue(
    uint32_t offset, const char *reg_name, const RegisterValue &value) {
  // PTRACE_POKEUSER don't work in the aarch64 linux kernel used on android
  // devices (always return "Bad address"). To avoid using PTRACE_POKEUSER we
  // read out the full GPR register set, modify the requested register and
  // write it back. This approach is about 4 times slower but the performance
  // overhead is negligible in comparison to processing time in lldb-server.
  assert(offset % 4 == 0 && "Try to write a register with unaligned offset");
  if (offset + sizeof(uint32_t) > sizeof(m_gpr_arm))
    return Status::FromErrorString(
        "Register isn't fit into the size of the GPR area");

  Status error = ReadGPR();
  if (error.Fail())
    return error;

  uint32_t reg_value = value.GetAsUInt32();
  // As precaution for an undefined behavior encountered while setting PC we
  // will clear thumb bit of new PC if we are already in thumb mode; that is
  // CPSR thumb mode bit is set.
  if (offset / sizeof(uint32_t) == gpr_pc_arm) {
    // Check if we are already in thumb mode and thumb bit of current PC is
    // read out to be zero and thumb bit of next PC is read out to be one.
    if ((m_gpr_arm[gpr_cpsr_arm] & 0x20) && !(m_gpr_arm[gpr_pc_arm] & 0x01) &&
        (value.GetAsUInt32() & 0x01)) {
      reg_value &= (~1ull);
    }
  }

  m_gpr_arm[offset / sizeof(uint32_t)] = reg_value;
  return WriteGPR();
}

Status NativeRegisterContextLinux_arm::ReadGPR() {
#ifdef __arm__
  return NativeRegisterContextLinux::ReadGPR();
#else  // __aarch64__
  struct iovec ioVec;
  ioVec.iov_base = GetGPRBuffer();
  ioVec.iov_len = GetGPRSize();

  return ReadRegisterSet(&ioVec, GetGPRSize(), NT_PRSTATUS);
#endif // __arm__
}

Status NativeRegisterContextLinux_arm::WriteGPR() {
#ifdef __arm__
  return NativeRegisterContextLinux::WriteGPR();
#else  // __aarch64__
  struct iovec ioVec;
  ioVec.iov_base = GetGPRBuffer();
  ioVec.iov_len = GetGPRSize();

  return WriteRegisterSet(&ioVec, GetGPRSize(), NT_PRSTATUS);
#endif // __arm__
}

Status NativeRegisterContextLinux_arm::ReadFPR() {
#ifdef __arm__
  return NativeProcessLinux::PtraceWrapper(PTRACE_GETVFPREGS, m_thread.GetID(),
                                           nullptr, GetFPRBuffer(),
                                           GetFPRSize());
#else  // __aarch64__
  struct iovec ioVec;
  ioVec.iov_base = GetFPRBuffer();
  ioVec.iov_len = GetFPRSize();

  return ReadRegisterSet(&ioVec, GetFPRSize(), NT_ARM_VFP);
#endif // __arm__
}

Status NativeRegisterContextLinux_arm::WriteFPR() {
#ifdef __arm__
  return NativeProcessLinux::PtraceWrapper(PTRACE_SETVFPREGS, m_thread.GetID(),
                                           nullptr, GetFPRBuffer(),
                                           GetFPRSize());
#else  // __aarch64__
  struct iovec ioVec;
  ioVec.iov_base = GetFPRBuffer();
  ioVec.iov_len = GetFPRSize();

  return WriteRegisterSet(&ioVec, GetFPRSize(), NT_ARM_VFP);
#endif // __arm__
}

#endif // defined(__arm__) || defined(__arm64__) || defined(__aarch64__)
