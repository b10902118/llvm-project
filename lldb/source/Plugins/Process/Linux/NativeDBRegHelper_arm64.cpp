#include "NativeDBRegHelper_arm64.h"
#include "Plugins/Process/Linux/NativeProcessLinux.h"
#include "lldb/Host/linux/Ptrace.h"
#include <sys/uio.h>

using namespace lldb;
using namespace lldb_private;
using namespace lldb_private::process_linux;

namespace lldb_private::process_linux::arm64 {

Status ReadHardwareDebugInfoHelper(::pid_t tid, int regset, uint32_t &result) {
  struct iovec ioVec;
  struct user_hwdebug_state dreg_state;
  Status error;

  ioVec.iov_base = &dreg_state;
  ioVec.iov_len = sizeof(dreg_state);
  error = NativeProcessLinux::PtraceWrapper(PTRACE_GETREGSET, tid, &regset,
                                            &ioVec, ioVec.iov_len);

  if (error.Fail())
    return error;

  result = dreg_state.dbg_info & 0xff;
  return error;
}

Status WriteHardwareDebugRegsHelper(::pid_t tid, DREGType hwbType) {}

} // namespace lldb_private::process_linux::arm64