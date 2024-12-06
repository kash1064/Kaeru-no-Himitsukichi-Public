#include <errno.h>
#include <linux/elf.h>
#include <linux/hw_breakpoint.h>
#include <signal.h>
#include <sys/ptrace.h>
#include <sys/uio.h>
#include <sys/user.h>
#include <sys/wait.h>
#include <unistd.h>

#include <cstring>
#include <iomanip>
#include <iostream>
#include <string>

// 固定で4つのハードウェアレジスタ
char hardware_breakpoints[4] = {0};

// ARM固有の定義
#define ARM_BREAKPOINT_EXECUTE 0
#define ARM_BREAKPOINT_LOAD 1
#define ARM_BREAKPOINT_STORE 2

#define ARM_BREAKPOINT_LEN_1 0x1
#define ARM_BREAKPOINT_LEN_2 0x3
#define ARM_BREAKPOINT_LEN_4 0xf
#define ARM_BREAKPOINT_LEN_8 0xff

uint32_t encode_ctrl_reg(uint32_t privilege, uint32_t len, uint32_t type,
                         uint32_t enable_mask) {
  return (privilege << 24) | (len << 5) | (type << 3) | (enable_mask << 1) | 1;
}

void attach_process(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
    std::cerr << "Failed to attach: " << strerror(errno) << std::endl;
    exit(1);
  }
  waitpid(pid, nullptr, 0);
}

void print_debug_regs(pid_t pid) {
  struct user_hwdebug_state hw_state;
  struct iovec iov;
  memset(&hw_state, 0, sizeof(hw_state));
  iov.iov_base = &hw_state;
  iov.iov_len = sizeof(hw_state);

  if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov) != -1) {
    std::cout << "\nWatchpoint registers:\n";
    for (int i = 0; i < 4; i++) {
      if (hw_state.dbg_regs[i].ctrl & 1) {
        std::cout << "WP" << i << ": addr=0x" << std::hex
                  << hw_state.dbg_regs[i].addr << " ctrl=0x"
                  << hw_state.dbg_regs[i].ctrl << std::dec << std::endl;
      }
    }
  }
}

int set_watchpoint(pid_t pid, void *addr, int size) {
  struct user_hwdebug_state hw_state;
  struct iovec iov;
  memset(&hw_state, 0, sizeof(hw_state));
  iov.iov_base = &hw_state;
  iov.iov_len = 8 + 16 * 4;

  // 現在の状態を取得
  if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov) == -1) {
    std::cerr << "Failed to get debug registers: " << strerror(errno)
              << std::endl;
    return -1;
  }

  // 既存のウォッチポイントの状態を維持
  for (int i = 0; i < 4; i++) {
    if (hw_state.dbg_regs[i].addr) {
      hw_state.dbg_regs[i].ctrl |= 1;
    }
  }

  // 利用可能なスロットを探す
  int slot = -1;
  for (int i = 0; i < 4; i++) {
    if (hardware_breakpoints[i] == 0) {
      slot = i;
      break;
    }
  }

  if (slot == -1) {
    std::cerr << "No free watchpoint slots\n";
    return -1;
  }

  hardware_breakpoints[slot] = 1;

  // サイズをARMフォーマットに変換
  uint32_t arm_len;
  switch (size) {
  case 1:
    arm_len = ARM_BREAKPOINT_LEN_1;
    break;
  case 2:
    arm_len = ARM_BREAKPOINT_LEN_2;
    break;
  case 4:
    arm_len = ARM_BREAKPOINT_LEN_4;
    break;
  case 8:
    arm_len = ARM_BREAKPOINT_LEN_8;
    break;
  default:
    std::cerr << "Invalid watchpoint size\n";
    return -1;
  }

  // ウォッチポイントを設定
  hw_state.dbg_regs[slot].addr = (uint64_t)addr;
  hw_state.dbg_regs[slot].ctrl = encode_ctrl_reg(
      0, arm_len, ARM_BREAKPOINT_LOAD | ARM_BREAKPOINT_STORE, 0);

  // 設定を適用
  iov.iov_len = 8 + 16 * 4;
  if (ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov) == -1) {
    std::cerr << "Failed to set watchpoint: " << strerror(errno) << std::endl;
    hardware_breakpoints[slot] = 0;
    return -1;
  }

  std::cout << "Set watchpoint " << slot << " at 0x" << std::hex
            << (uint64_t)addr << " ctrl=0x" << hw_state.dbg_regs[slot].ctrl
            << std::dec << std::endl;

  return slot;
}

void remove_watchpoint(pid_t pid, int slot) {
  if (slot < 0 || slot >= 4)
    return;

  struct user_hwdebug_state hw_state;
  struct iovec iov;
  memset(&hw_state, 0, sizeof(hw_state));
  iov.iov_base = &hw_state;
  iov.iov_len = 8 + 16 * 4;

  // レジスタをクリア
  if (ptrace(PTRACE_GETREGSET, pid, NT_ARM_HW_WATCH, &iov) != -1) {
    hw_state.dbg_regs[slot].addr = 0;
    hw_state.dbg_regs[slot].ctrl = 0;
    ptrace(PTRACE_SETREGSET, pid, NT_ARM_HW_WATCH, &iov);
  }

  hardware_breakpoints[slot] = 0;
}

void debug_loop(pid_t pid) {
  while (true) {
    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
      std::cerr << "PTRACE_CONT failed: " << strerror(errno) << std::endl;
      break;
    }

    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
      std::cout << "Process " << pid << " exited\n";
      break;
    }

    if (WIFSTOPPED(status) && WSTOPSIG(status) == SIGTRAP) {
      std::cout << "Watchpoint hit!\n";
      print_debug_regs(pid);

      // PCを取得
      struct user_pt_regs regs;
      struct iovec iov;
      memset(&regs, 0, sizeof(regs));
      iov.iov_base = &regs;
      iov.iov_len = sizeof(regs);

      if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
        std::cerr << "Failed to get registers: " << strerror(errno)
                  << std::endl;
        continue;
      }

      // ARM64の無限ループ命令(b .) = 0x14000000を書き込み
      if (ptrace(PTRACE_POKETEXT, pid, (void *)regs.pc, 0x14000000) == -1) {
        std::cerr << "Failed to write infinite loop: " << strerror(errno)
                  << std::endl;
        continue;
      }

      std::cout << "Injected infinite loop at 0x" << std::hex << regs.pc
                << std::dec << std::endl;

      // ウォッチポイントをすべて削除
      for (int i = 0; i < 4; i++) {
        if (hardware_breakpoints[i]) {
          remove_watchpoint(pid, i);
        }
      }

      // プロセスをデタッチ
      if (ptrace(PTRACE_DETACH, pid, nullptr, nullptr) == -1) {
        std::cerr << "Failed to detach: " << strerror(errno) << std::endl;
      }
      std::cout << "Process detached\n";
      return;
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 4) {
    std::cerr << "Usage: " << argv[0] << " <pid> <address_hex> <size>\n";
    return 1;
  }

  pid_t pid = std::stoi(argv[1]);
  void *addr = reinterpret_cast<void *>(std::stoull(argv[2], nullptr, 16));
  int size = std::stoi(argv[3]);

  attach_process(pid);

  int slot = set_watchpoint(pid, addr, size);
  if (slot >= 0) {
    debug_loop(pid);
    remove_watchpoint(pid, slot);
  }

  ptrace(PTRACE_DETACH, pid, nullptr, nullptr);
  return 0;
}