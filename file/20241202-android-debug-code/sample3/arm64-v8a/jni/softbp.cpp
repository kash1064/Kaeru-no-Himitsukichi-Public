#include <errno.h>
#include <linux/elf.h>
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

void attach_process(pid_t pid) {
  if (ptrace(PTRACE_ATTACH, pid, nullptr, nullptr) == -1) {
    std::cerr << "Failed to attach process: " << strerror(errno) << std::endl;
    exit(1);
  }
  waitpid(pid, nullptr, 0);
}

// ARM64では4バイトの命令を保存
uint32_t save_original_instruction(pid_t pid, void *addr) {
  errno = 0;
  long data = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
  if (errno != 0) {
    std::cerr << "PTRACE_PEEKTEXT failed: " << strerror(errno) << std::endl;
    exit(1);
  }
  return static_cast<uint32_t>(data & 0xFFFFFFFF);
}

void set_breakpoint(pid_t pid, void *addr, uint32_t original_instruction) {
  errno = 0;
  long data = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
  if (errno != 0) {
    std::cerr << "PTRACE_PEEKTEXT failed: " << strerror(errno) << std::endl;
    exit(1);
  }

  // ARM64のBRK命令: 0xD4200000
  long modified = (data & ~0xFFFFFFFF) | 0xD4200000;

  if (ptrace(PTRACE_POKETEXT, pid, addr, modified) == -1) {
    std::cerr << "PTRACE_POKETEXT failed: " << strerror(errno) << std::endl;
    exit(1);
  }
}

void print_registers(pid_t pid) {
  struct iovec iov;
  struct user_pt_regs regs;
  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);

  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
    std::cerr << "PTRACE_GETREGSET failed: " << strerror(errno) << std::endl;
    exit(1);
  }

  std::cout << "Register state:\n";
  std::cout << "PC: 0x" << std::hex << regs.pc << "\n";
  std::cout << "SP: 0x" << std::hex << regs.sp << "\n";
  std::cout << "PSTATE: 0x" << std::hex << regs.pstate << "\n";

  void *addresses[] = {
      (void *)regs.regs[0],  // X0
      (void *)regs.regs[1],  // X1
      (void *)regs.regs[2],  // X2
      (void *)regs.regs[3],  // X3
      (void *)regs.regs[4],  // X4
      (void *)regs.sp,       // SP
      (void *)regs.regs[29], // X29 (Frame pointer)
      (void *)regs.regs[30]  // X30 (Link register)
  };
  const char *reg_names[] = {"X0", "X1", "X2", "X3", "X4", "SP", "FP", "LR"};

  for (int i = 0; i < 8; i++) {
    std::cout << reg_names[i] << ": 0x" << std::hex
              << reinterpret_cast<unsigned long>(addresses[i]) << " -> ";

    unsigned char bytes[16];

    // 最初の8バイトを読む
    long data1 = ptrace(PTRACE_PEEKTEXT, pid, addresses[i], nullptr);
    if (errno != 0) {
      std::cout << "Memory read failed\n";
      continue;
    }
    memcpy(bytes, &data1, 8);

    // 次の8バイトを読む
    long data2 = ptrace(PTRACE_PEEKTEXT, pid,
                        (void *)((char *)addresses[i] + 8), nullptr);
    if (errno != 0) {
      std::cout << "Memory read failed\n";
      continue;
    }
    memcpy(bytes + 8, &data2, 8);

    // hexダンプを表示
    for (int j = 0; j < 16; j++) {
      std::cout << std::setfill('0') << std::setw(2) << (int)bytes[j] << " ";
    }

    // ASCIIを表示
    std::cout << "  |";
    for (int j = 0; j < 16; j++) {
      char c = bytes[j];
      std::cout << (isprint(c) ? c : '.');
    }
    std::cout << "|\n";
  }
}

void handle_breakpoint(pid_t pid, void *addr, uint32_t original_instruction) {
  struct iovec iov;
  struct user_pt_regs regs;
  iov.iov_base = &regs;
  iov.iov_len = sizeof(regs);

  if (ptrace(PTRACE_GETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
    std::cerr << "PTRACE_GETREGSET failed: " << strerror(errno) << std::endl;
    exit(1);
  }

  // ARM64のBRK命令は4バイト長
  regs.pc -= 4;

  if (ptrace(PTRACE_SETREGSET, pid, NT_PRSTATUS, &iov) == -1) {
    std::cerr << "PTRACE_SETREGSET failed: " << strerror(errno) << std::endl;
    exit(1);
  }

  // 元の命令を復元
  long data = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
  if (errno != 0) {
    std::cerr << "PTRACE_PEEKTEXT failed: " << strerror(errno) << std::endl;
    exit(1);
  }

  long restored = (data & ~0xFFFFFFFF) | original_instruction;

  if (ptrace(PTRACE_POKETEXT, pid, addr, restored) == -1) {
    std::cerr << "PTRACE_POKETEXT failed: " << strerror(errno) << std::endl;
    exit(1);
  }

  if (ptrace(PTRACE_SINGLESTEP, pid, nullptr, nullptr) == -1) {
    std::cerr << "PTRACE_SINGLESTEP failed: " << strerror(errno) << std::endl;
    exit(1);
  }

  waitpid(pid, nullptr, 0);
  set_breakpoint(pid, addr, original_instruction);
}

void debug_loop(pid_t pid, void *addr, uint32_t original_instruction) {
  while (true) {
    if (ptrace(PTRACE_CONT, pid, nullptr, nullptr) == -1) {
      std::cerr << "PTRACE_CONT failed: " << strerror(errno) << std::endl;
      exit(1);
    }
    int status;
    waitpid(pid, &status, 0);

    if (WIFEXITED(status)) {
      std::cout << "Process " << pid << " exited\n";
      break;
    }

    if (WIFSTOPPED(status)) {
      if (WSTOPSIG(status) == SIGTRAP) {
        std::cout << "Breakpoint hit!\n";
        print_registers(pid);
        handle_breakpoint(pid, addr, original_instruction);
      }
    }
  }
}

int main(int argc, char *argv[]) {
  if (argc != 3) {
    std::cerr << "Usage: " << argv[0] << " <pid> <breakpoint_address_hex>\n";
    return 1;
  }

  pid_t pid = std::stoi(argv[1]);
  void *addr = reinterpret_cast<void *>(std::stoull(argv[2], nullptr, 16));

  attach_process(pid);
  uint32_t original_instruction = save_original_instruction(pid, addr);
  set_breakpoint(pid, addr, original_instruction);
  debug_loop(pid, addr, original_instruction);

  // クリーンアップ
  long data = ptrace(PTRACE_PEEKTEXT, pid, addr, nullptr);
  long restored = (data & ~0xFFFFFFFF) | original_instruction;
  ptrace(PTRACE_POKETEXT, pid, addr, restored);
  ptrace(PTRACE_DETACH, pid, nullptr, nullptr);

  return 0;
}