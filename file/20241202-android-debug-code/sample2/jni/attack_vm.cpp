#include <dlfcn.h>
#include <sys/syscall.h>
#include <sys/uio.h>

#include <iostream>

typedef ssize_t (*process_vm_readv_func)(pid_t, const struct iovec *, unsigned long,
                                         const struct iovec *, unsigned long, unsigned long);
typedef ssize_t (*process_vm_writev_func)(pid_t, const struct iovec *, unsigned long,
                                          const struct iovec *, unsigned long, unsigned long);
static process_vm_readv_func process_vm_readv = nullptr;
static process_vm_writev_func process_vm_writev = nullptr;

void process_vm_method(pid_t pid, void *addr, long new_value)
{
    struct iovec local;
    struct iovec remote;
    long current_value;

    local.iov_base = &current_value;
    local.iov_len = sizeof(current_value);
    remote.iov_base = addr;
    remote.iov_len = sizeof(current_value);

    // 指定アドレスの値を読み込む
    if (process_vm_readv(pid, &local, 1, &remote, 1, 0) == -1)
    {
        std::cerr << "Failed to read: " << strerror(errno) << std::endl;
        return;
    }
    std::cout << "Current value at " << addr << ": " << current_value << std::endl;

    // 指定アドレスに値を書き込む
    local.iov_base = &new_value;
    if (process_vm_writev(pid, &local, 1, &remote, 1, 0) == -1)
    {
        std::cerr << "Failed to write: " << strerror(errno) << std::endl;
    }
}

int main(int argc, char *argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <pid> <address> <new_value>" << std::endl;
        return 1;
    }

    void *handle = dlopen("libc.so", RTLD_NOW);
    if (!handle)
    {
        std::cerr << "Failed to open libc.so. Error: " << dlerror() << std::endl;
        return -1;
    }

    process_vm_readv = (process_vm_readv_func)dlsym(handle, "process_vm_readv");
    if (!process_vm_readv)
    {
        std::cerr << " Failed to find process_vm_readv symbol.Error : " << dlerror() << std::endl;
        dlclose(handle);
        return -1;
    }
    process_vm_writev = (process_vm_readv_func)dlsym(handle, "process_vm_writev");
    if (!process_vm_writev)
    {
        std::cerr << " Failed to find process_vm_writev symbol.Error : " << dlerror() << std::endl;
        dlclose(handle);
        return -1;
    }
    pid_t pid = std::stol(argv[1]);
    void *addr = (void *)std::stoull(argv[2], nullptr, 16);
    long new_value = std::stol(argv[3]);

    process_vm_method(pid, addr, new_value);

    return 0;
}