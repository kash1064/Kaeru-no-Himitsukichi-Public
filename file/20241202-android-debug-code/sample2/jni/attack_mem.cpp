#include <fcntl.h>
#include <unistd.h>

#include <iostream>

void proc_mem_method(pid_t pid, void* addr, long new_value)
{
    char path[32];
    snprintf(path, sizeof(path), "/proc/%d/mem", pid);

    int fd = open(path, O_RDWR);
    if (fd == -1)
    {
        std::cerr << "Failed to open memory: " << strerror(errno) << std::endl;
        return;
    }

    // 指定アドレスの値を読み込む
    long current_value;
    if (pread(fd, &current_value, sizeof(current_value), (off_t)addr) == -1)
    {
        std::cerr << "Failed to read: " << strerror(errno) << std::endl;
        close(fd);
        return;
    }
    std::cout << "Current value at " << addr << ": " << current_value << std::endl;

    // 指定アドレスに値を書き込む
    if (pwrite(fd, &new_value, sizeof(new_value), (off_t)addr) == -1)
    {
        std::cerr << "Failed to write: " << strerror(errno) << std::endl;
    }

    close(fd);
}

int main(int argc, char* argv[])
{
    if (argc != 4)
    {
        std::cerr << "Usage: " << argv[0] << " <pid> <address> <new_value>" << std::endl;
        return 1;
    }

    pid_t pid = std::stol(argv[1]);
    void* addr = (void*)std::stoull(argv[2], nullptr, 16);
    long new_value = std::stol(argv[3]);

    proc_mem_method(pid, addr, new_value);

    return 0;
}