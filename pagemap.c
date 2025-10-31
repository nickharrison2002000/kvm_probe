#include <err.h>
#include <errno.h>
#include <getopt.h>
#include <inttypes.h>
#include <limits.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/stat.h>
#include <fcntl.h>
#include <dirent.h>

/* unnecessary and boring */
#define __PROG__        "getPAGEMAP"
#define __EXEC__        "pagemap"
#define __VER__         "19042002be"
#define __COPYLEFT__    "Copyright 2011 Columbia University.\nThis is free software; see the source for copying conditions. There is NO\nwarranty; not even for MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE."
#define __BUGS__        "<vpk@cs.columbia.edu>"

/* constants */
#define BASE10  10              /* base 10 */
#define BASE16  16              /* base 16 */
#define PATH_SZ         64              /* path size */
#define PRESENT_MASK    (1ULL << 63)    /* get bit 63 from a 64-bit integer */
#define PFN_MASK        ((1ULL << 55) - 1)      /* get bits 0-54 from
                                           a 64-bit integer */
#define SWAP_MASK       (1ULL << 62)    /* swap bit */
#define SOFT_DIRTY      (1ULL << 55)    /* soft-dirty bit */

/* Kernel address space starts here on x86-64 */
#define KERNEL_ADDR_START      0xFFFF800000000000ULL

/* QEMU RAM region minimum size */
#define QEMU_RAM_REGION_MIN_SIZE (256 * 1024 * 1024ULL) /* 256MB minimum for QEMU RAM */

/* kpageflags bit definitions */
#define KPF_LOCKED              0
#define KPF_ERROR               1
#define KPF_REFERENCED          2
#define KPF_UPTODATE            3
#define KPF_DIRTY               4
#define KPF_LRU                 5
#define KPF_ACTIVE              6
#define KPF_SLAB                7
#define KPF_WRITEBACK           8
#define KPF_RECLAIM             9
#define KPF_BUDDY               10
#define KPF_MMAP                11
#define KPF_ANON                12
#define KPF_SWAPCACHE           13
#define KPF_SWAPBACKED          14
#define KPF_COMPOUND_HEAD       15
#define KPF_COMPOUND_TAIL       16
#define KPF_HUGE                17
#define KPF_UNEVICTABLE         18
#define KPF_HWPOISON            19
#define KPF_NOPAGE              20
#define KPF_KSM                 21
#define KPF_THP                 22
#define KPF_BALLOON             23
#define KPF_ZERO_PAGE           24
#define KPF_IDLE                25

static void print_ascii(const unsigned char* buf, size_t len) {
    for (size_t i = 0; i < len; i++)
        printf("%c", (buf[i] >= 32 && buf[i] <= 126) ? buf[i] : '.');
}

/* help
 *
 * display useful information
 */
static void
help(void)
{
        (void)fprintf(stdout, "Usage: %s [OPTION]...\n", __EXEC__);
        (void)fprintf(stdout, "Read /proc/<pid>/pagemap and /proc/kpageflags.\n\n");
        (void)fprintf(stdout, "\t--scan-flag HEXVAL\tScan all guest physical memory for value\n");
        (void)fprintf(stdout, "\t--scan-mmio START END STEP --scan-flag HEXVAL\tScan MMIO region for value\n");
        (void)fprintf(stdout, "\t--scan-pattern FILE\tScan using patterns from file\n");
        (void)fprintf(stdout, "\t--output-script\tScripting output for automation\n");
        (void)fprintf(stdout, "\t--auto-qemu\t\tAutomatically detect QEMU PID\n");
        (void)fprintf(stdout, "\t--batch-gpa FILE\tBatch translate GPAs from file\n");
        (void)fprintf(stdout, "\t--export-maps FORMAT\tExport memory maps (python, json, shell)\n");
        (void)fprintf(stdout, "\t--find-symbol ADDR\tFind which mapping contains address\n");
        (void)fprintf(stdout,
        "\t-p, --pid=NUM\t\tread the pagemap of process with PID=NUM\n");
        (void)fprintf(stdout,
        "\t-a, --virt=NUM\t\tread the pagemap entry for virtual address=NUM\n");
        (void)fprintf(stdout,
        "\t-f, --pfn=NUM\t\tdirectly query kpageflags for PFN=NUM\n");
        (void)fprintf(stdout,
        "\t-k, --kpageflags\tquery /proc/kpageflags for the PFN\n");
        (void)fprintf(stdout,
        "\t-q, --qemu-pid=NUM\tQEMU PID for translating GPA to HPA or HPA to GPA\n");
        (void)fprintf(stdout,
        "\t-g, --gpa=NUM\t\tGuest Physical Address to translate to HPA\n");
        (void)fprintf(stdout,
        "\t-H, --hpa=NUM\t\tHost Physical Address to translate to GPA\n");
        (void)fprintf(stdout, "\t-h, --help\t\tdisplay this help and exit\n");
        (void)fprintf(stdout,
               "\t-v, --version\t\tprint version information and exit\n\n");
        (void)fprintf(stdout, "Report bugs to %s\n", __BUGS__);
}

static void
version(void)
{
        (void)fprintf(stdout, "%s %s\n\n", __PROG__, __VER__);
        (void)fprintf(stdout, "%s\n", __COPYLEFT__);
}

static int
is_kvm_guest(void)
{
#if defined(__x86_64__) || defined(__i386__)
        unsigned int eax, ebx, ecx, edx;
        eax = 0x40000000;
        __asm__ __volatile__ ("cpuid"
                              : "=a"(eax), "=b"(ebx), "=c"(ecx), "=d"(edx)
                              : "a"(eax));
        if (ebx == 0x4B4D564B && ecx == 0x564B4D56 && edx == 0x0000004D) {
                return 1;
        }
#endif
        return 0;
}

/* Enhanced QEMU process detection */
static pid_t
find_qemu_processes(void)
{
    DIR *dir;
    struct dirent *entry;
    pid_t candidates[10] = {0};
    int count = 0;
    
    dir = opendir("/proc");
    if (!dir) return -1;
    
    while ((entry = readdir(dir)) != NULL && count < 10) {
        pid_t pid = atoi(entry->d_name);
        if (pid > 0) {
            char path[PATH_SZ], line[1024];
            FILE *fp;
            
            snprintf(path, PATH_SZ, "/proc/%d/cmdline", pid);
            fp = fopen(path, "r");
            if (fp) {
                if (fgets(line, sizeof(line), fp)) {
                    if (strstr(line, "qemu-system") || strstr(line, "qemu-kvm") || 
                        strstr(line, "kvm")) {
                        candidates[count++] = pid;
                        printf("Found QEMU process: PID %d - %s\n", pid, line);
                    }
                }
                fclose(fp);
            }
        }
    }
    closedir(dir);
    
    if (count == 1) return candidates[0];
    if (count > 1) {
        printf("Multiple QEMU processes found. Using PID %d\n", candidates[0]);
        return candidates[0];
    }
    return -1;
}

/* Enhanced: Scan for flag in file (guest RAM or MMIO) */
int scan_file_for_flag(const char *path, size_t blocksize, const unsigned char *flag, size_t flaglen, int output_script) {
    int fd = open(path, O_RDONLY);
    if (fd < 0) {
        perror("Failed to open file for scan");
        return 1;
    }
    unsigned char *buf = malloc(blocksize);
    if (!buf) {
        perror("malloc for scan");
        close(fd);
        return 1;
    }
    off_t offset = 0;
    ssize_t r;
    int found = 0;
    while ((r = read(fd, buf, blocksize)) > 0) {
        for (ssize_t i = 0; i < r - (ssize_t)flaglen + 1; i++) {
            if (memcmp(buf + i, flag, flaglen) == 0) {
                found = 1;
                if (output_script)
                    printf("echo \"Flag value found at offset 0x%lx\";\n", offset + i);
                else {
                    printf("[MATCH] Offset 0x%lx: ", offset + i);
                    for (size_t f = 0; f < flaglen; f++)
                        printf("%02x", buf[i+f]);
                    printf(" [");
                    print_ascii(buf + i, flaglen);
                    printf("]\n");
                }
            }
        }
        offset += r;
    }
    free(buf);
    close(fd);
    if (!found)
        printf("[*] Flag value not found in %s\n", path);
    return found ? 0 : 1;
}

int scan_guest_ram_for_flag(const unsigned char* flag, size_t flaglen, int output_script) {
    printf("[*] Scanning /dev/mem for flag value\n");
    return scan_file_for_flag("/dev/mem", 0x10000, flag, flaglen, output_script);
}

int scan_mmio_for_flag(uint64_t start, uint64_t end, uint64_t step, const unsigned char* flag, size_t flaglen, int output_script) {
    printf("[*] Scanning MMIO region 0x%lx - 0x%lx for flag value\n", start, end);
    int fd = open("/dev/mem", O_RDONLY);
    if (fd < 0) {
        perror("Failed to open /dev/mem for MMIO scan");
        return 1;
    }
    unsigned char *buf = malloc(step);
    if (!buf) {
        perror("malloc for MMIO scan");
        close(fd);
        return 1;
    }
    int found = 0;
    for (uint64_t addr = start; addr < end; addr += step) {
        if (lseek(fd, addr, SEEK_SET) == (off_t)-1) {
            continue;
        }
        ssize_t r = read(fd, buf, step);
        if (r < (ssize_t)flaglen) continue;
        for (ssize_t i = 0; i < r - (ssize_t)flaglen + 1; i++) {
            if (memcmp(buf + i, flag, flaglen) == 0) {
                found = 1;
                if (output_script)
                    printf("echo \"Flag value found in MMIO at 0x%lx offset %lx\";\n", addr, addr + i);
                else {
                    printf("[MATCH] MMIO Addr 0x%lx: ", addr + i);
                    for (size_t f = 0; f < flaglen; f++)
                        printf("%02x", buf[i+f]);
                    printf(" [");
                    print_ascii(buf + i, flaglen);
                    printf("]\n");
                }
            }
        }
    }
    free(buf);
    close(fd);
    if (!found)
        printf("[*] Flag value not found in MMIO region\n");
    return found ? 0 : 1;
}

/* Pattern-based scanning */
int scan_for_patterns(const char *path, const char *pattern_file, int output_script) {
    FILE *pf = fopen(pattern_file, "r");
    if (!pf) {
        perror("Failed to open pattern file");
        return 1;
    }
    
    char pattern_name[256];
    unsigned char pattern[256];
    size_t pattern_len;
    int found_any = 0;
    
    while (fscanf(pf, "%255[^:]:", pattern_name) == 1) {
        char hex_pattern[512];
        if (fscanf(pf, "%511[^\n]\n", hex_pattern) == 1) {
            pattern_len = strlen(hex_pattern) / 2;
            for (size_t i = 0; i < pattern_len; i++) {
                sscanf(hex_pattern + 2*i, "%2hhx", &pattern[i]);
            }
            
            printf("[*] Scanning for pattern: %s\n", pattern_name);
            if (scan_file_for_flag(path, 0x10000, pattern, pattern_len, output_script) == 0) {
                found_any = 1;
            }
        }
    }
    fclose(pf);
    return found_any ? 0 : 1;
}

/*
 * find_qemu_ram_region: Find the base virtual address and size of the largest anonymous mapping in /proc/<pid>/maps
 */
static uint64_t
find_qemu_ram_region(pid_t pid, uint64_t *size_out)
{
    char path[PATH_SZ];
    FILE *fp;
    char line[1024];
    uint64_t max_size = 0;
    uint64_t base = 0;
    int region_count = 0;

    snprintf(path, PATH_SZ, "/proc/%d/maps", pid);
    fp = fopen(path, "r");
    if (!fp) {
        warnx("Failed to open %s", path);
        return 0;
    }

    (void)fprintf(stdout, "Scanning /proc/%d/maps for RAM regions...\n", pid);

    while (fgets(line, sizeof(line), fp)) {
        uint64_t start, end;
        char perms[5];
        long offset;
        char dev[10];
        long inode;
        char pathname[1024] = {0};

        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %lx %9s %ld %1023[^\n]",
                  &start, &end, perms, &offset, dev, &inode, pathname) >= 6) {
            if (pathname[0] == '\0' && strstr(perms, "rw") && offset == 0) {
                uint64_t size = end - start;
                region_count++;
                (void)fprintf(stdout, "  Region %d: 0x%" PRIx64 "-0x%" PRIx64 " (size: 0x%" PRIx64 ")\n",
                            region_count, start, end, size);
                if (size > max_size) {
                    max_size = size;
                    base = start;
                }
            }
        }
    }

    fclose(fp);

    if (base == 0) {
        warnx("No suitable RAM region found in /proc/%d/maps", pid);
        warnx("Looking for large anonymous rw mappings with offset 0");
    } else {
        (void)fprintf(stdout, "Selected largest RAM region: 0x%" PRIx64 "-0x%" PRIx64 " (size: 0x%" PRIx64 ")\n",
                     base, base + max_size, max_size);
    }

    if (size_out) *size_out = max_size;

    return base;
}

/* print_kpageflags: decode and print kpageflags bits */
static void
print_kpageflags(uint64_t flags, int is_guest)
{
        (void)fprintf(stdout, "Page flags: 0x%016" PRIx64 "\n", flags);

        if (flags == 0) {
                (void)fprintf(stdout, "  (no flags set)\n");
                return;
        }

        if (flags & (1ULL << KPF_LOCKED))       fprintf(stdout, "  - LOCKED\n");
        if (flags & (1ULL << KPF_ERROR))        fprintf(stdout, "  - ERROR\n");
        if (flags & (1ULL << KPF_REFERENCED))   fprintf(stdout, "  - REFERENCED\n");
        if (flags & (1ULL << KPF_UPTODATE))     fprintf(stdout, "  - UPTODATE\n");
        if (flags & (1ULL << KPF_DIRTY))        fprintf(stdout, "  - DIRTY\n");
        if (flags & (1ULL << KPF_LRU))          fprintf(stdout, "  - LRU\n");
        if (flags & (1ULL << KPF_ACTIVE))       fprintf(stdout, "  - ACTIVE\n");
        if (flags & (1ULL << KPF_SLAB))         fprintf(stdout, "  - SLAB\n");
        if (flags & (1ULL << KPF_WRITEBACK))    fprintf(stdout, "  - WRITEBACK\n");
        if (flags & (1ULL << KPF_RECLAIM))      fprintf(stdout, "  - RECLAIM\n");
        if (flags & (1ULL << KPF_BUDDY))        fprintf(stdout, "  - BUDDY\n");
        if (flags & (1ULL << KPF_MMAP))         fprintf(stdout, "  - MMAP\n");
        if (flags & (1ULL << KPF_ANON))         fprintf(stdout, "  - ANON\n");
        if (flags & (1ULL << KPF_SWAPCACHE))    fprintf(stdout, "  - SWAPCACHE\n");
        if (flags & (1ULL << KPF_SWAPBACKED))   fprintf(stdout, "  - SWAPBACKED\n");
        if (flags & (1ULL << KPF_COMPOUND_HEAD)) fprintf(stdout, "  - COMPOUND_HEAD\n");
        if (flags & (1ULL << KPF_COMPOUND_TAIL)) fprintf(stdout, "  - COMPOUND_TAIL\n");
        if (flags & (1ULL << KPF_HUGE))         fprintf(stdout, "  - HUGE\n");
        if (flags & (1ULL << KPF_UNEVICTABLE))  fprintf(stdout, "  - UNEVICTABLE\n");
        if (flags & (1ULL << KPF_HWPOISON))     fprintf(stdout, "  - HWPOISON\n");
        if (flags & (1ULL << KPF_NOPAGE))       fprintf(stdout, "  - NOPAGE\n");
        if (flags & (1ULL << KPF_KSM))          fprintf(stdout, "  - KSM\n");
        if (flags & (1ULL << KPF_THP))          fprintf(stdout, "  - THP (Transparent Huge Page)\n");
        if (flags & (1ULL << KPF_BALLOON))      fprintf(stdout, "  - BALLOON\n");
        if (flags & (1ULL << KPF_ZERO_PAGE))    fprintf(stdout, "  - ZERO_PAGE\n");
        if (flags & (1ULL << KPF_IDLE))         fprintf(stdout, "  - IDLE\n");

        if ((flags & (1ULL << KPF_LRU)) && !(flags & (1ULL << KPF_UNEVICTABLE))) {
                fprintf(stdout, "  - EVICTABLE");
                if (!is_guest) {
                        fprintf(stdout, " (can be mapped to KVM guest)\n");
                } else {
                        fprintf(stdout, "\n");
                }
        }
}

/* query_kpageflags: query /proc/kpageflags for a given PFN */
static void
query_kpageflags(uint64_t pfn, long psize, int is_guest)
{
        const char      *path = "/proc/kpageflags";
        int             fd = -1;
        uint64_t        flags = 0;
        off_t           offset;
        ssize_t         bytes_read;

        uint64_t pa = pfn * (uint64_t)psize;

        (void)fprintf(stdout, "Querying PFN: %" PRIu64 " (0x%" PRIx64 ")\n", pfn, pfn);
        (void)fprintf(stdout, "%s Physical Address: %" PRIu64 " (0x%" PRIx64 ")\n",
                     is_guest ? "Guest" : "Host", pa, pa);

        if ((fd = open(path, O_RDONLY)) == -1)
               errx(7, "failed while trying to open %s -- %s (need root?)",
                    path, strerror(errno));
        offset = pfn * sizeof(uint64_t);

        if (lseek(fd, offset, SEEK_SET) == -1) {
               (void)close(fd);
               errx(7, "failed while trying to seek in kpageflags -- %s",
                        strerror(errno));
        }

        bytes_read = read(fd, &flags, sizeof(uint64_t));
        if (bytes_read != sizeof(uint64_t)) {
               if (bytes_read == -1) {
                       (void)close(fd);
                       errx(7, "failed while trying to read kpageflags -- %s",
                                strerror(errno));
               }
               else if (bytes_read == 0) {
                       (void)close(fd);
                       errx(7, "PFN %" PRIu64 " is out of range", pfn);
               }
               else {
                       (void)close(fd);
                       errx(7, "partial read of kpageflags (got %zd bytes)",
                                bytes_read);
               }
        }

        print_kpageflags(flags, is_guest);
        (void)close(fd);
}

/* get_guest_symbol: Use /proc/kmod to find the nearest symbol <= vaddr and compute offset */
static void
get_guest_symbol(uint64_t vaddr, char *buf, size_t bufsz)
{
        FILE *fp;
        char line[1024];
        uint64_t sym_addr;
        uint64_t max_sym_addr = 0;
        char name[256];
        char last_name[256] = {0};

        fp = fopen("/proc/kmod", "r");
        if (!fp) {
                snprintf(buf, bufsz, "Failed to open /proc/kmod");
                return;
        }

        while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "%" SCNx64 " %255s", &sym_addr, name) == 2) {
                        if (sym_addr <= vaddr && sym_addr > max_sym_addr) {
                                max_sym_addr = sym_addr;
                                strncpy(last_name, name, sizeof(last_name) - 1);
                                last_name[sizeof(last_name) - 1] = '\0';
                        }
                }
        }
        fclose(fp);

        if (last_name[0]) {
                uint64_t offset = vaddr - max_sym_addr;
                if (offset == 0) {
                        snprintf(buf, bufsz, "%s", last_name);
                } else {
                        snprintf(buf, bufsz, "%s + 0x%" PRIx64, last_name, offset);
                }
        } else {
                snprintf(buf, bufsz, "No symbol found");
        }
}

/* get_host_symbol: Use nm on host vmlinux to find the nearest symbol <= vaddr and compute offset */
static void
get_host_symbol(uint64_t vaddr, char *buf, size_t bufsz)
{
        FILE *fp;
        char line[1024];
        uint64_t sym_addr;
        uint64_t max_sym_addr = 0;
        char type;
        char name[256];
        char last_name[256] = {0};

        fp = popen("nm -n vmlinux 2>/dev/null", "r");
        if (!fp) {
                snprintf(buf, bufsz, "Failed to run nm on host vmlinux (make sure vmlinux is in current directory)");
                return;
        }

        while (fgets(line, sizeof(line), fp)) {
                if (sscanf(line, "%" SCNx64 " %c %255s", &sym_addr, &type, name) == 3) {
                        if (sym_addr <= vaddr && sym_addr > max_sym_addr) {
                                max_sym_addr = sym_addr;
                                strncpy(last_name, name, sizeof(last_name) - 1);
                                last_name[sizeof(last_name) - 1] = '\0';
                        }
                }
        }
        pclose(fp);

        if (last_name[0]) {
                uint64_t offset = vaddr - max_sym_addr;
                if (offset == 0) {
                        snprintf(buf, bufsz, "%s", last_name);
                } else {
                        snprintf(buf, bufsz, "%s + 0x%" PRIx64, last_name, offset);
                }
        } else {
                snprintf(buf, bufsz, "No symbol found in host vmlinux");
        }
}

/* Enhanced symbol finding with multiple methods */
static void
find_symbol_in_mappings(pid_t pid, uint64_t addr, int is_guest)
{
    char path[PATH_SZ];
    FILE *fp;
    char line[1024];
    
    snprintf(path, PATH_SZ, "/proc/%d/maps", pid);
    fp = fopen(path, "r");
    if (!fp) return;
    
    while (fgets(line, sizeof(line), fp)) {
        uint64_t start, end;
        char perms[5], pathname[1024] = {0};
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %*s %*s %*s %1023[^\n]",
                  &start, &end, perms, pathname) >= 3) {
            if (addr >= start && addr < end) {
                printf("Address 0x%016" PRIx64 " is in mapping: 0x%016" PRIx64 "-0x%016" PRIx64 " %s %s\n",
                       addr, start, end, perms, pathname[0] ? pathname : "[anon]");
                
                if (pathname[0] && strstr(pathname, ".so")) {
                    /* Library mapping - could use nm/readelf here */
                    printf("This appears to be in shared library: %s\n", pathname);
                }
                break;
            }
        }
    }
    fclose(fp);
}

/* querypmap: open the /proc/<pid>/pagemap of a process and search the page frame info for a specific virtual address */
static uint64_t
querypmap(pid_t pid, uint64_t vaddr, long psize, int use_kpageflags, int is_guest)
{
        char    path[PATH_SZ];
        uint64_t        pentry  = 0;
        uint64_t        pfn     = 0;
        int     fd      = -1;
        uint64_t        page_num;
        off_t           offset;
        ssize_t         bytes_read;
        (void)memset(path, 0, PATH_SZ);

        if (snprintf(path, PATH_SZ, "/proc/%d/pagemap", pid) >= PATH_SZ)
               errx(4, "failed while trying to open /proc/%d/pagemap -- path too long",
                        pid);

        if ((fd = open(path, O_RDONLY)) == -1)
               errx(4, "failed while trying to open %s -- %s", path,
                        strerror(errno));

        page_num = vaddr / psize;
        offset = page_num * sizeof(uint64_t);

        if (lseek(fd, offset, SEEK_SET) == -1) {
               (void)close(fd);
               errx(5, "failed while trying to seek in pagemap (offset: %ld) -- %s",
                        offset, strerror(errno));
        }

        bytes_read = read(fd, &pentry, sizeof(uint64_t));
        if (bytes_read != sizeof(uint64_t)) {
               if (bytes_read == -1) {
                       (void)close(fd);
                       errx(6,
                       "failed while trying to read a pagemap entry -- %s",
                       strerror(errno));
               }
               else if (bytes_read == 0) {
                       (void)close(fd);
                       errx(6,
                       "address %#" PRIx64 " (page %" PRIu64 ") is outside process address space",
                       vaddr, page_num);
               }
               else {
                       (void)close(fd);
                       errx(6,
                       "partial read of pagemap entry (got %zd bytes, expected %zu)",
                       bytes_read, sizeof(uint64_t));
               }
        }
        (void)close(fd);

        if (pentry & SWAP_MASK) {
               warnx("%#" PRIx64 " is swapped out", vaddr);
               return 0;
        }

        if ((pentry & PRESENT_MASK) == 0) {
               warnx("%#" PRIx64 " is not present in physical memory", vaddr);
               return 0;
        }

        pfn = pentry & PFN_MASK;
        (void)fprintf(stdout, "Virtual address: %#" PRIx64 "\n", vaddr);
        (void)fprintf(stdout, "Page number: %" PRIu64 "\n", page_num);
        (void)fprintf(stdout, "PFN: %" PRIu64 " (0x%" PRIx64 ")\n", pfn, pfn);

        uint64_t pa = pfn * (uint64_t)psize;
        (void)fprintf(stdout, "%s Physical Address: %" PRIu64 " (0x%" PRIx64 ")\n",
                     is_guest ? "Guest" : "Host", pa, pa);

        if (vaddr >= KERNEL_ADDR_START) {
                char buf[1024];
                if (is_guest) {
                        get_guest_symbol(vaddr, buf, sizeof(buf));
                        (void)fprintf(stdout, "Guest kernel symbol: %s\n", buf);
                } else {
                        get_host_symbol(vaddr, buf, sizeof(buf));
                        (void)fprintf(stdout, "Host kernel symbol: %s\n", buf);
                }
        }

        if (use_kpageflags) {
               (void)fprintf(stdout, "\n");
               query_kpageflags(pfn, psize, is_guest);
        }

        return pfn;
}

/* translate_gpa_to_hpa: Translate GPA to HPA using QEMU PID */
static void
translate_gpa_to_hpa(pid_t qemu_pid, uint64_t gpa, long psize, int use_kpageflags, int is_guest)
{
        uint64_t hva_base = find_qemu_ram_region(qemu_pid, NULL);
        if (hva_base == 0) {
                errx(3, "Failed to find QEMU RAM base");
        }
        uint64_t gpa_page_aligned = gpa & ~((uint64_t)(psize - 1));
        uint64_t offset_in_page = gpa & ((uint64_t)(psize - 1));
        uint64_t hva = hva_base + gpa_page_aligned + offset_in_page;

        (void)fprintf(stdout, "GPA: %#" PRIx64 "\n", gpa);
        (void)fprintf(stdout, "GPA (page-aligned): %#" PRIx64 "\n", gpa_page_aligned);
        (void)fprintf(stdout, "Offset within page: %#" PRIx64 "\n", offset_in_page);
        (void)fprintf(stdout, "Assumed HVA base: %#" PRIx64 "\n", hva_base);
        (void)fprintf(stdout, "HVA: %#" PRIx64 "\n", hva);

        uint64_t pfn = querypmap(qemu_pid, hva, psize, 0, 0);

        if (use_kpageflags && pfn != 0) {
                (void)fprintf(stdout, "\n");
                query_kpageflags(pfn, psize, 0);
        }
}

/* translate_hpa_to_gpa: Translate HPA to GPA using QEMU PID by iterating through PFNs */
static void
translate_hpa_to_gpa(pid_t qemu_pid, uint64_t hpa, long psize, int use_kpageflags, int is_guest)
{
    uint64_t target_pfn = hpa / psize;
    uint64_t ram_size;
    uint64_t hva_base = find_qemu_ram_region(qemu_pid, &ram_size);
    if (hva_base == 0) {
        errx(3, "Failed to find QEMU RAM region");
    }
    char path[PATH_SZ];
    int fd = -1;
    uint64_t pentry = 0;
    ssize_t bytes_read;
    int found = 0;
    snprintf(path, PATH_SZ, "/proc/%d/pagemap", qemu_pid);
    if ((fd = open(path, O_RDONLY)) == -1) {
        errx(4, "failed while trying to open %s -- %s", path, strerror(errno));
    }
    uint64_t num_pages = ram_size / psize;
    (void)fprintf(stdout, "HPA: 0x%" PRIx64 "\n", hpa);
    (void)fprintf(stdout, "Target PFN: %" PRIu64 " (0x%" PRIx64 ")\n", target_pfn, target_pfn);
    (void)fprintf(stdout, "HVA base: 0x%" PRIx64 "\n", hva_base);
    (void)fprintf(stdout, "RAM size: 0x%" PRIx64 " (%" PRIu64 " pages)\n", ram_size, num_pages);
    (void)fprintf(stdout, "Iterating through %" PRIu64 " PFNs...\n", num_pages);
    for (uint64_t i = 0; i < num_pages; i++) {
        uint64_t hva = hva_base + i * psize;
        uint64_t page_num = hva / psize;
        off_t offset = page_num * sizeof(uint64_t);
        if (lseek(fd, offset, SEEK_SET) == -1) {
            (void)close(fd);
            errx(5, "failed while trying to seek in pagemap -- %s", strerror(errno));
        }
        bytes_read = read(fd, &pentry, sizeof(uint64_t));
        if (bytes_read != sizeof(uint64_t)) {
            (void)close(fd);
            errx(6, "failed while trying to read pagemap entry -- %s", strerror(errno));
        }
        if ((pentry & PRESENT_MASK) && ((pentry & PFN_MASK) == target_pfn)) {
            uint64_t gpa = i * psize;
            uint64_t offset_in_page = hpa % psize;
            uint64_t full_gpa = gpa + offset_in_page;
            (void)fprintf(stdout, "\n*** MATCH FOUND ***\n");
            (void)fprintf(stdout, "HVA: 0x%" PRIx64 "\n", hva);
            (void)fprintf(stdout, "Page index: %" PRIu64 "\n", i);
            (void)fprintf(stdout, "GPA (page-aligned): 0x%" PRIx64 "\n", gpa);
            (void)fprintf(stdout, "Offset in page: 0x%" PRIx64 "\n", offset_in_page);
            (void)fprintf(stdout, "Full GPA: 0x%" PRIx64 "\n", full_gpa);
            found = 1;
            if (use_kpageflags) {
                (void)fprintf(stdout, "\n");
                query_kpageflags(target_pfn, psize, 0);
            }
            break;
        }
        if ((i + 1) % 100000 == 0 || i == num_pages - 1) {
            (void)fprintf(stdout, "Scanned %" PRIu64 "/%" PRIu64 " pages (%.1f%%)\n",
                         i + 1, num_pages, (double)(i + 1) / num_pages * 100);
        }
    }
    (void)close(fd);
    if (!found) {
        warnx("No matching GPA found for HPA 0x%" PRIx64, hpa);
        warnx("Possible reasons:");
        warnx("1. The HPA is not currently mapped by QEMU");
        warnx("2. The page is swapped out or not present");
        warnx("3. The QEMU PID is incorrect");
        warnx("4. The HPA is not part of guest RAM");
    }
}

/* Batch translation for multiple addresses */
static void
batch_translate_gpa_to_hpa(pid_t qemu_pid, const char *gpa_list_file, long psize)
{
    FILE *fp = fopen(gpa_list_file, "r");
    if (!fp) {
        warnx("Cannot open GPA list file: %s", gpa_list_file);
        return;
    }
    
    char line[256];
    uint64_t hva_base = find_qemu_ram_region(qemu_pid, NULL);
    
    if (hva_base == 0) {
        fclose(fp);
        errx(3, "Failed to find QEMU RAM base");
    }
    
    printf("=== Batch GPA to HPA Translation ===\n");
    printf("Using QEMU PID: %d\n", qemu_pid);
    printf("HVA base: 0x%016" PRIx64 "\n", hva_base);
    printf("\n");
    
    while (fgets(line, sizeof(line), fp)) {
        uint64_t gpa;
        if (sscanf(line, "%" SCNx64, &gpa) == 1) {
            uint64_t gpa_page_aligned = gpa & ~((uint64_t)(psize - 1));
            uint64_t offset_in_page = gpa & ((uint64_t)(psize - 1));
            uint64_t hva = hva_base + gpa_page_aligned + offset_in_page;
            uint64_t pfn = querypmap(qemu_pid, hva, psize, 0, 0);
            
            if (pfn != 0) {
                printf("GPA: 0x%016" PRIx64 " -> HPA: 0x%016" PRIx64 "\n", 
                       gpa, pfn * psize + offset_in_page);
            } else {
                printf("GPA: 0x%016" PRIx64 " -> [NOT MAPPED]\n", gpa);
            }
        }
    }
    fclose(fp);
}

/* Export memory mappings for scripting */
static void
export_memory_mappings(pid_t pid, const char *output_format)
{
    char path[PATH_SZ];
    FILE *fp;
    char line[1024];
    
    snprintf(path, PATH_SZ, "/proc/%d/maps", pid);
    fp = fopen(path, "r");
    if (!fp) {
        warnx("Cannot open /proc/%d/maps", pid);
        return;
    }
    
    if (strcmp(output_format, "python") == 0) {
        printf("memory_regions = [\n");
        while (fgets(line, sizeof(line), fp)) {
            uint64_t start, end;
            char perms[5], pathname[1024] = {0};
            if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %*s %*s %*s %1023[^\n]",
                      &start, &end, perms, pathname) >= 3) {
                printf("    {'start': 0x%016" PRIx64 ", 'end': 0x%016" PRIx64 ", 'perms': '%s', 'path': '%s'},\n",
                       start, end, perms, pathname[0] ? pathname : "[anon]");
            }
        }
        printf("]\n");
    } else if (strcmp(output_format, "json") == 0) {
        printf("{\"memory_regions\": [\n");
        int first = 1;
        while (fgets(line, sizeof(line), fp)) {
            uint64_t start, end;
            char perms[5], pathname[1024] = {0};
            if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %*s %*s %*s %1023[^\n]",
                      &start, &end, perms, pathname) >= 3) {
                if (!first) printf(",\n");
                printf("  {\"start\": \"0x%016" PRIx64 "\", \"end\": \"0x%016" PRIx64 "\", \"perms\": \"%s\", \"path\": \"%s\"}",
                       start, end, perms, pathname[0] ? pathname : "[anon]");
                first = 0;
            }
        }
        printf("\n]}\n");
    } else {
        /* Default shell format */
        while (fgets(line, sizeof(line), fp)) {
            printf("%s", line);
        }
    }
    fclose(fp);
}

/* Main entry */
int
main(int argc, char **argv)
{
    long    psize;
    pid_t   pid     = -1;
    uint64_t        vaddr   = 0;
    uint64_t        pfn_direct = 0;
    uint64_t        aligned_vaddr;
    int             use_kpageflags = 0;
    int             direct_pfn_mode = 0;
    pid_t   qemu_pid = -1;
    uint64_t        gpa     = 0;
    int             translate_gpa_mode = 0;
    uint64_t        hpa     = 0;
    int             translate_hpa_mode = 0;
    int             is_guest = is_kvm_guest();

    int scan_flag_mode = 0, scan_mmio_mode = 0, output_script = 0;
    int auto_qemu_mode = 0, batch_gpa_mode = 0, export_maps_mode = 0;
    int find_symbol_mode = 0, scan_pattern_mode = 0;
    unsigned char flagval[32] = {0};
    size_t flaglen = 0;
    uint64_t mmio_start = 0, mmio_end = 0, mmio_step = 0;
    char *batch_gpa_file = NULL;
    char *export_maps_format = NULL;
    char *pattern_file = NULL;
    uint64_t find_symbol_addr = 0;

    struct option long_options[] = {
        {"scan-flag", 1, NULL, 'F'},
        {"scan-mmio", 3, NULL, 'M'},
        {"scan-pattern", 1, NULL, 'P'},
        {"output-script", 0, NULL, 'S'},
        {"auto-qemu", 0, NULL, 'Q'},
        {"batch-gpa", 1, NULL, 'B'},
        {"export-maps", 1, NULL, 'E'},
        {"find-symbol", 1, NULL, 's'},
        {"pid",          1, NULL, 'p'},
        {"virt",         1, NULL, 'a'},
        {"pfn",          1, NULL, 'f'},
        {"kpageflags",   0, NULL, 'k'},
        {"qemu-pid",     1, NULL, 'q'},
        {"gpa",          1, NULL, 'g'},
        {"hpa",          1, NULL, 'H'},
        {"help",         0, NULL, 'h'},
        {"version",      0, NULL, 'v'},
        {NULL,           0, NULL, 0}
    };

    printf("=== Enhanced PAGEMAP for KVMCTF Exploitation ===\n");
    printf("  * Automated flag scanning modes enabled\n");
    printf("  * Use --scan-flag <hexvalue> to scan guest RAM for host flag values\n");
    printf("  * Use --scan-mmio <start> <end> <step> --scan-flag <hexvalue> to scan device regions\n");
    printf("  * Use --output-script for scripting-friendly output\n");

    /* First round: enhanced options */
    int opt;
    int long_opt_indx = 0;
    while ((opt = getopt_long(argc, argv, "F:M:P:SQB:E:s:", long_options, &long_opt_indx)) != -1) {
        switch (opt) {
            case 'F':
                scan_flag_mode = 1;
                {
                    const char *hex = optarg;
                    size_t len = strlen(hex);
                    if (len % 2 != 0 || len > sizeof(flagval)*2) {
                        fprintf(stderr, "Flag value must be even hex string <= %lu chars\n", sizeof(flagval)*2);
                        exit(1);
                    }
                    flaglen = len / 2;
                    for (size_t i = 0; i < flaglen; i++) {
                        if (sscanf(hex + 2*i, "%2hhx", &flagval[i]) != 1) {
                            fprintf(stderr, "Invalid hex in flag value\n");
                            exit(1);
                        }
                    }
                }
                break;
            case 'M':
                scan_mmio_mode = 1;
                if (optind + 2 <= argc) {
                    mmio_start = strtoull(argv[optind - 1], NULL, 16);
                    mmio_end   = strtoull(argv[optind], NULL, 16);
                    mmio_step  = strtoull(argv[optind + 1], NULL, 16);
                }
                break;
            case 'P':
                scan_pattern_mode = 1;
                pattern_file = optarg;
                break;
            case 'S':
                output_script = 1;
                break;
            case 'Q':
                auto_qemu_mode = 1;
                break;
            case 'B':
                batch_gpa_mode = 1;
                batch_gpa_file = optarg;
                break;
            case 'E':
                export_maps_mode = 1;
                export_maps_format = optarg;
                break;
            case 's':
                find_symbol_mode = 1;
                find_symbol_addr = strtoull(optarg, NULL, 16);
                break;
        }
    }

    /* Handle enhanced modes */
    if (scan_pattern_mode) {
        return scan_for_patterns("/dev/mem", pattern_file, output_script);
    }
    
    if (scan_flag_mode && !scan_mmio_mode) {
        return scan_guest_ram_for_flag(flagval, flaglen, output_script);
    } else if (scan_flag_mode && scan_mmio_mode) {
        return scan_mmio_for_flag(mmio_start, mmio_end, mmio_step, flagval, flaglen, output_script);
    }
    
    if (export_maps_mode) {
        if (pid == -1 && qemu_pid != -1) {
            pid = qemu_pid;
        }
        if (pid == -1 && auto_qemu_mode) {
            pid = find_qemu_processes();
        }
        if (pid == -1) {
            errx(3, "Need to specify PID with -p or use --auto-qemu");
        }
        export_memory_mappings(pid, export_maps_format);
        goto done;
    }
    
    if (find_symbol_mode) {
        if (pid == -1 && qemu_pid != -1) {
            pid = qemu_pid;
        }
        if (pid == -1 && auto_qemu_mode) {
            pid = find_qemu_processes();
        }
        if (pid == -1) {
            errx(3, "Need to specify PID with -p or use --auto-qemu");
        }
        find_symbol_in_mappings(pid, find_symbol_addr, is_guest);
        goto done;
    }
    
    if (batch_gpa_mode) {
        if (qemu_pid == -1 && auto_qemu_mode) {
            qemu_pid = find_qemu_processes();
        }
        if (qemu_pid == -1) {
            errx(3, "Need to specify QEMU PID with -q or use --auto-qemu");
        }
        if ((psize = sysconf(_SC_PAGESIZE)) == -1)
            errx(2, "failed while trying to read page size -- %s", strerror(errno));
        batch_translate_gpa_to_hpa(qemu_pid, batch_gpa_file, psize);
        goto done;
    }

    /* --- ORIGINAL ARGUMENT PARSING BELOW --- */
    optind = 1; /* Reset getopt */
    long_opt_indx = 0;
    while ((opt = getopt_long(argc, argv, ":hvkp:a:f:q:g:H:", long_options,
                                    &long_opt_indx)) != -1) {
           switch(opt) {
            case 'p': pid = (pid_t)strtol(optarg, NULL, BASE10); break;
            case 'a': vaddr = (uint64_t)strtoull(optarg, NULL, BASE16); break;
            case 'f': pfn_direct = (uint64_t)strtoull(optarg, NULL, BASE16); direct_pfn_mode = 1; break;
            case 'q': qemu_pid = (pid_t)strtol(optarg, NULL, BASE10); break;
            case 'g': gpa = (uint64_t)strtoull(optarg, NULL, BASE16); translate_gpa_mode = 1; break;
            case 'H': hpa = (uint64_t)strtoull(optarg, NULL, BASE16); translate_hpa_mode = 1; break;
            case 'k': use_kpageflags = 1; break;
            case 'h': help(); goto done; break;
            case 'v': version(); goto done; break;
            case '?': errx(1, "illegal option -- %s", (optind == 0) ? argv[long_opt_indx] : argv[optind - 1]); break;
            case ':': errx(1, "option requires an argument -- %s", (optind == 0) ? argv[long_opt_indx] : argv[optind - 1]); break;
            default: break;
           }
    }

    /* Auto-detect QEMU if requested */
    if (auto_qemu_mode && qemu_pid == -1) {
        qemu_pid = find_qemu_processes();
        if (qemu_pid == -1) {
            errx(3, "Failed to automatically detect QEMU process");
        }
    }

    if ((psize = sysconf(_SC_PAGESIZE)) == -1)
           errx(2, "failed while trying to read page size -- %s", strerror(errno));

    if (translate_gpa_mode) {
           if (qemu_pid == -1) {
                   errx(3, "missing `qemu-pid' argument for GPA translation");
           }
           translate_gpa_to_hpa(qemu_pid, gpa, psize, use_kpageflags, is_guest);
           goto done;
    }

    if (translate_hpa_mode) {
           if (qemu_pid == -1) {
                   errx(3, "missing `qemu-pid' argument for HPA translation");
           }
           translate_hpa_to_gpa(qemu_pid, hpa, psize, use_kpageflags, is_guest);
           goto done;
    }

    if (direct_pfn_mode) {
           query_kpageflags(pfn_direct, psize, is_guest);
           goto done;
    }

    if (pid == -1)
           errx(3, "missing `pid' argument");
    if (pid <= 0)
           errx(3, "invalid `pid' argument -- %d", pid);

    aligned_vaddr = vaddr & ~((uint64_t)(psize - 1));
    if (vaddr != aligned_vaddr) {
           warnx("virtual address %#" PRIx64 " is not page-aligned; converting to %#" PRIx64,
           vaddr, aligned_vaddr);
           vaddr = aligned_vaddr;
    }

    querypmap(pid, vaddr, psize, use_kpageflags, is_guest);

done:
    return EXIT_SUCCESS;
}
