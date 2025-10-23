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


/*
 * help
 *
 * display useful information
 */
static void
help(void)
{
        /* usage info */
        (void)fprintf(stdout, "Usage: %s [OPTION]...\n", __EXEC__);
        (void)fprintf(stdout, "Read /proc/<pid>/pagemap and /proc/kpageflags.\n\n");

        /* options */
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

        /* notes */
        (void)fprintf(stdout, "NOTE: Use -p and -a together for userspace addresses\n");
        (void)fprintf(stdout, "      Use -f alone to directly query a PFN in kpageflags\n");
        (void)fprintf(stdout, "      Requires root privileges for kpageflags access\n");
        (void)fprintf(stdout, "      For guest kernel addresses (>= 0xFFFF800000000000), uses /proc/kmod for symbol resolution\n");
        (void)fprintf(stdout, "      For host kernel addresses (when doing GPA/HPA translation), uses vmlinux in current directory\n");
        (void)fprintf(stdout, "      This tool runs entirely from inside the guest VM\n");
        (void)fprintf(stdout, "      Use -q and -g together to translate GPA to HPA (requires host vmlinux for host symbol resolution)\n");
        (void)fprintf(stdout, "      Use -q and -H together to translate HPA to GPA (requires host vmlinux for host symbol resolution)\n\n");

        /* examples using the specific addresses of interest */
        (void)fprintf(stdout, "Examples for KVMCTF addresses 0xffffffff826279a and 0xffffffff82b5ee10:\n\n");

        (void)fprintf(stdout, "1. Query guest kernel addresses directly (inside guest):\n");
        (void)fprintf(stdout, "  %s -p 1 -a 0xffffffff826279a -k\t# Query first kernel address with symbol resolution\n", __EXEC__);
        (void)fprintf(stdout, "  %s -p 1 -a 0xffffffff82b5ee10 -k\t# Query second kernel address with symbol resolution\n\n", __EXEC__);

        (void)fprintf(stdout, "2. Get Guest Physical Address (GPA) for kernel addresses:\n");
        (void)fprintf(stdout, "  %s -p 1 -a 0xffffffff826279a\t\t# Get GPA for first address\n", __EXEC__);
        (void)fprintf(stdout, "  %s -p 1 -a 0xffffffff82b5ee10\t\t# Get GPA for second address\n\n", __EXEC__);

        (void)fprintf(stdout, "3. Translate GPA to Host Physical Address (HPA) using QEMU PID:\n");
        (void)fprintf(stdout, "  %s -q 1234 -g 0x6427000 -k\t\t# Translate GPA to HPA (replace 0x6427000 with actual GPA)\n", __EXEC__);
        (void)fprintf(stdout, "  %s -q 1234 -g 0x6427000\t\t# Translate without kpageflags\n\n", __EXEC__);

        (void)fprintf(stdout, "4. Translate HPA to GPA using QEMU PID:\n");
        (void)fprintf(stdout, "  %s -q 1234 -H 0xabcdef000 -k\t\t# Translate HPA to GPA (replace 0xabcdef000 with actual HPA)\n", __EXEC__);
        (void)fprintf(stdout, "  %s -q 1234 -H 0xabcdef000\t\t# Translate without kpageflags\n\n", __EXEC__);

        (void)fprintf(stdout, "5. Direct PFN queries (if you know the PFNs):\n");
        (void)fprintf(stdout, "  %s -f 0x12345 -k\t\t\t# Query guest PFN with kpageflags\n", __EXEC__);
        (void)fprintf(stdout, "  %s -f 0x67890\t\t\t\t# Query guest PFN without kpageflags\n\n", __EXEC__);

        (void)fprintf(stdout, "6. Complete workflow example:\n");
        (void)fprintf(stdout, "   # Step 1: Get GPA of kernel address in guest\n");
        (void)fprintf(stdout, "   %s -p 1 -a 0xffffffff826279a\n", __EXEC__);
        (void)fprintf(stdout, "   # Step 2: Use the GPA to find HPA via QEMU\n");
        (void)fprintf(stdout, "   %s -q 1234 -g <GPA_from_step1> -k\n\n", __EXEC__);

        (void)fprintf(stdout, "Note: Replace '1234' with actual QEMU PID and addresses with actual values\n");

        /* bugs */
        (void)fprintf(stdout, "Report bugs to %s\n", __BUGS__);
}

/*
 * version
 *
 * display version information
 */
static void
version(void)
{
        /* display version */
        (void)fprintf(stdout, "%s %s\n\n", __PROG__, __VER__);
        /* copyright info */
        (void)fprintf(stdout, "%s\n", __COPYLEFT__);
}

/*
 * is_kvm_guest
 *
 * Detect if running inside a KVM guest using CPUID
 *
 * return: 1 if KVM guest, 0 otherwise
 */
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

/*
 * find_qemu_ram_region
 *
 * Find the base virtual address and size of the largest anonymous mapping in /proc/<pid>/maps,
 * which is typically the guest RAM in QEMU.
 *
 * @pid: QEMU PID
 * @size_out: output for size
 * return: base address or 0 on failure
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

        // Parse the maps line
        if (sscanf(line, "%" SCNx64 "-%" SCNx64 " %4s %lx %9s %ld %1023[^\n]",
                  (uint64_t*)&start, (uint64_t*)&end, perms, &offset, dev, &inode, pathname) >= 6) {

            // Look for large anonymous read-write mappings (typical of guest RAM)
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

/*
 * print_kpageflags
 *
 * decode and print kpageflags bits
 *
 * @flags:     the kpageflags value
 * @is_guest:  whether running in guest
 */
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

        /* Check for evictable */
        if ((flags & (1ULL << KPF_LRU)) && !(flags & (1ULL << KPF_UNEVICTABLE))) {
                fprintf(stdout, "  - EVICTABLE");
                if (!is_guest) {
                        fprintf(stdout, " (can be mapped to KVM guest)\n");
                } else {
                        fprintf(stdout, "\n");
                }
        }
}

/*
 * query_kpageflags
 *
 * query /proc/kpageflags for a given PFN
 *
 * @pfn:       the page frame number
 */
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

        /* open kpageflags */
        if ((fd = open(path, O_RDONLY)) == -1)
               errx(7, "failed while trying to open %s -- %s (need root?)",
                    path, strerror(errno));

        /* calculate offset */
        offset = pfn * sizeof(uint64_t);

        /* seek to the PFN entry */
        if (lseek(fd, offset, SEEK_SET) == -1) {
               (void)close(fd);
               errx(7, "failed while trying to seek in kpageflags -- %s",
                        strerror(errno));
        }

        /* read the flags */
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

        /* print the flags */
        print_kpageflags(flags, is_guest);

        /* cleanup */
        (void)close(fd);
}

/*
 * get_guest_symbol
 *
 * Use /proc/kmod to find the nearest symbol <= vaddr and compute offset.
 * Used for guest kernel address resolution.
 *
 * @vaddr:     the virtual address
 * @buf:       buffer to store the symbol info
 * @bufsz:     size of the buffer
 */
static void
get_guest_symbol(uint64_t vaddr, char *buf, size_t bufsz)
{
        FILE *fp;
        char line[1024];
        uint64_t sym_addr;
        uint64_t max_sym_addr = 0;
        char name[256];
        char last_name[256] = {0};

        /* In guest: use /proc/kmod */
        fp = fopen("/proc/kmod", "r");
        if (!fp) {
                snprintf(buf, bufsz, "Failed to open /proc/kmod");
                return;
        }

        while (fgets(line, sizeof(line), fp)) {
                /* Parse /proc/kmod format: address symbol_name */
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

/*
 * get_host_symbol
 *
 * Use nm on host vmlinux to find the nearest symbol <= vaddr and compute offset.
 * Used for host kernel address resolution from inside the guest.
 *
 * @vaddr:     the virtual address
 * @buf:       buffer to store the symbol info
 * @bufsz:     size of the buffer
 */
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

        /* Use host vmlinux for symbol resolution */
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

/*
 * query the pagemap
 *
 * open the /proc/<pid>/pagemap of a process and search the page frame
 * information for a specific virtual address
 *
 * @pid:       the pid of the process that we are interested into
 * @vaddr:     the virtual address (page-aligned)
 * @psize:     page size
 * @use_kpageflags: whether to query kpageflags for the PFN
 * @is_guest:  whether running in guest
 * return:     the PFN (or 0 if not present)
 */
static uint64_t
querypmap(pid_t pid, uint64_t vaddr, long psize, int use_kpageflags, int is_guest)
{
        /* path in /proc */
        char    path[PATH_SZ];
        /* pagemap entry */
        uint64_t        pentry  = 0;
        uint64_t        pfn     = 0;

        /* file descriptor */
        int     fd      = -1;

        /* offset for seeking and page number */
        uint64_t        page_num;
        off_t           offset;
        ssize_t         bytes_read;

        /* cleanup */
        (void)memset(path, 0, PATH_SZ);

        /* format the path variable */
        if (snprintf(path, PATH_SZ, "/proc/%d/pagemap", pid) >= PATH_SZ)
               errx(4, "failed while trying to open /proc/%d/pagemap -- path too long",
                        pid);

        /* open the pagemap file with O_RDONLY */
        if ((fd = open(path, O_RDONLY)) == -1)
               errx(4, "failed while trying to open %s -- %s", path,
                        strerror(errno));

        /* calculate page number and offset */
        page_num = vaddr / psize;
        offset = page_num * sizeof(uint64_t);

        /* seek to the appropriate place */
        if (lseek(fd, offset, SEEK_SET) == -1) {
               (void)close(fd);
               errx(5, "failed while trying to seek in pagemap (offset: %ld) -- %s",
                        offset, strerror(errno));
        }

        /* read the corresponding pagemap entry */
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

        /* cleanup */
        (void)close(fd);

        /* check for swap */
        if (pentry & SWAP_MASK) {
               warnx("%#" PRIx64 " is swapped out", vaddr);
               return 0;
        }

        /* check the present bit */
        if ((pentry & PRESENT_MASK) == 0) {
               warnx("%#" PRIx64 " is not present in physical memory", vaddr);
               return 0;
        }

        /* extract PFN */
        pfn = pentry & PFN_MASK;
        (void)fprintf(stdout, "Virtual address: %#" PRIx64 "\n", vaddr);
        (void)fprintf(stdout, "Page number: %" PRIu64 "\n", page_num);
        (void)fprintf(stdout, "PFN: %" PRIu64 " (0x%" PRIx64 ")\n", pfn, pfn);

        uint64_t pa = pfn * (uint64_t)psize;
        (void)fprintf(stdout, "%s Physical Address: %" PRIu64 " (0x%" PRIx64 ")\n",
                     is_guest ? "Guest" : "Host", pa, pa);

        /* If this is a kernel address, attempt to translate using appropriate symbol table */
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

        /* query kpageflags if requested */
        if (use_kpageflags) {
               (void)fprintf(stdout, "\n");
               query_kpageflags(pfn, psize, is_guest);
        }

        return pfn;
}

/*
 * translate_gpa_to_hpa
 *
 * Translate GPA to HPA using QEMU PID
 *
 * @qemu_pid: QEMU process PID
 * @gpa: Guest Physical Address
 * @psize: page size
 * @use_kpageflags: whether to query kpageflags
 * @is_guest: whether running in guest (should be 1 since we're in guest)
 */
static void
translate_gpa_to_hpa(pid_t qemu_pid, uint64_t gpa, long psize, int use_kpageflags, int is_guest)
{
        uint64_t hva_base = find_qemu_ram_region(qemu_pid, NULL);
        if (hva_base == 0) {
                errx(3, "Failed to find QEMU RAM base");
        }

        /* Extract the page-aligned GPA and the offset within the page */
        uint64_t gpa_page_aligned = gpa & ~((uint64_t)(psize - 1));
        uint64_t offset_in_page = gpa & ((uint64_t)(psize - 1));

        /* Calculate the HVA by adding the page-aligned GPA to the base and then adding the offset */
        uint64_t hva = hva_base + gpa_page_aligned + offset_in_page;

        (void)fprintf(stdout, "GPA: %#" PRIx64 "\n", gpa);
        (void)fprintf(stdout, "GPA (page-aligned): %#" PRIx64 "\n", gpa_page_aligned);
        (void)fprintf(stdout, "Offset within page: %#" PRIx64 "\n", offset_in_page);
        (void)fprintf(stdout, "Assumed HVA base: %#" PRIx64 "\n", hva_base);
        (void)fprintf(stdout, "HVA: %#" PRIx64 "\n", hva);

        /* Now query pagemap for HVA in QEMU PID to get PFN and HPA */
        /* Note: querypmap will align the address internally, so we pass the full HVA */
        /* We pass is_guest=0 because we're dealing with host addresses now */
        uint64_t pfn = querypmap(qemu_pid, hva, psize, 0, 0);  /* Don't use kpageflags here yet */

        if (use_kpageflags && pfn != 0) {
                (void)fprintf(stdout, "\n");
                query_kpageflags(pfn, psize, 0);  /* is_guest=0 because this is host physical memory */
        }
}

/*
 * translate_hpa_to_gpa
 *
 * Translate HPA to GPA using QEMU PID by scanning pagemap
 *
 * @qemu_pid: QEMU process PID
 * @hpa: Host Physical Address
 * @psize: page size
 * @use_kpageflags: whether to query kpageflags
 * @is_guest: whether running in guest (should be 1 since we're in guest)
 */
/*
 * translate_hpa_to_gpa
 *
 * Translate HPA to GPA using QEMU PID by iterating through PFNs
 *
 * @qemu_pid: QEMU process PID
 * @hpa: Host Physical Address
 * @psize: page size
 * @use_kpageflags: whether to query kpageflags
 * @is_guest: whether running in guest (should be 1 since we're in guest)
 */
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

    // Iterate through each page in the QEMU RAM region
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

        // Check if this page is present and has our target PFN
        if ((pentry & PRESENT_MASK) && ((pentry & PFN_MASK) == target_pfn)) {
            uint64_t gpa = i * psize;  // GPA is simply the index * page_size
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
                query_kpageflags(target_pfn, psize, 0);  /* is_guest=0 because this is host physical memory */
            }
            break;
        }

        // Progress indicator for large scans
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

/*
 * getPAGEMAP
 *
 * read the pagemap of a particular process
 *
 * @argc:      number of command-line options
 * @argv:      command-line options
 * return      0: success
 *             1: illegal option, missing argument
 *             2: failed while trying to read the page size
 *             3: invalid pid or virt parameter
 *             4: failed while trying to open /proc/<pid>/pagemap
 *             5: failed while trying to seek in /proc/<pid>/pagemap
 *             6: failed while trying to read a pagemap entry
 *             7: failed while trying to access /proc/kpageflags
 */
int
main(int argc, char **argv)
{
        long    psize;          /* page size            */
        pid_t   pid     = -1;   /* pid                  */
        uint64_t        vaddr   = 0;    /* virtual address      */
        uint64_t        pfn_direct = 0; /* direct PFN query     */
        uint64_t        aligned_vaddr;  /* page-aligned address */
        int             use_kpageflags = 0;     /* use kpageflags flag */
        int             direct_pfn_mode = 0;    /* direct PFN mode */
        pid_t   qemu_pid = -1;  /* QEMU pid             */
        uint64_t        gpa     = 0;    /* guest physical address */
        int             translate_gpa_mode = 0; /* translate GPA mode   */
        uint64_t        hpa     = 0;    /* host physical address */
        int             translate_hpa_mode = 0; /* translate HPA mode   */
        int             is_guest = is_kvm_guest(); /* detect if guest */

        /* getopt stuff */
        int     opt;            /* option               */
        int    long_opt_indx    = 0;    /* long option index    */

        /* long options */
        struct option long_options[] = {
               {"pid",          1, NULL, 'p'},  /* -p / --pid           */
               {"virt",         1, NULL, 'a'},  /* -a / --virt          */
               {"pfn",          1, NULL, 'f'},  /* -f / --pfn           */
               {"kpageflags",   0, NULL, 'k'},  /* -k / --kpageflags    */
               {"qemu-pid",     1, NULL, 'q'},  /* -q / --qemu-pid      */
               {"gpa",          1, NULL, 'g'},  /* -g / --gpa           */
               {"hpa",          1, NULL, 'H'},  /* -H / --hpa           */
               {"help",         0, NULL, 'h'},  /* -h / --help          */
               {"version",      0, NULL, 'v'},  /* -v / --version       */
               {NULL,           0, NULL, 0}};   /* terminating item     */

        /* arguments parsing */
        while ((opt = getopt_long(argc, argv, ":hvkp:a:f:q:g:H:", long_options,
                                        &long_opt_indx)) != -1) {
               switch(opt) {
                case 'p': /* -p / --pid */
                        pid     = (pid_t)strtol(optarg, NULL, BASE10);
                        break;
                case 'a': /* -a / --virt */
                        vaddr   = (uint64_t)strtoull(optarg, NULL, BASE16);
                        break;
                case 'f': /* -f / --pfn */
                        pfn_direct = (uint64_t)strtoull(optarg, NULL, BASE16);
                        direct_pfn_mode = 1;
                        break;
                case 'q': /* -q / --qemu-pid */
                        qemu_pid = (pid_t)strtol(optarg, NULL, BASE10);
                        break;
                case 'g': /* -g / --gpa */
                        gpa     = (uint64_t)strtoull(optarg, NULL, BASE16);
                        translate_gpa_mode = 1;
                        break;
                case 'H': /* -H / --hpa */
                        hpa     = (uint64_t)strtoull(optarg, NULL, BASE16);
                        translate_hpa_mode = 1;
                        break;
                case 'k': /* -k / --kpageflags */
                        use_kpageflags = 1;
                        break;
                case 'h': /* help */
                        help();
                        goto done;
                        break;  /* not reached */
                case 'v': /* version info */
                        version();
                        goto done;
                        break;  /* not reached */
                case '?': /* illegal option */
                        errx(1, "illegal option -- %s",
                                        (optind == 0) ?
                                        argv[long_opt_indx] :
                                        argv[optind - 1]);
                        break;
                case ':': /* missing argument */
                        errx(1, "option requires an argument -- %s",
                                        (optind == 0) ?
                                        argv[long_opt_indx] :
                                        argv[optind - 1]);
                        break;
                default: /* not reached */
                        break; /* make the compiler happy */
               }
        }

        /* get the page size */
        if ((psize = sysconf(_SC_PAGESIZE)) == -1)
               errx(2, "failed while trying to read page size -- %s",
                        strerror(errno));

        /* translate GPA mode */
        if (translate_gpa_mode) {
               if (qemu_pid == -1) {
                       errx(3, "missing `qemu-pid' argument for GPA translation");
               }
               translate_gpa_to_hpa(qemu_pid, gpa, psize, use_kpageflags, is_guest);
               goto done;
        }

        /* translate HPA mode */
        if (translate_hpa_mode) {
               if (qemu_pid == -1) {
                       errx(3, "missing `qemu-pid' argument for HPA translation");
               }
               translate_hpa_to_gpa(qemu_pid, hpa, psize, use_kpageflags, is_guest);
               goto done;
        }

        /* direct PFN query mode */
        if (direct_pfn_mode) {
               query_kpageflags(pfn_direct, psize, is_guest);
               goto done;
        }

        /* validate arguments */
        if (pid == -1)
               /* pid is missing */
               errx(3, "missing `pid' argument");
        if (pid <= 0)
               /* invalid pid value */
               errx(3, "invalid `pid' argument -- %d", pid);

        /* align the virtual address to page boundary (round down) */
        aligned_vaddr = vaddr & ~((uint64_t)(psize - 1));

        /* check if the virtual address is page-aligned */
        if (vaddr != aligned_vaddr) {
               /* verbose */
        warnx("virtual address %#" PRIx64 " is not page-aligned; converting to %#" PRIx64,
               vaddr, aligned_vaddr);
               /* use the aligned address */
               vaddr = aligned_vaddr;
        }

        /* query pagemap */
        querypmap(pid, vaddr, psize, use_kpageflags, is_guest);

done:   /* done; return with success */
        return EXIT_SUCCESS;
}
