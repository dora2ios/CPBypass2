/* Copyright 2020 0x7ff
 *
 * Licensed under the Apache License, Version 2.0 (the "License");
 * you may not use this file except in compliance with the License.
 * You may obtain a copy of the License at
 *
 * http://www.apache.org/licenses/LICENSE-2.0
 *
 * Unless required by applicable law or agreed to in writing, software
 * distributed under the License is distributed on an "AS IS" BASIS,
 * WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
 * See the License for the specific language governing permissions and
 * limitations under the License.
 */

#include <CoreFoundation/CoreFoundation.h>
#include <compression.h>
#include <mach-o/fat.h>
#include <mach-o/loader.h>
#include <mach-o/nlist.h>
#include <mach/mach.h>
#include <sys/mman.h>
#include <sys/stat.h>

#define LZSS_F (18)
#define LZSS_N (4096)
#define LZSS_THRESHOLD (2)
#define IPC_ENTRY_SZ (0x18)
#define PMAP_MIN_OFF (0x10)
#define PMAP_MAX_OFF (0x18)
#define VM_MAP_PMAP_OFF (0x48)
#define KCOMP_HDR_PAD_SZ (0x16C)
//#define USER_CLIENT_TRAP_OFF (0x40)
static int user_client_trap_off;
#define IPC_SPACE_IS_TABLE_OFF (0x20)
#define IPC_ENTRY_IE_OBJECT_OFF (0x0)
#define PROC_P_LIST_LE_PREV_OFF (0x8)
#define IPC_PORT_IP_KOBJECT_OFF (0x68)
#define PROC_P_LIST_LH_FIRST_OFF (0x0)
#define IPC_SPACE_IS_TABLE_SZ_OFF (0x14)
#define kCFCoreFoundationVersionNumber_iOS_10_0_b5 (1348)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b2 (1656)
#define kCFCoreFoundationVersionNumber_iOS_11_0_b1 (1429.15)
#define kCFCoreFoundationVersionNumber_iOS_12_0_b1 (1535.13)
#define kCFCoreFoundationVersionNumber_iOS_13_0_b1 (1652.20)
#define kCFCoreFoundationVersionNumber_iOS_14_0_b1 (1740)
#define BOOT_PATH "/System/Library/Caches/com.apple.kernelcaches/kernelcache"

#define DER_INT (0x2U)
#define DER_SEQ (0x30U)
#define DER_IA5_STR (0x16U)
#define DER_OCTET_STR (0x4U)
#define KADDR_FMT "0x%" PRIX64
#define VM_KERN_MEMORY_CPU (9)
#define RD(a) extract32(a, 0, 5)
#define RN(a) extract32(a, 5, 5)
#define BCOPY_PHYS_DST_PHYS (1U)
#define BCOPY_PHYS_SRC_PHYS (2U)
#define KCOMP_HDR_MAGIC (0x636F6D70U)
#define IS_NOP(a) ((a) == 0xD503201FU)
#define IS_RET(a) ((a) == 0xD65F03C0U)
#define ADRP_ADDR(a) ((a) & ~0xFFFULL)
#define ADRP_IMM(a) (ADR_IMM(a) << 12U)
#define IO_OBJECT_NULL ((io_object_t)0)
#define MAX_VTAB_SZ (vm_kernel_page_size)
#define ADD_X_IMM(a) extract32(a, 10, 12)
#define KCOMP_HDR_TYPE_LZSS (0x6C7A7373U)
#define FAULT_MAGIC (0xAAAAAAAAAAAAAAAAULL)
#define MOV_W_ZHW_IMM(a) extract32(a, 5, 16)
#define BL_IMM(a) (sextract64(a, 0, 26) << 2U)
#define LDR_X_IMM(a) (sextract64(a, 5, 19) << 2U)
#define IS_BL(a) (((a) & 0xFC000000U) == 0x94000000U)
#define IS_ADR(a) (((a) & 0x9F000000U) == 0x10000000U)
#define IS_ADRP(a) (((a) & 0x9F000000U) == 0x90000000U)
#define IS_ADD_X(a) (((a) & 0xFFC00000U) == 0x91000000U)
#define IS_LDR_X(a) (((a) & 0xFF000000U) == 0x58000000U)
#define IS_MOV_X(a) (((a) & 0xFFE00000U) == 0xAA000000U)
#define LDR_W_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 2U)
#define LDR_X_UNSIGNED_IMM(a) (extract32(a, 10, 12) << 3U)
#define IS_MOV_W_ZHW(a) (((a) & 0xFFE00000U) == 0x52800000U)
#define IS_LDR_W_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xB9400000U)
#define IS_LDR_X_UNSIGNED_IMM(a) (((a) & 0xFFC00000U) == 0xF9400000U)
#define ADR_IMM(a) ((sextract64(a, 5, 19) << 2U) | extract32(a, 29, 2))

#ifndef SECT_CSTRING
#    define SECT_CSTRING "__cstring"
#endif

#ifndef SEG_TEXT_EXEC
#    define SEG_TEXT_EXEC "__TEXT_EXEC"
#endif

#ifndef MIN
#    define MIN(a, b) ((a) < (b) ? (a) : (b))
#endif

typedef uint64_t kaddr_t;
typedef mach_port_t io_object_t;
typedef uint32_t ipc_entry_num_t;
typedef io_object_t io_service_t, io_connect_t, io_registry_entry_t;
typedef char io_string_t[512];
typedef uint32_t IOOptionBits, ipc_entry_num_t;

typedef struct {
    struct section_64 s64;
    const char *data;
} sec_64_t;

typedef struct {
    struct symtab_command cmd_symtab;
    sec_64_t sec_text, sec_cstring;
    kaddr_t base, kslide;
    const char *kernel;
    size_t kernel_sz;
    char *data;
} pfinder_t;

uint64_t slide;

typedef struct {
    kaddr_t obj, func, delta;
} io_external_trap_t;

kern_return_t
IOServiceClose(io_connect_t);

kern_return_t
IOObjectRelease(io_object_t);

CFMutableDictionaryRef
IOServiceMatching(const char *);

io_service_t
IOServiceGetMatchingService(mach_port_t, CFDictionaryRef);

io_registry_entry_t
IORegistryEntryFromPath(mach_port_t, const io_string_t);

CFTypeRef
IORegistryEntryCreateCFProperty(io_registry_entry_t, CFStringRef, CFAllocatorRef, IOOptionBits);

kern_return_t
mach_vm_deallocate(vm_map_t, mach_vm_address_t, mach_vm_size_t);

kern_return_t
IOServiceOpen(io_service_t, task_port_t, uint32_t, io_connect_t *);

kern_return_t
mach_vm_allocate(vm_map_t, mach_vm_address_t *, mach_vm_size_t, int);

kern_return_t
mach_vm_copy(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t);

kern_return_t
mach_vm_write(vm_map_t, mach_vm_address_t, vm_offset_t, mach_msg_type_number_t);

kern_return_t
IOConnectTrap6(io_connect_t, uint32_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t, uintptr_t);

kern_return_t
mach_vm_read_overwrite(vm_map_t, mach_vm_address_t, mach_vm_size_t, mach_vm_address_t, mach_vm_size_t *);

kern_return_t
mach_vm_machine_attribute(vm_map_t, mach_vm_address_t, mach_vm_size_t, vm_machine_attribute_t, vm_machine_attribute_val_t *);

kern_return_t
mach_vm_region(vm_map_t, mach_vm_address_t *, mach_vm_size_t *, vm_region_flavor_t, vm_region_info_t, mach_msg_type_number_t *, mach_port_t *);

kern_return_t mach_vm_protect(vm_map_t target_task, mach_vm_address_t address, mach_vm_size_t size, boolean_t set_maximum, vm_prot_t new_protection);

extern const mach_port_t kIOMasterPortDefault;

static task_t tfp0 = MACH_PORT_NULL;
static io_connect_t g_conn = IO_OBJECT_NULL;
static size_t task_map_off, proc_task_off, proc_p_pid_off, task_itk_space_off, cpu_data_rtclock_datap_off, vtab_get_ext_trap_for_idx_off;
static kaddr_t kernproc, csblob_get_cdhash, pmap_find_phys, bcopy_phys, our_task, orig_vtab, fake_vtab, user_client, kernel_pmap, kernel_pmap_min, kernel_pmap_max;

static uint32_t
extract32(uint32_t val, unsigned start, unsigned len) {
    return (val >> start) & (~0U >> (32U - len));
}

static uint64_t
sextract64(uint64_t val, unsigned start, unsigned len) {
    return (uint64_t)((int64_t)(val << (64U - len - start)) >> (64U - len));
}

static size_t
decompress_lzss(const uint8_t *src, size_t src_len, uint8_t *dst, size_t dst_len) {
    const uint8_t *src_end = src + src_len, *dst_start = dst, *dst_end = dst + dst_len;
    uint16_t i, r = LZSS_N - LZSS_F, flags = 0;
    uint8_t text_buf[LZSS_N + LZSS_F - 1], j;
    
    memset(text_buf, ' ', r);
    while(src != src_end && dst != dst_end) {
        if(((flags >>= 1U) & 0x100U) == 0) {
            flags = *src++ | 0xFF00U;
            if(src == src_end) {
                break;
            }
        }
        if((flags & 1U) != 0) {
            text_buf[r++] = *dst++ = *src++;
            r &= LZSS_N - 1U;
        } else {
            i = *src++;
            if(src == src_end) {
                break;
            }
            j = *src++;
            i |= (j & 0xF0U) << 4U;
            j = (j & 0xFU) + LZSS_THRESHOLD;
            do {
                *dst++ = text_buf[r++] = text_buf[i++ & (LZSS_N - 1U)];
                r &= LZSS_N - 1U;
            } while(j-- != 0 && dst != dst_end);
        }
    }
    return (size_t)(dst - dst_start);
}

static const uint8_t *
der_decode(uint8_t tag, const uint8_t *der, const uint8_t *der_end, size_t *out_len) {
    size_t der_len;
    
    if(der_end - der > 2 && tag == *der++) {
        if(((der_len = *der++) & 0x80U) != 0) {
            *out_len = 0;
            if((der_len &= 0x7FU) <= sizeof(*out_len) && (size_t)(der_end - der) >= der_len) {
                while(der_len-- != 0) {
                    *out_len = (*out_len << 8U) | *der++;
                }
            }
        } else {
            *out_len = der_len;
        }
        if(*out_len != 0 && (size_t)(der_end - der) >= *out_len) {
            return der;
        }
    }
    return NULL;
}

static const uint8_t *
der_decode_seq(const uint8_t *der, const uint8_t *der_end, const uint8_t **seq_end) {
    size_t der_len;
    
    if((der = der_decode(DER_SEQ, der, der_end, &der_len)) != NULL) {
        *seq_end = der + der_len;
    }
    return der;
}

static const uint8_t *
der_decode_uint64(const uint8_t *der, const uint8_t *der_end, uint64_t *r) {
    size_t der_len;
    
    if((der = der_decode(DER_INT, der, der_end, &der_len)) != NULL && (*der & 0x80U) == 0 && (der_len <= sizeof(*r) || (--der_len == sizeof(*r) && *der++ == 0))) {
        *r = 0;
        while(der_len-- != 0) {
            *r = (*r << 8U) | *der++;
        }
        return der;
    }
    return NULL;
}

static void *
kdecompress(const void *src, size_t src_len, size_t *dst_len) {
    const uint8_t *der, *octet, *der_end, *src_end = (const uint8_t *)src + src_len;
    struct {
        uint32_t magic, type, adler32, uncomp_sz, comp_sz;
        uint8_t pad[KCOMP_HDR_PAD_SZ];
    } kcomp_hdr;
    size_t der_len;
    uint64_t r;
    void *dst;
    
    if((der = der_decode_seq(src, src_end, &der_end)) != NULL && (der = der_decode(DER_IA5_STR, der, der_end, &der_len)) != NULL && der_len == 4 && (memcmp(der, "IMG4", der_len) != 0 || ((der = der_decode_seq(der + der_len, src_end, &der_end)) != NULL && (der = der_decode(DER_IA5_STR, der, der_end, &der_len)) != NULL && der_len == 4)) && memcmp(der, "IM4P", der_len) == 0 && (der = der_decode(DER_IA5_STR, der + der_len, der_end, &der_len)) != NULL && der_len == 4 && memcmp(der, "krnl", der_len) == 0 && (der = der_decode(DER_IA5_STR, der + der_len, der_end, &der_len)) != NULL && (der = der_decode(DER_OCTET_STR, der + der_len, der_end, &der_len)) != NULL && der_len > sizeof(kcomp_hdr)) {
        octet = der;
        memcpy(&kcomp_hdr, octet, sizeof(kcomp_hdr));
        if(kcomp_hdr.magic == __builtin_bswap32(KCOMP_HDR_MAGIC)) {
            if(kcomp_hdr.type == __builtin_bswap32(KCOMP_HDR_TYPE_LZSS) && (kcomp_hdr.comp_sz = __builtin_bswap32(kcomp_hdr.comp_sz)) <= der_len - sizeof(kcomp_hdr) && (kcomp_hdr.uncomp_sz = __builtin_bswap32(kcomp_hdr.uncomp_sz)) != 0 && (dst = malloc(kcomp_hdr.uncomp_sz)) != NULL) {
                if(decompress_lzss(octet + sizeof(kcomp_hdr), kcomp_hdr.comp_sz, dst, kcomp_hdr.uncomp_sz) == kcomp_hdr.uncomp_sz) {
                    *dst_len = kcomp_hdr.uncomp_sz;
                    return dst;
                }
                free(dst);
            }
        } else if((der = der_decode_seq(der + der_len, src_end, &der_end)) != NULL && (der = der_decode_uint64(der, der_end, &r)) != NULL && r == 1 && der_decode_uint64(der, der_end, &r) != NULL && r != 0 && (dst = malloc(r)) != NULL) {
            if(compression_decode_buffer(dst, r, octet, der_len, NULL, COMPRESSION_LZFSE) == r) {
                *dst_len = r;
                return dst;
            }
            free(dst);
        }
    }
    return NULL;
}

static kern_return_t
init_tfp0(void) {
    kern_return_t ret = task_for_pid(mach_task_self(), 0, &tfp0);
    mach_port_t host;
    pid_t pid;
    
    if(ret != KERN_SUCCESS) {
        host = mach_host_self();
        if(MACH_PORT_VALID(host)) {
            printf("host: 0x%" PRIX32 "\n", host);
            ret = host_get_special_port(host, HOST_LOCAL_NODE, 4, &tfp0);
            mach_port_deallocate(mach_task_self(), host);
        }
    }
    if(ret == KERN_SUCCESS && MACH_PORT_VALID(tfp0)) {
        if(pid_for_task(tfp0, &pid) == KERN_SUCCESS && pid == 0) {
            return ret;
        }
        mach_port_deallocate(mach_task_self(), tfp0);
    }
    return KERN_FAILURE;
}

static kern_return_t
kread_buf(kaddr_t addr, void *buf, mach_vm_size_t sz) {
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_vm_size_t read_sz, out_sz = 0;
    
    while(sz != 0) {
        read_sz = MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if(mach_vm_read_overwrite(tfp0, addr, read_sz, p, &out_sz) != KERN_SUCCESS || out_sz != read_sz) {
            return KERN_FAILURE;
        }
        p += read_sz;
        sz -= read_sz;
        addr += read_sz;
    }
    return KERN_SUCCESS;
}

static kern_return_t
kread_addr(kaddr_t addr, kaddr_t *val) {
    return kread_buf(addr, val, sizeof(*val));
}

static kern_return_t
kwrite_buf(kaddr_t addr, const void *buf, mach_msg_type_number_t sz) {
    vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
    mach_vm_address_t p = (mach_vm_address_t)buf;
    mach_msg_type_number_t write_sz;
    
    while(sz != 0) {
        write_sz = (mach_msg_type_number_t)MIN(sz, vm_kernel_page_size - (addr & vm_kernel_page_mask));
        if(mach_vm_write(tfp0, addr, p, write_sz) != KERN_SUCCESS || mach_vm_machine_attribute(tfp0, addr, write_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
            return KERN_FAILURE;
        }
        p += write_sz;
        sz -= write_sz;
        addr += write_sz;
    }
    return KERN_SUCCESS;
}

void _kwrite_buf(uint64_t addr, const void *buf, unsigned int sz){
    kwrite_buf(addr, buf, sz);
}

static kern_return_t
kwrite_addr(kaddr_t addr, kaddr_t val) {
    return kwrite_buf(addr, &val, sizeof(val));
}


uint32_t kread32(uint64_t addr){
    uint32_t val = 0;
    //kread_addr(addr, &val);
    kread_buf(addr, &val, 4);
    return val;
}

uint64_t kread64(uint64_t addr){
    uint64_t val = 0;
    kread_addr(addr, &val);
    return val;
}

void kwrite32(uint64_t addr, uint32_t val){
    kwrite_addr(addr, val);
}

void kwrite64(uint64_t addr, uint64_t val){
    kwrite_addr(addr, val);
}


static kern_return_t
kalloc(mach_vm_size_t sz, kaddr_t *addr) {
    return mach_vm_allocate(tfp0, addr, sz, VM_FLAGS_ANYWHERE);
}

static kern_return_t
kfree(kaddr_t addr, mach_vm_size_t sz) {
    return mach_vm_deallocate(tfp0, addr, sz);
}

static kern_return_t
find_section(const char *p, struct segment_command_64 sg64, const char *sect_name, struct section_64 *sp) {
    for(; sg64.nsects-- != 0; p += sizeof(*sp)) {
        memcpy(sp, p, sizeof(*sp));
        if((sp->flags & SECTION_TYPE) != S_ZEROFILL) {
            if(sp->offset < sg64.fileoff || sp->size > sg64.filesize || sp->offset - sg64.fileoff > sg64.filesize - sp->size) {
                break;
            }
            if(sp->size != 0 && strncmp(sp->segname, sg64.segname, sizeof(sp->segname)) == 0 && strncmp(sp->sectname, sect_name, sizeof(sp->sectname)) == 0) {
                return KERN_SUCCESS;
            }
        }
    }
    return KERN_FAILURE;
}

static void
sec_reset(sec_64_t *sec) {
    memset(&sec->s64, '\0', sizeof(sec->s64));
    sec->data = NULL;
}

static kern_return_t
sec_read_buf(sec_64_t sec, kaddr_t addr, void *buf, size_t sz) {
    size_t off;
    
    if(addr < sec.s64.addr || sz > sec.s64.size || (off = addr - sec.s64.addr) > sec.s64.size - sz) {
        return KERN_FAILURE;
    }
    memcpy(buf, sec.data + off, sz);
    return KERN_SUCCESS;
}

static void
pfinder_reset(pfinder_t *pfinder) {
    pfinder->base = 0;
    pfinder->kslide = 0;
    pfinder->data = NULL;
    pfinder->kernel = NULL;
    pfinder->kernel_sz = 0;
    sec_reset(&pfinder->sec_text);
    sec_reset(&pfinder->sec_cstring);
    memset(&pfinder->cmd_symtab, '\0', sizeof(pfinder->cmd_symtab));
}

static void
pfinder_term(pfinder_t *pfinder) {
    free(pfinder->data);
    pfinder_reset(pfinder);
}

#define PREBOOT_PATH "/private/preboot/"
#define kIODeviceTreePlane "IODeviceTree"

static char *
get_boot_path(void) {
    size_t hash_len, path_len = sizeof(BOOT_PATH);
    io_registry_entry_t chosen;
    struct stat stat_buf;
    const uint8_t *hash;
    CFDataRef hash_cf;
    char *path = NULL;
    
    if(stat(PREBOOT_PATH, &stat_buf) != -1 && S_ISDIR(stat_buf.st_mode)) {
        if((chosen = IORegistryEntryFromPath(kIOMasterPortDefault, kIODeviceTreePlane ":/chosen")) != IO_OBJECT_NULL) {
            if((hash_cf = IORegistryEntryCreateCFProperty(chosen, CFSTR("boot-manifest-hash"), kCFAllocatorDefault, kNilOptions)) != NULL) {
                if(CFGetTypeID(hash_cf) == CFDataGetTypeID() && (hash_len = (size_t)CFDataGetLength(hash_cf) << 1U) != 0) {
                    path_len += strlen(PREBOOT_PATH) + hash_len;
                    if((path = malloc(path_len)) != NULL) {
                        memcpy(path, PREBOOT_PATH, strlen(PREBOOT_PATH));
                        for(hash = CFDataGetBytePtr(hash_cf); hash_len-- != 0; ) {
                            path[strlen(PREBOOT_PATH) + hash_len] = "0123456789ABCDEF"[(hash[hash_len >> 1U] >> ((~hash_len & 1U) << 2U)) & 0xFU];
                        }
                    }
                }
                CFRelease(hash_cf);
            }
            IOObjectRelease(chosen);
        }
    }
    if(path == NULL) {
        path_len = sizeof(BOOT_PATH);
        path = malloc(path_len);
    }
    if(path != NULL) {
        memcpy(path + (path_len - sizeof(BOOT_PATH)), BOOT_PATH, sizeof(BOOT_PATH));
    }
    return path;
}


static kern_return_t
pfinder_init_file(pfinder_t *pfinder, const char *filename) {
    struct symtab_command cmd_symtab;
    kern_return_t ret = KERN_FAILURE;
    struct segment_command_64 sg64;
    struct mach_header_64 mh64;
    struct load_command lc;
    struct section_64 s64;
    struct fat_header fh;
    struct stat stat_buf;
    struct fat_arch fa;
    const char *p, *e;
    size_t len;
    void *m;
    int fd;
    
    pfinder_reset(pfinder);
    if((fd = open(filename, O_RDONLY | O_CLOEXEC)) != -1) {
        if(fstat(fd, &stat_buf) != -1 && stat_buf.st_size > 0) {
            len = (size_t)stat_buf.st_size;
            if((m = mmap(NULL, len, PROT_READ, MAP_PRIVATE, fd, 0)) != MAP_FAILED) {
                if((pfinder->data = kdecompress(m, len, &pfinder->kernel_sz)) != NULL && pfinder->kernel_sz > sizeof(fh) + sizeof(mh64)) {
                    pfinder->kernel = pfinder->data;
                    memcpy(&fh, pfinder->kernel, sizeof(fh));
                    if(fh.magic == __builtin_bswap32(FAT_MAGIC) && (fh.nfat_arch = __builtin_bswap32(fh.nfat_arch)) < (pfinder->kernel_sz - sizeof(fh)) / sizeof(fa)) {
                        for(p = pfinder->kernel + sizeof(fh); fh.nfat_arch-- != 0; p += sizeof(fa)) {
                            memcpy(&fa, p, sizeof(fa));
                            if(fa.cputype == (cpu_type_t)__builtin_bswap32(CPU_TYPE_ARM64) && (fa.offset = __builtin_bswap32(fa.offset)) < pfinder->kernel_sz && (fa.size = __builtin_bswap32(fa.size)) <= pfinder->kernel_sz - fa.offset && fa.size > sizeof(mh64)) {
                                pfinder->kernel_sz = fa.size;
                                pfinder->kernel += fa.offset;
                                break;
                            }
                        }
                    }
                    memcpy(&mh64, pfinder->kernel, sizeof(mh64));
                    if(mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE && mh64.sizeofcmds < pfinder->kernel_sz - sizeof(mh64)) {
                        for(p = pfinder->kernel + sizeof(mh64), e = p + mh64.sizeofcmds; mh64.ncmds-- != 0 && (size_t)(e - p) >= sizeof(lc); p += lc.cmdsize) {
                            memcpy(&lc, p, sizeof(lc));
                            if(lc.cmdsize < sizeof(lc) || (size_t)(e - p) < lc.cmdsize) {
                                break;
                            }
                            if(lc.cmd == LC_SEGMENT_64) {
                                if(lc.cmdsize < sizeof(sg64)) {
                                    break;
                                }
                                memcpy(&sg64, p, sizeof(sg64));
                                if(sg64.vmsize == 0) {
                                    continue;
                                }
                                if(sg64.nsects != (lc.cmdsize - sizeof(sg64)) / sizeof(s64) || sg64.fileoff > pfinder->kernel_sz || sg64.filesize > pfinder->kernel_sz - sg64.fileoff) {
                                    break;
                                }
                                if(sg64.fileoff == 0 && sg64.filesize != 0) {
                                    if(pfinder->base != 0) {
                                        break;
                                    }
                                    pfinder->base = sg64.vmaddr;
                                    printf("base: " KADDR_FMT "\n", sg64.vmaddr);
                                }
                                if(strncmp(sg64.segname, SEG_TEXT_EXEC, sizeof(sg64.segname)) == 0) {
                                    if(find_section(p + sizeof(sg64), sg64, SECT_TEXT, &s64) != KERN_SUCCESS) {
                                        break;
                                    }
                                    pfinder->sec_text.s64 = s64;
                                    pfinder->sec_text.data = pfinder->kernel + s64.offset;
                                    printf("sec_text_addr: " KADDR_FMT ", sec_text_off: 0x%" PRIX32 ", sec_text_sz: 0x%" PRIX64 "\n", s64.addr, s64.offset, s64.size);
                                } else if(strncmp(sg64.segname, SEG_TEXT, sizeof(sg64.segname)) == 0) {
                                    if(find_section(p + sizeof(sg64), sg64, SECT_CSTRING, &s64) != KERN_SUCCESS || pfinder->kernel[s64.offset + s64.size - 1] != '\0') {
                                        break;
                                    }
                                    pfinder->sec_cstring.s64 = s64;
                                    pfinder->sec_cstring.data = pfinder->kernel + s64.offset;
                                    printf("sec_cstring_addr: " KADDR_FMT ", sec_cstring_off: 0x%" PRIX32 ", sec_cstring_sz: 0x%" PRIX64 "\n", s64.addr, s64.offset, s64.size);
                                }
                            } else if(lc.cmd == LC_SYMTAB) {
                                if(lc.cmdsize != sizeof(cmd_symtab)) {
                                    break;
                                }
                                memcpy(&cmd_symtab, p, sizeof(cmd_symtab));
                                printf("cmd_symtab_symoff: 0x%" PRIX32 ", cmd_symtab_nsyms: 0x%" PRIX32 ", cmd_symtab_stroff: 0x%" PRIX32 "\n", cmd_symtab.symoff, cmd_symtab.nsyms, cmd_symtab.stroff);
                                if(cmd_symtab.nsyms != 0 && (cmd_symtab.symoff > pfinder->kernel_sz || cmd_symtab.nsyms > (pfinder->kernel_sz - cmd_symtab.symoff) / sizeof(struct nlist_64) || cmd_symtab.stroff > pfinder->kernel_sz || cmd_symtab.strsize > pfinder->kernel_sz - cmd_symtab.stroff || cmd_symtab.strsize == 0 || pfinder->kernel[cmd_symtab.stroff + cmd_symtab.strsize - 1] != '\0')) {
                                    break;
                                }
                                pfinder->cmd_symtab = cmd_symtab;
                            }
                            if(pfinder->base != 0 && pfinder->sec_text.s64.size != 0 && pfinder->sec_cstring.s64.size != 0 && pfinder->cmd_symtab.cmdsize != 0) {
                                ret = KERN_SUCCESS;
                                break;
                            }
                        }
                    }
                }
                munmap(m, len);
            }
        }
        close(fd);
    }
    if(ret != KERN_SUCCESS) {
        pfinder_term(pfinder);
    }
    return ret;
}

static kaddr_t
pfinder_xref_rd(pfinder_t pfinder, uint32_t rd, kaddr_t start, kaddr_t to) {
    kaddr_t x[32] = { 0 };
    uint32_t insn;
    
    for(; sec_read_buf(pfinder.sec_text, start, &insn, sizeof(insn)) == KERN_SUCCESS; start += sizeof(insn)) {
        if(IS_LDR_X(insn)) {
            x[RD(insn)] = start + LDR_X_IMM(insn);
        } else if(IS_ADR(insn)) {
            x[RD(insn)] = start + ADR_IMM(insn);
        } else if(IS_ADD_X(insn)) {
            x[RD(insn)] = x[RN(insn)] + ADD_X_IMM(insn);
        } else if(IS_LDR_W_UNSIGNED_IMM(insn)) {
            x[RD(insn)] = x[RN(insn)] + LDR_W_UNSIGNED_IMM(insn);
        } else if(IS_LDR_X_UNSIGNED_IMM(insn)) {
            x[RD(insn)] = x[RN(insn)] + LDR_X_UNSIGNED_IMM(insn);
        } else {
            if(IS_ADRP(insn)) {
                x[RD(insn)] = ADRP_ADDR(start) + ADRP_IMM(insn);
            }
            continue;
        }
        if(RD(insn) == rd) {
            if(to == 0) {
                if(x[rd] < pfinder.base) {
                    break;
                }
                return x[rd];
            }
            if(x[rd] == to) {
                return start;
            }
        }
    }
    return 0;
}

static kaddr_t
pfinder_xref_str(pfinder_t pfinder, const char *str, uint32_t rd) {
    const char *p, *e;
    size_t len;
    
    for(p = pfinder.sec_cstring.data, e = p + pfinder.sec_cstring.s64.size; p != e; p += len) {
        len = strlen(p) + 1;
        if(strncmp(str, p, len) == 0) {
            return pfinder_xref_rd(pfinder, rd, pfinder.sec_text.s64.addr, pfinder.sec_cstring.s64.addr + (kaddr_t)(p - pfinder.sec_cstring.data));
        }
    }
    return 0;
}

static kaddr_t
pfinder_sym(pfinder_t pfinder, const char *sym) {
    const char *p, *strtab = pfinder.kernel + pfinder.cmd_symtab.stroff;
    struct nlist_64 nl64;
    
    for(p = pfinder.kernel + pfinder.cmd_symtab.symoff; pfinder.cmd_symtab.nsyms-- != 0; p += sizeof(nl64)) {
        memcpy(&nl64, p, sizeof(nl64));
        if(nl64.n_un.n_strx != 0 && nl64.n_un.n_strx < pfinder.cmd_symtab.strsize && (nl64.n_type & (N_STAB | N_TYPE)) == N_SECT && nl64.n_value >= pfinder.base && strcmp(strtab + nl64.n_un.n_strx, sym) == 0) {
            return nl64.n_value + pfinder.kslide;
        }
    }
    return 0;
}

static kaddr_t
pfinder_rtclock_data(pfinder_t pfinder) {
    kaddr_t ref = pfinder_sym(pfinder, "_RTClockData");
    uint32_t insns[3];
    
    if(ref != 0) {
        return ref;
    }
    for(ref = pfinder_xref_str(pfinder, "assert_wait_timeout_with_leeway", 8); sec_read_buf(pfinder.sec_text, ref, insns, sizeof(insns)) == KERN_SUCCESS; ref -= sizeof(*insns)) {
        if(IS_ADRP(insns[0]) && IS_NOP(insns[1]) && IS_LDR_W_UNSIGNED_IMM(insns[2])) {
            return pfinder_xref_rd(pfinder, RD(insns[2]), ref, 0);
        }
    }
    return 0;
}

static kaddr_t
pfinder_kernproc(pfinder_t pfinder) {
    kaddr_t ref = pfinder_sym(pfinder, "_kernproc");
    uint32_t insns[2];
    
    if(ref != 0) {
        return ref;
    }
    for(ref = pfinder_xref_str(pfinder, "\"Should never have an EVFILT_READ except for reg or fifo.\"", 0); sec_read_buf(pfinder.sec_text, ref, insns, sizeof(insns)) == KERN_SUCCESS; ref -= sizeof(*insns)) {
        if(IS_ADRP(insns[0]) && IS_LDR_X_UNSIGNED_IMM(insns[1]) && RD(insns[1]) == 3) {
            return pfinder_xref_rd(pfinder, RD(insns[1]), ref, 0);
        }
    }
    return 0;
}

static kaddr_t
pfinder_csblob_get_cdhash(pfinder_t pfinder) {
    kaddr_t ref = pfinder_sym(pfinder, "_csblob_get_cdhash");
    uint32_t insns[2];
    
    if(ref != 0) {
        return ref;
    }
    for(ref = pfinder.sec_text.s64.addr; sec_read_buf(pfinder.sec_text, ref, insns, sizeof(insns)) == KERN_SUCCESS; ref += sizeof(*insns)) {
        if(IS_ADD_X(insns[0]) && RD(insns[0]) == 0 && RN(insns[0]) == 0 && ADD_X_IMM(insns[0]) == user_client_trap_off && IS_RET(insns[1])) {
            return ref;
        }
    }
    return 0;
}

static kaddr_t
pfinder_pmap_find_phys(pfinder_t pfinder) {
    kaddr_t ref = pfinder_sym(pfinder, "_pmap_find_phys");
    uint32_t insns[2];
    
    if(ref != 0) {
        return ref;
    }
    for(ref = pfinder_xref_str(pfinder, "Kext %s - page %p is not backed by physical memory.", 2); sec_read_buf(pfinder.sec_text, ref, insns, sizeof(insns)) == KERN_SUCCESS; ref -= sizeof(*insns)) {
        if(IS_MOV_X(insns[0]) && RD(insns[0]) == 1 && IS_BL(insns[1])) {
            return ref + sizeof(*insns) + BL_IMM(insns[1]);
        }
    }
    return 0;
}

static kaddr_t
pfinder_bcopy_phys(pfinder_t pfinder) {
    kaddr_t ref = pfinder_sym(pfinder, "_bcopy_phys");
    uint32_t insns[3];
    size_t i;
    
    if(ref != 0) {
        return ref;
    }
    for(ref = pfinder_xref_str(pfinder, "\"mdevstrategy: sink address %016llX not mapped\\n\"", 0); sec_read_buf(pfinder.sec_text, ref, insns, sizeof(insns)) == KERN_SUCCESS; ref -= sizeof(*insns)) {
        if(IS_MOV_X(insns[0]) && RD(insns[0]) == 2) {
            i = IS_MOV_W_ZHW(insns[1]) && RD(insns[1]) == 3 && MOV_W_ZHW_IMM(insns[1]) == (BCOPY_PHYS_SRC_PHYS | BCOPY_PHYS_DST_PHYS) ? 2 : 1;
            if(IS_BL(insns[i])) {
                return ref + i * sizeof(*insns) + BL_IMM(insns[i]);
            }
        }
    }
    return 0;
}

static kaddr_t
pfinder_init_kbase(pfinder_t *pfinder) {
    mach_msg_type_number_t cnt = TASK_DYLD_INFO_COUNT;
    kaddr_t addr, rtclock_data, rtclock_data_slid;
    vm_region_extended_info_data_t extended_info;
    task_dyld_info_data_t dyld_info;
    struct mach_header_64 mh64;
    mach_port_t object_name;
    mach_vm_size_t sz;
    
    if(task_info(tfp0, TASK_DYLD_INFO, (task_info_t)&dyld_info, &cnt) == KERN_SUCCESS) {
        pfinder->kslide = dyld_info.all_image_info_size;
    }
    if(pfinder->kslide == 0 && (rtclock_data = pfinder_rtclock_data(*pfinder)) != 0) {
        printf("rtclock_data: " KADDR_FMT "\n", rtclock_data);
        cnt = VM_REGION_EXTENDED_INFO_COUNT;
        for(addr = 0; mach_vm_region(tfp0, &addr, &sz, VM_REGION_EXTENDED_INFO, (vm_region_info_t)&extended_info, &cnt, &object_name) == KERN_SUCCESS; addr += sz) {
            mach_port_deallocate(mach_task_self(), object_name);
            if(extended_info.protection == VM_PROT_DEFAULT && extended_info.user_tag == VM_KERN_MEMORY_CPU) {
                if(kread_addr(addr + cpu_data_rtclock_datap_off, &rtclock_data_slid) == KERN_SUCCESS && rtclock_data_slid > rtclock_data) {
                    pfinder->kslide = rtclock_data_slid - rtclock_data;
                }
                break;
            }
        }
    }
    if(pfinder->base + pfinder->kslide > pfinder->base && kread_buf(pfinder->base + pfinder->kslide, &mh64, sizeof(mh64)) == KERN_SUCCESS && mh64.magic == MH_MAGIC_64 && mh64.cputype == CPU_TYPE_ARM64 && mh64.filetype == MH_EXECUTE) {
        pfinder->sec_text.s64.addr += pfinder->kslide;
        pfinder->sec_cstring.s64.addr += pfinder->kslide;
        printf("kbase: " KADDR_FMT ", kslide: " KADDR_FMT "\n", pfinder->base + pfinder->kslide, pfinder->kslide);
        slide = pfinder->kslide;
        return KERN_SUCCESS;
    }
    return KERN_FAILURE;
}

static kern_return_t
pfinder_init_offsets(void) {
    kern_return_t ret = KERN_FAILURE;
    pfinder_t pfinder;
    user_client_trap_off = 0x40;
    task_map_off = 0x20;
    proc_task_off = 0x18;
    proc_p_pid_off = 0x10;
    task_itk_space_off = 0x290;
    cpu_data_rtclock_datap_off = 0x1D8;
    vtab_get_ext_trap_for_idx_off = 0x5B8;
    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_10_0_b5) {
        task_itk_space_off = 0x300;
        if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_11_0_b1) {
            task_itk_space_off = 0x308;
            cpu_data_rtclock_datap_off = 0x1A8;
            if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_12_0_b1) {
                proc_task_off = 0x10;
                proc_p_pid_off = 0x60;
                task_itk_space_off = 0x300;
#ifdef __arm64e__
                cpu_data_rtclock_datap_off = 0x190;
#else
                cpu_data_rtclock_datap_off = 0x198;
#endif
                if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b1) {
                    task_map_off = 0x28;
                    task_itk_space_off = 0x320;
                    vtab_get_ext_trap_for_idx_off = 0x5C0;
                    if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_13_0_b2) {
                        proc_p_pid_off = 0x68;
                        if(kCFCoreFoundationVersionNumber >= kCFCoreFoundationVersionNumber_iOS_14_0_b1) {
                            task_itk_space_off = 0x330;
                            user_client_trap_off = 0x48;
                        }
                    }
                }
            }
        }
    }
    if(pfinder_init_file(&pfinder, get_boot_path()) == KERN_SUCCESS) {
        if(pfinder_init_kbase(&pfinder) == KERN_SUCCESS && (kernproc = pfinder_kernproc(pfinder)) != 0) {
            printf("kernproc: " KADDR_FMT "\n", kernproc);
            if((csblob_get_cdhash = pfinder_csblob_get_cdhash(pfinder)) != 0) {
                printf("csblob_get_cdhash: " KADDR_FMT "\n", csblob_get_cdhash);
                if((pmap_find_phys = pfinder_pmap_find_phys(pfinder)) != 0) {
                    printf("pmap_find_phys: " KADDR_FMT "\n", pmap_find_phys);
                    if((bcopy_phys = pfinder_bcopy_phys(pfinder)) != 0) {
                        printf("bcopy_phys: " KADDR_FMT "\n", bcopy_phys);
                        ret = KERN_SUCCESS;
                    }
                }
            }
        }
        pfinder_term(&pfinder);
    }
    return ret;
}

static kern_return_t
find_task(pid_t pid, kaddr_t *task) {
    pid_t cur_pid;
    kaddr_t proc;
    
    if(kread_addr(kernproc + PROC_P_LIST_LH_FIRST_OFF, &proc) == KERN_SUCCESS) {
        while(proc != 0 && kread_buf(proc + proc_p_pid_off, &cur_pid, sizeof(cur_pid)) == KERN_SUCCESS) {
            if(cur_pid == pid) {
                return kread_addr(proc + proc_task_off, task);
            }
            if(pid == 0 || kread_addr(proc + PROC_P_LIST_LE_PREV_OFF, &proc) != KERN_SUCCESS) {
                break;
            }
        }
    }
    return KERN_FAILURE;
}

static kern_return_t
lookup_ipc_port(mach_port_name_t port_name, kaddr_t *ipc_port) {
    ipc_entry_num_t port_idx, is_table_sz;
    kaddr_t itk_space, is_table;
    
    if(MACH_PORT_VALID(port_name) && kread_addr(our_task + task_itk_space_off, &itk_space) == KERN_SUCCESS) {
        printf("itk_space: " KADDR_FMT "\n", itk_space);
        if(kread_buf(itk_space + IPC_SPACE_IS_TABLE_SZ_OFF, &is_table_sz, sizeof(is_table_sz)) == KERN_SUCCESS) {
            printf("is_table_sz: 0x%" PRIX32 "\n", is_table_sz);
            if((port_idx = MACH_PORT_INDEX(port_name)) < is_table_sz && kread_addr(itk_space + IPC_SPACE_IS_TABLE_OFF, &is_table) == KERN_SUCCESS) {
                printf("is_table: " KADDR_FMT "\n", is_table);
                return kread_addr(is_table + port_idx * IPC_ENTRY_SZ + IPC_ENTRY_IE_OBJECT_OFF, ipc_port);
            }
        }
    }
    return KERN_FAILURE;
}

static kern_return_t
lookup_io_object(io_object_t object, kaddr_t *ip_kobject) {
    kaddr_t ipc_port;
    
    if(lookup_ipc_port(object, &ipc_port) == KERN_SUCCESS) {
        printf("ipc_port: " KADDR_FMT "\n", ipc_port);
        return kread_addr(ipc_port + IPC_PORT_IP_KOBJECT_OFF, ip_kobject);
    }
    return KERN_FAILURE;
}

static io_connect_t
get_conn(const char *name) {
    io_service_t serv = IOServiceGetMatchingService(kIOMasterPortDefault, IOServiceMatching(name));
    io_connect_t conn = IO_OBJECT_NULL;
    
    if(serv != IO_OBJECT_NULL) {
        printf("serv: 0x%" PRIX32 "\n", serv);
        if(IOServiceOpen(serv, mach_task_self(), 0, &conn) != KERN_SUCCESS) {
            conn = IO_OBJECT_NULL;
        }
        IOObjectRelease(serv);
    }
    return conn;
}

static void
kcall_term(void) {
    io_external_trap_t trap = { 0 };
    
    kwrite_addr(user_client, orig_vtab);
    kfree(fake_vtab, MAX_VTAB_SZ);
    kwrite_buf(user_client + user_client_trap_off, &trap, sizeof(trap));
    IOServiceClose(g_conn);
}

static kern_return_t
kcall_init(void) {
    if((g_conn = get_conn("AppleKeyStore")) != IO_OBJECT_NULL) {
        printf("g_conn: 0x%" PRIX32 "\n", g_conn);
        if(find_task(getpid(), &our_task) == KERN_SUCCESS) {
            printf("our_task: " KADDR_FMT "\n", our_task);
            if(lookup_io_object(g_conn, &user_client) == KERN_SUCCESS) {
                printf("user_client: " KADDR_FMT "\n", user_client);
                if(kread_addr(user_client, &orig_vtab) == KERN_SUCCESS) {
                    printf("orig_vtab: " KADDR_FMT "\n", orig_vtab);
                    if(kalloc(MAX_VTAB_SZ, &fake_vtab) == KERN_SUCCESS) {
                        printf("fake_vtab: " KADDR_FMT "\n", fake_vtab);
                        if(mach_vm_copy(tfp0, orig_vtab, MAX_VTAB_SZ, fake_vtab) == KERN_SUCCESS && kwrite_addr(fake_vtab + vtab_get_ext_trap_for_idx_off, csblob_get_cdhash) == KERN_SUCCESS && kwrite_addr(user_client, fake_vtab) == KERN_SUCCESS) {
                            return KERN_SUCCESS;
                        }
                        kfree(fake_vtab, MAX_VTAB_SZ);
                    }
                }
            }
        }
        IOServiceClose(g_conn);
    }
    return KERN_FAILURE;
}

static kern_return_t
kcall(kern_return_t *ret, kaddr_t func, size_t argc, ...) {
    io_external_trap_t trap;
    kaddr_t args[7] = { 1 };
    va_list ap;
    size_t i;
    
    va_start(ap, argc);
    for(i = 0; i < MIN(argc, 7); ++i) {
        args[i] = va_arg(ap, kaddr_t);
    }
    va_end(ap);
    trap.obj = args[0];
    trap.func = func;
    trap.delta = 0;
    if(kwrite_buf(user_client + user_client_trap_off, &trap, sizeof(trap)) == KERN_SUCCESS) {
        *ret = IOConnectTrap6(g_conn, 0, args[1], args[2], args[3], args[4], args[5], args[6]);
        return KERN_SUCCESS;
    }
    return KERN_FAILURE;
}

static kern_return_t
phys_init(void) {
    kaddr_t kernel_task, kernel_map;
    
    if(find_task(0, &kernel_task) == KERN_SUCCESS) {
        printf("kernel_task: " KADDR_FMT "\n", kernel_task);
        if(kread_addr(kernel_task + task_map_off, &kernel_map) == KERN_SUCCESS) {
            printf("kernel_map: " KADDR_FMT "\n", kernel_map);
            if(kread_addr(kernel_map + VM_MAP_PMAP_OFF, &kernel_pmap) == KERN_SUCCESS) {
                printf("kernel_pmap: " KADDR_FMT "\n", kernel_pmap);
                if(kread_addr(kernel_pmap + PMAP_MIN_OFF, &kernel_pmap_min) == KERN_SUCCESS) {
                    printf("kernel_pmap_min: " KADDR_FMT "\n", kernel_pmap_min);
                    if(kread_addr(kernel_pmap + PMAP_MAX_OFF, &kernel_pmap_max) == KERN_SUCCESS) {
                        printf("kernel_pmap_max: " KADDR_FMT "\n", kernel_pmap_max);
                        return KERN_SUCCESS;
                    }
                }
            }
        }
    }
    return KERN_FAILURE;
}

static kern_return_t
phys_copy(kaddr_t src, kaddr_t dst, mach_vm_size_t sz) {
    vm_machine_attribute_val_t mattr_val = MATTR_VAL_CACHE_FLUSH;
    kaddr_t phys_src = src, phys_dst = dst;
    bool is_virt_src, is_virt_dst;
    mach_vm_size_t copy_sz;
    kern_return_t ret;
    
    while(sz != 0) {
        is_virt_src = src >= kernel_pmap_min && src < kernel_pmap_max;
        if(is_virt_src) {
            if(kcall(&ret, pmap_find_phys, 2, kernel_pmap, src) != KERN_SUCCESS || ret <= 0) {
                return KERN_FAILURE;
            }
            phys_src = ((kaddr_t)ret << vm_kernel_page_shift) | (src & vm_kernel_page_mask);
            printf("phys_src: " KADDR_FMT "\n", phys_src);
        }
        is_virt_dst = dst >= kernel_pmap_min && dst < kernel_pmap_max;
        if(is_virt_dst) {
            if(kcall(&ret, pmap_find_phys, 2, kernel_pmap, dst) != KERN_SUCCESS || ret <= 0) {
                if(kwrite_addr(dst, FAULT_MAGIC) != KERN_SUCCESS || kcall(&ret, pmap_find_phys, 2, kernel_pmap, dst) != KERN_SUCCESS || ret <= 0) {
                    return KERN_FAILURE;
                }
            }
            phys_dst = ((kaddr_t)ret << vm_kernel_page_shift) | (dst & vm_kernel_page_mask);
            printf("phys_dst: " KADDR_FMT "\n", phys_dst);
        }
        copy_sz = MIN(sz, MIN(vm_kernel_page_size - (phys_src & vm_kernel_page_mask), vm_kernel_page_size - (phys_dst & vm_kernel_page_mask)));
        if(((phys_src | phys_dst | copy_sz) % sizeof(kaddr_t)) != 0 || kcall(&ret, bcopy_phys, 4, phys_src, phys_dst, copy_sz, BCOPY_PHYS_SRC_PHYS | BCOPY_PHYS_DST_PHYS) != KERN_SUCCESS) {
            return KERN_FAILURE;
        }
        if(is_virt_dst && mach_vm_machine_attribute(tfp0, dst, copy_sz, MATTR_CACHE, &mattr_val) != KERN_SUCCESS) {
            return KERN_FAILURE;
        }
        src += copy_sz;
        dst += copy_sz;
        sz -= copy_sz;
    }
    return KERN_SUCCESS;
}


/*--- start ---*/
#include "payload.h"
#include "offsets.h"

uint64_t ml_phys_read_data;  // phys_read
uint64_t ml_phys_write_data; // phys_write

uint64_t ttbr1_el1;

uint64_t _sysent_stat;
uint64_t _copyinstr;
uint64_t _IOLog;
uint64_t _strcmp;
//uint64_t bootargs_store;
uint64_t _payload_base;

/* kvtophys: From KTRW
 *  Description:
 *      Convert a kernel virtual address to a physical address.
 */
static uint64_t
kvtophys(uint64_t kvaddr){
    kern_return_t ret;
    uint64_t src = kvaddr;
    
    uint64_t is_virt_src = src >= kernel_pmap_min && src < kernel_pmap_max;
    if(is_virt_src) {
        if(kcall(&ret, pmap_find_phys, 2, kernel_pmap, src) != KERN_SUCCESS || ret <= 0) {
            return 0;
        }
        uint64_t phys_src = ((kaddr_t)ret << vm_kernel_page_shift) | (src & vm_kernel_page_mask);
        printf("phys_src: " KADDR_FMT "\n", phys_src);
        return phys_src;
    }
    return 0;
}

/* phys_read64: From KTRW
 *  Description:
 *      Read a 64-bit value from the specified physical address.
 */
static uint64_t
phys_read64(uint64_t paddr) {
    kern_return_t ret;
    union {
        uint32_t u32[2];
        uint64_t u64;
    } u;
    
    kcall(&ret, ml_phys_read_data, 2, paddr, 4);
    u.u32[0] = (uint32_t)ret;
    kcall(&ret, ml_phys_read_data, 2, paddr+4, 4);
    u.u32[1] = (uint32_t)ret;
    return u.u64;
}

/* phys_write64: From KTRW
 *  Description:
 *      Write a 64-bit value to the specified physical address.
 */
static void
phys_write64(uint64_t paddr, uint64_t value) {
    kern_return_t ret;
    kcall(&ret, ml_phys_write_data, 3, paddr, value, 8);
}

/* pagetable_lockup: based on KTRW
 *  Description:
 *      Performs a page table lookup. Returns the physical address based on the set level.
 */
static uint64_t
pagetable_lockup(uint64_t ttb, uint64_t vaddr, int level){
    const uint64_t pg_bits = 14;
    const uint64_t l1_size = 3;
    const uint64_t l2_size = 11;
    const uint64_t l3_size = 11;
    const uint64_t tte_physaddr_mask = ((1uLL << 40) - 1) & ~((1 << pg_bits) - 1);
    
    printf("vaddr: %llx\n", vaddr);
    
    uint64_t l1_table = ttb;
    uint64_t l1_index = (vaddr >> (l2_size + l3_size + pg_bits)) & ((1 << l1_size) - 1);
    uint64_t l2_index = (vaddr >> (l3_size + pg_bits)) & ((1 << l2_size) - 1);
    uint64_t l3_index = (vaddr >> pg_bits) & ((1 << l3_size) - 1);
    uint64_t pg_offset = vaddr & ((1 << pg_bits) - 1);
    uint64_t p_l1_tte = l1_table + 8 * l1_index;
    
    if(level == 1) return p_l1_tte;
    
    uint64_t l1_tte = phys_read64(p_l1_tte);
    printf("l1_tte: %llx\n", l1_tte);
    
    uint64_t l2_table = l1_tte & tte_physaddr_mask;
    uint64_t p_l2_tte = l2_table + 8 * l2_index;
    
    if(level == 2) return p_l2_tte;
    
    uint64_t l2_tte = phys_read64(p_l2_tte);
    printf("l2_tte: %llx\n", l2_tte);
    
    uint64_t l3_table = l2_tte & tte_physaddr_mask;
    uint64_t p_l3_tte = l3_table + 8 * l3_index;
    
    if(level == 3) return p_l3_tte;
    
    uint64_t l3_tte = phys_read64(p_l3_tte);
    printf("l3_tte: %llx\n", l3_tte);
    
    uint64_t frame = l3_tte & tte_physaddr_mask;
    
    return  (frame | pg_offset);
}

/* change_l3_tte: based on KTRW
 *  Description:
 *      Change L3_tte to make it writable. KPP must be disabled in advance.
 */
void change_l3_tte(uint64_t ttb, uint64_t vaddr){
    uint64_t p_l3_tte = pagetable_lockup(ttb, vaddr, 3);
    uint64_t l3_tte = phys_read64(p_l3_tte);
    printf("old l3_tte: %llx\n", l3_tte);
    
    l3_tte &= ~(1uL << 52);     // Clear Contiguous
    l3_tte &= ~(3uL << 6);      // Set AP[2:1] = 00 (grants EL1 RW access)
    printf("new l3_tte: %llx\n", l3_tte);
    
    phys_write64(p_l3_tte, l3_tte);
    sleep(1);
}

static kern_return_t
bypass_jb_detection(void){
    kern_return_t ret;
    
    ret = KERN_FAILURE;
    if(offsets_init() == KERN_SUCCESS){
        
        /*--- Not used for KPP devices ---*
        uint64_t BootArgs;
        uint64_t virtBase;
        uint64_t physBase;
        
        kread_addr(bootargs_store,  &BootArgs);
        kread_addr(BootArgs + 0x8,  &virtBase);
        kread_addr(BootArgs + 0x10, &physBase);
        printf("BootArgs.virtBase: 0x%016llx\n", virtBase);
        printf("BootArgs.physBase: 0x%016llx\n", physBase);
         *--- END ---*/
        
        /* TTBR1_EL1:
         *  _kernel_pmap+0:  ttbr1_el1 + gVirtBase + gPhysBase
         *  _kernel_pmap+8:  ttbr1_el1
         */
        kread_addr(kernel_pmap + 8, &ttbr1_el1);
        printf("ttbr1_el1: 0x%llx\n", ttbr1_el1);
        
        write_payload();
        
        ret = KERN_SUCCESS;
    }
    
    return ret;
}

int
main(void) {
    
    printf("CPBypass2 v1.0.1 made by @dora2ios\n");
    
    kern_return_t ret;
    int str;
    printf("!! WARNING !!\n");
    printf("CPBypass2 apply patches actual pages protected with KPP/KTRR lockdown.\n");
    printf("If KPP is not disabled, the device will kernel panic after a few minutes.\n");
    printf("KPP really disabled on this device? If you want to continue, type \"Y\" and press <enter> key.\n");
    printf(">> ");
    
    str = getchar();
    if(str != 0x59){
        return -1;
    }
    
    if(init_tfp0() == KERN_SUCCESS) {
        printf("tfp0: 0x%" PRIX32 "\n", tfp0);
        if(pfinder_init_offsets() == KERN_SUCCESS && kcall_init() == KERN_SUCCESS) {
            if(kcall(&ret, csblob_get_cdhash, 1, user_client_trap_off) == KERN_SUCCESS) {
                printf("csblob_get_cdhash(USER_CLIENT_TRAP_OFF): 0x%" PRIX32 "\n", ret);
                if(phys_init() == KERN_SUCCESS) {
                    
                    bypass_jb_detection();
                    
                }
            }
            kcall_term();
        }
        mach_port_deallocate(mach_task_self(), tfp0);
    }
    
    return 0;
}
