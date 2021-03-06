#include <CoreFoundation/CoreFoundation.h>
#include <sys/utsname.h>

extern uint64_t ml_phys_read_data;  // phys_read
extern uint64_t ml_phys_write_data; // phys_write

extern uint64_t _sysent_stat;
extern uint64_t _copyinstr;
extern uint64_t _IOLog;
extern uint64_t _strcmp;
extern uint64_t bootargs_store;
extern uint64_t _payload_base;

extern uint64_t slide;

kern_return_t
offsets_init(void){
    kern_return_t ret;
    
    ret = KERN_FAILURE;
    struct utsname u = { 0 };
    uname(&u);
    
    if (strcmp(u.version, "Darwin Kernel Version 20.0.0: Fri Aug 28 23:05:58 PDT 2020; root:xnu-7195.0.46~9/RELEASE_ARM64_S8000") == 0) {
        /*---- iPhone8,1 18A373 ----*/
        bootargs_store = 0xfffffff0070ec000 + slide;
        ml_phys_read_data = 0xfffffff00723a58c + slide;
        ml_phys_write_data = 0xfffffff00723a7ac + slide;
        _sysent_stat = 0xfffffff0070d1360 + slide;
        _copyinstr = 0xfffffff00723427c + slide;
        _IOLog = 0xfffffff0076635bc + slide;
        _strcmp = 0xfffffff007213fa0 + slide;
        _payload_base = 0xfffffff00772b6d0 + slide; // __TEXT_EXEC area
    } else if (strcmp(u.version, "Darwin Kernel Version 20.2.0: Fri Nov 13 01:00:11 PST 2020; root:xnu-7195.62.1~4/RELEASE_ARM64_S8000") == 0) {
        /*---- iPhone8,1 18C66 ----*/
        bootargs_store = 0xfffffff0070f87e8 + slide;
        ml_phys_read_data = 0xfffffff0072476e8 + slide;
        ml_phys_write_data = 0xfffffff007247908 + slide;
        _sysent_stat = 0xfffffff0070dd3a0 + slide;
        _copyinstr = 0xfffffff007241298 + slide;
        _IOLog = 0xfffffff00767496c + slide;
        _strcmp = 0xfffffff007220afc + slide;
        _payload_base = 0xfffffff0077436d0 + slide; // __TEXT_EXEC area
    } else {
        printf("offsets are not set\n");
        return ret;
    }
    
    ret = KERN_SUCCESS;
    
    /*---- Show offsets ----*/
    printf("ml_phys_read_data: 0x%016llx\n", ml_phys_read_data);
    printf("ml_phys_write_data: 0x%016llx\n", ml_phys_write_data);
    printf("_sysent_stat: 0x%016llx\n", _sysent_stat);
    printf("_copyinstr: 0x%016llx\n", _copyinstr);
    printf("_IOLog: 0x%016llx\n", _IOLog);
    printf("_strcmp: 0x%016llx\n", _strcmp);
    printf("_payload_base: 0x%016llx\n", _payload_base);
    
    return ret;
}
