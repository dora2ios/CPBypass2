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

#define OFFSET(val) ((uint64_t)val + slide)

kern_return_t
offsets_init(void){
    kern_return_t ret;
    
    ret = KERN_FAILURE;
    struct utsname u = { 0 };
    uname(&u);
    
    /* ----- find payload base ----- *
     1, Find __LASTDATA_CONST segment
     2, Subtract 0x930 from __LASTDATA_CONST start point.
     3, Make sure that the area is __TEXT_EXEC and that the range up to __LASTDATA_CONST is filled with \x00.
       ------------ end ------------ */
    
    
    /*---- All A9(X) - iOS 14 kernel offsets (Maybe) ----*/
    if (strcmp(u.version, "Darwin Kernel Version 20.0.0: Fri Aug 28 23:05:58 PDT 2020; root:xnu-7195.0.46~9/RELEASE_ARM64_S8000") == 0 ||
        strcmp(u.version, "Darwin Kernel Version 20.0.0: Wed Sep 30 03:24:41 PDT 2020; root:xnu-7195.0.46~41/RELEASE_ARM64_S8000") == 0) {
        /*---- S8000 18A373 [14.0] ----*/
        /*---- S8000 18A393 [14.0.1] ----*/
        /*---- S8000 18A8395 [14.1] ----*/
        bootargs_store      = OFFSET(0xfffffff0070ec000);
        ml_phys_read_data   = OFFSET(0xfffffff00723a58c);
        ml_phys_write_data  = OFFSET(0xfffffff00723a7ac);
        _sysent_stat        = OFFSET(0xfffffff0070d1360);
        _copyinstr          = OFFSET(0xfffffff00723427c);
        _IOLog              = OFFSET(0xfffffff0076635bc);
        _strcmp             = OFFSET(0xfffffff007213fa0);
        _payload_base       = OFFSET(0xfffffff00772b6d0); // __TEXT_EXEC area
    } else if (strcmp(u.version, "Darwin Kernel Version 20.1.0: Fri Oct 30 00:34:16 PDT 2020; root:xnu-7195.42.3~1/RELEASE_ARM64_S8000") == 0) {
        /*---- S8000 18B92 [14.2] ----*/
        bootargs_store      = OFFSET(0xfffffff0070f8230);
        ml_phys_read_data   = OFFSET(0xfffffff007246b50);
        ml_phys_write_data  = OFFSET(0xfffffff007246d70);
        _sysent_stat        = OFFSET(0xfffffff0070dd3a0);
        _copyinstr          = OFFSET(0xfffffff007240780);
        _IOLog              = OFFSET(0xfffffff0076732d4);
        _strcmp             = OFFSET(0xfffffff0072204e4);
        _payload_base       = OFFSET(0xfffffff00773f6d0);
    } else if (strcmp(u.version, "Darwin Kernel Version 20.2.0: Fri Nov 13 01:00:11 PST 2020; root:xnu-7195.62.1~4/RELEASE_ARM64_S8000") == 0) {
        /*---- S8000 18C65/18C66 [14.3 (RC/RC2)] ----*/
        bootargs_store      = OFFSET(0xfffffff0070f87e8);
        ml_phys_read_data   = OFFSET(0xfffffff0072476e8);
        ml_phys_write_data  = OFFSET(0xfffffff007247908);
        _sysent_stat        = OFFSET(0xfffffff0070dd3a0);
        _copyinstr          = OFFSET(0xfffffff007241298);
        _IOLog              = OFFSET(0xfffffff00767496c);
        _strcmp             = OFFSET(0xfffffff007220afc);
        _payload_base       = OFFSET(0xfffffff0077436d0);
    } else if (strcmp(u.version, "Darwin Kernel Version 20.3.0: Tue Jan  5 18:34:47 PST 2021; root:xnu-7195.80.35~2/RELEASE_ARM64_S8000") == 0) {
        /*---- S8000 18D52 [14.4] ----*/
        bootargs_store      = OFFSET(0xfffffff0070f8800);
        ml_phys_read_data   = OFFSET(0xfffffff007247798);
        ml_phys_write_data  = OFFSET(0xfffffff0072479b8);
        _sysent_stat        = OFFSET(0xfffffff0070dd3a0);
        _copyinstr          = OFFSET(0xfffffff00724146c);
        _IOLog              = OFFSET(0xfffffff007674f10);
        _strcmp             = OFFSET(0xfffffff007220c60);
        _payload_base       = OFFSET(0xfffffff0077436d0);
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
