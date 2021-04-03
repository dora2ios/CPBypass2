# CPBypass2  
jailbreak detection bypass with kernel patches  

## Warning  
This project requires KPP to be disabled in order to patch the kernel. This means that kernel integrity is not guaranteed and should only be done on development devices.  
In the near future, this project will be a module of checkra1n. It will enable kernel integrity protection and will work with A7-A11 devices.  

## LICENSE  
For this project, Apache License 2.0 is used for the kernel patcher. But, The [syscall payload](https://github.com/dora2-iOS/CPBypass-public/blob/main/kernel/payload/stat_sysent64.c) used for it is based on GPLv3, so if you want to redistribute [it](https://github.com/dora2-iOS/CPBypass2/blob/main/src/payload.o), you need to clarify the source code of the syscall payload.  

## File details  
`module/KPPmodule` A checkra1n module that disables KPP for 16k devices based on [xnuspy](https://github.com/jsherman212/xnuspy/tree/master/module/el3) by Justin Sherman  
`src/` A kernel patcher for KPP disabled devices.  

## Support  
Currently it only supports iOS 14 A9 devices (with KPP disabled).  
- Support device Lists  
```
A9(X): iOS 14.0 - 14.4.2 (RELEASE version only)
```

## Build  
- clone  
```
git clone https://github.com/dora2-iOS/CPBypass2
cd CPBypass2
```

- build  
```
cd src/
make
```

## How To Use  
- Boot with checkra1n  
```
/Applications/checkra1n.app/Contents/MacOS/checkra1n -c -p
```

- Load KPPmodule  
```
cd module/
python module_load.py KPPmodule
python issue_cmd.py disable_kpp
```

- Install CPBypass2 Tweak on iOS (Mobile Terminal or SSH)  
```
dpkg -i jp.dora2ios.cpbypass64_1.0.1_iphoneos-arm.deb
```

- Apply kernel patch on iOS (Mobile Terminal or SSH)  
```
CPBypass2
```

## Thanks
Justin Sherman for [xnuspy](https://github.com/jsherman212/xnuspy)  
bazad for [KTRW](https://github.com/googleprojectzero/ktrw)   
0x7ff for [maphys](https://github.com/0x7ff/maphys)  
