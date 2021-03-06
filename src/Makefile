.PHONY: all clean
all:
	xcrun -sdk iphoneos clang -arch arm64 -mios-version-min=13.0 maphys.c offsets.c payload.o -o CPBypass2 -framework IOKit -framework CoreFoundation -lcompression -Os
	strip CPBypass2
	ldid -Stfp0.entitlements CPBypass2

clean:
	$(RM) CPBypass2
