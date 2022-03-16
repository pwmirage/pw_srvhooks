COMMON_OBJECTS = memory.o
OBJECTS = main.o
ALL_OBJECTS = $(COMMON_OBJECTS) $(OBJECTS)
CFLAGS := -O0 -g -MD -MP -fPIC -m32 -masm=intel -fno-strict-aliasing -fno-stack-protector -Wall $(CFLAGS)
CFLAGS := $(CFLAGS) -I../common

$(shell mkdir -p build &>/dev/null)

all: build/preload.so

clean:
	rm -f $(ALL_OBJECTS:%.o=build/%.o) $(ALL_OBJECTS:%.o=build/%.d) build/preload.so

build/preload.so: $(COMMON_OBJECTS:%.o=build/%.o) $(OBJECTS:%.o=build/%.o)
	gcc-5 $(CFLAGS) -shared -o $@ -Wl,--hash-style=sysv -Wl,-Ttext-segment=0x400000 -Wl,--just-symbols,symbols.ld -Wl,--no-undefined -Wl,--version-script,version.map $^ -nostdlib

$(COMMON_OBJECTS:%.o=build/%.o): build/%.o: ../common/%.c
	gcc-5 $(CFLAGS) -c -o $@ $<

$(OBJECTS:%.o=build/%.o): build/%.o: %.c
	gcc-5 $(CFLAGS) -c -o $@ $<

-include $(ALL_OBJECTS:%.o=build/%.d)
