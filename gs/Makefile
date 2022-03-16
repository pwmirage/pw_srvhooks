COMMON_OBJECTS = avl.o cjson.o common.o
OBJECTS = main.o
CFLAGS := -O0 -g -MD -MP -fPIC -m32 -masm=intel -fno-strict-aliasing -Wall -Wno-format-truncation $(CFLAGS)
CFLAGS := $(CFLAGS) -I../common

$(shell mkdir -p build &>/dev/null)

all: build/preload.so

clean:
	rm -f $(ALL_OBJECTS:%.o=build/%.o) $(ALL_OBJECTS:%.o=build/%.d) build/preload.so

build/preload.so: $(COMMON_OBJECTS:%.o=build/%.o) $(OBJECTS:%.o=build/%.o)
	gcc-5 -shared $(CFLAGS) -o $@ $^

$(COMMON_OBJECTS:%.o=build/%.o): build/%.o: ../common/%.c
	gcc-5 $(CFLAGS) -c -o $@ $<

$(OBJECTS:%.o=build/%.o): build/%.o: %.c
	gcc-5 $(CFLAGS) -c -o $@ $<

-include $(ALL_OBJECTS:%.o=build/%.d)
