OBJECTS = avl.o cjson.o common.o
ALL_OBJECTS := $(OBJECTS) gs_preload.o
CFLAGS := -O0 -g -MD -MP -fPIC -m32 -masm=intel -fno-strict-aliasing -Wall -Wno-format-truncation $(CFLAGS)

$(shell mkdir -p build &>/dev/null)

all: build/gs_preload.so

clean:
	rm -f $(ALL_OBJECTS:%.o=build/%.o) $(ALL_OBJECTS:%.o=build/%.d)

build/gs_preload.so: $(OBJECTS:%.o=build/%.o) build/gs_preload.o
	gcc-5 -shared $(CFLAGS) -o $@ $^

build/%.o: %.c
	gcc-5 $(CFLAGS) -c -o $@ $<

-include $(ALL_OBJECTS:%.o=build/%.d)
