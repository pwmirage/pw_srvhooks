TARGETS = gamedbd gdeliveryd gs
MAKEFLAGS += --no-print-directory

all: $(TARGETS) dummy

.PHONY: dummy

$(TARGETS): dummy
	@if [ "$(MAKECMDGOALS)" = "all" ] || [ "$(MAKECMDGOALS)" = "" ]; then \
		echo "$$ make $@:"; \
	fi
	@cd $@ && $(MAKE)

dummy: