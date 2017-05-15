PROG := el

ifdef __EL_COUNTER
SRCS += $(REL)el.c $(REL)load.c $(REL)dynamic.c $(REL)dynamic_segment.c $(REL)utility.c $(REL)init.c $(REL)print.c
else
SRCS := el.c load.c dynamic.c dynamic_segment.c utility.c init.c print.c
OBJS := $(SRCS:%.c=%.o)
DEPS := $(SRCS:%.c=%.d)

CFLAGS :=-g -Wall -W
LDFLAGS := -rdynamic -ldl -Wl,-Ttext-segment=0x2000000

all: $(PROG)

-include $(DEPS)

$(PROG): $(OBJS)
	$(CC) $(CFLAGS) $^ $(LDFLAGS) -o $@

%.o: %.c
	$(CC) $(CFLAGS) -c -MMD -MP $<

clean:
	rm -f $(PROG) $(OBJS) $(DEPS)
endif
