MODULE_big = pg_logforward
OBJS = pg_logforward.o

SHLIB_LINK = $(filter, $(LIBS)) -ljson

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
