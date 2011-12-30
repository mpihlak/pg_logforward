MODULE_big = pg_logforward
OBJS = pg_logforward.o

#EXTENSION = pg_logforward
#DATA = pg_logforward--1.0.sql pg_logforward--unpackaged--1.0.sql

SHLIB_LINK = $(filter, $(LIBS)) -ljson

PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
