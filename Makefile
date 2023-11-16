MODULE_big = pg_errors
OBJS = pg_errors.o

EXTENSION = pg_errors
DATA = pg_errors--1.0.sql
PGFILEDESC = "pg_errors - SQL statements error statistics"

REGRESS_OPTS = --temp-config $(top_srcdir)/contrib/pg_errors/pg_errors.conf
REGRESS = pg_errors


ifdef USE_PGXS
PG_CONFIG = pg_config
PGXS := $(shell $(PG_CONFIG) --pgxs)
include $(PGXS)
else
subdir = contrib/pg_errors
top_builddir = ../..
include $(top_builddir)/src/Makefile.global
include $(top_srcdir)/contrib/contrib-global.mk
endif
