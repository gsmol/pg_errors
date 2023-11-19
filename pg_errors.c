#include <unistd.h>
#include <sys/stat.h>
#include <string.h>
#include <sys/mman.h>
#include <stdio.h>
#include <stdlib.h>

#include "postgres.h"
#include "funcapi.h"
#include "pgstat.h"
#include "storage/fd.h"
#include "postmaster/autovacuum.h"
#include "storage/lwlock.h"

#if PG_VERSION_NUM < 120000
#include "catalog/pg_type.h"
#include "access/htup_details.h"
#endif

PG_MODULE_MAGIC;

#ifndef PG_MAJORVERSION_NUM
#define PG_MAJORVERSION_NUM (PG_VERSION_NUM / 100)
#endif

/* Location of permanent stats file (valid when database is shut down) */
#define PG_ERRORS_DUMP_FILE	PGSTAT_STAT_PERMANENT_DIRECTORY "/pg_errors.stat"
#define PG_ERRORS_HEADER_MAGIC 0xF2A9E150
#define PG_ERRORS_LIB_VERSION 0x0001 /* MUST be incremented any time shared struct changes */

bool backend_is_tainted = false;
static emit_log_hook_type prev_log_hook = NULL;

typedef struct pg_errors_header
{
	uint32	magic;
	uint16	shmem_size;
	uint16	pg_version_num;
	uint16	lib_version_num;
} pg_errors_header;

typedef struct pg_errors_counter
{
	pg_atomic_uint64	statement_cancel;
	pg_atomic_uint64	statement_timeout;
	pg_atomic_uint64	lock_timeout;
	pg_atomic_uint64	idle_in_tx_timeout;
} pg_errors_counter;

/* NOTE: any change in this structure MUST come with PG_ERRORS_LIB_VERSION change */
typedef struct pg_errors_shmem
{
	pg_errors_header	hdr;
	pg_errors_counter	count;
} pg_errors_shmem;

/* Shared memory state */
static pg_errors_shmem *shmem = NULL;

/*---- Function declarations ----*/
void		_PG_init(void);
void		_PG_fini(void);
static void	pg_errors_emit_log(ErrorData *edata);
static void	pg_errors_emit_log_internal(ErrorData *edata);
static Datum pg_errors_get_internal(void);
static void	pg_errors_reset_internal(void);
static void init_shmem(void);
static bool is_header_valid(void);

/* Register */
PG_FUNCTION_INFO_V1(pg_errors_get);
PG_FUNCTION_INFO_V1(pg_errors_reset);

/*
 =========== EXTERNAL ===========
 */

/*
 * Module load callback
 */
void
_PG_init(void)
{
	/* Setup hooks */
	prev_log_hook = emit_log_hook;
	emit_log_hook = pg_errors_emit_log;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	emit_log_hook = prev_log_hook;
}

void
pg_errors_emit_log(ErrorData *edata)
{
	/* we are bound to do so */
	if (prev_log_hook)
		prev_log_hook(edata);

	if (edata->elevel < ERROR ||		/* Not interested in noncrit messages */
		backend_is_tainted ||
		IsAutoVacuumWorkerProcess() ||
		in_error_recursion_trouble())	/* avoid recursion in elog */
			return;

	init_shmem();
	if (!shmem)
		return;

	/* sanity, make sure that shared memory structure didnt changed since last access */
	if (!is_header_valid())
	{
		backend_is_tainted = true;
		return;
	}
	pg_errors_emit_log_internal(edata);
}

Datum
pg_errors_get(PG_FUNCTION_ARGS)
{
	init_shmem();
	if (!shmem)
		elog(ERROR, "failed to init shmem");
	if (!is_header_valid())
		elog(ERROR, "pg_errors header is invalid");

	return pg_errors_get_internal();
}

Datum
pg_errors_reset(PG_FUNCTION_ARGS)
{
	init_shmem();
	if (!shmem)
		elog(ERROR, "failed to init shmem");
	if (!is_header_valid())
		elog(ERROR, "pg_errors header is invalid");

	pg_errors_reset_internal();
	PG_RETURN_VOID();
}

/*
 =========== INTERNAL ===========
 */

void
pg_errors_reset_internal(void)
{
	pg_atomic_write_u64(&(shmem->count.statement_cancel), 0);
	pg_atomic_write_u64(&(shmem->count.statement_timeout), 0);
	pg_atomic_write_u64(&(shmem->count.lock_timeout), 0);
	pg_atomic_write_u64(&(shmem->count.idle_in_tx_timeout), 0);
}

Datum
pg_errors_get_internal(void)
{
	bool		nulls[4];
	Datum		values[4];
	HeapTuple	htup;
	TupleDesc	tupdesc;

#if PG_VERSION_NUM >= 120000
	tupdesc = CreateTemplateTupleDesc(4);
#else
	tupdesc = CreateTemplateTupleDesc(4, false);
#endif

	TupleDescInitEntry(tupdesc, (AttrNumber) 1, "statement_cancel",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 2, "statement_timeout",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 3, "lock_timeout",
					   INT8OID, -1, 0);
	TupleDescInitEntry(tupdesc, (AttrNumber) 4, "idle_in_tx_timeout",
					   INT8OID, -1, 0);
	tupdesc = BlessTupleDesc(tupdesc);

	values[0] = UInt64GetDatum(
							   pg_atomic_read_u64(&(shmem->count.statement_cancel)));
	nulls[0] = false;

	values[1] = UInt64GetDatum(
							   pg_atomic_read_u64(&(shmem->count.statement_timeout)));
	nulls[1] = false;

	values[2] = UInt64GetDatum(
							   pg_atomic_read_u64(&(shmem->count.lock_timeout)));
	nulls[2] = false;

	values[3] = UInt64GetDatum(
							   pg_atomic_read_u64(&(shmem->count.idle_in_tx_timeout)));
	nulls[3] = false;

	htup = heap_form_tuple(tupdesc, values, nulls);
	PG_RETURN_DATUM(HeapTupleGetDatum(htup));
}

/* the heart of all things */
void
pg_errors_emit_log_internal(ErrorData *edata)
{
	/* increment counters */
	switch (edata->sqlerrcode)
	{
		case ERRCODE_QUERY_CANCELED:
			if (strstr(edata->message_id, "statement timeout"))
				pg_atomic_add_fetch_u64(&shmem->count.statement_timeout, 1);
			else if (strstr(edata->message_id, "user request"))
				pg_atomic_add_fetch_u64(&shmem->count.statement_cancel, 1);
			break;
		case ERRCODE_LOCK_NOT_AVAILABLE:
			pg_atomic_add_fetch_u64(&shmem->count.lock_timeout, 1);
			break;
		case ERRCODE_IDLE_IN_TRANSACTION_SESSION_TIMEOUT:
			pg_atomic_add_fetch_u64(&shmem->count.idle_in_tx_timeout, 1);
			break;
	}
	/* elog(WARNING, "SQL CODE: %s", unpack_sql_state(edata->sqlerrcode)); */
}

/* open dump file (create if none) and mmap it into shared memory */
void
init_shmem(void)
{
	int fd = 0;
	struct stat sb;

	if (shmem) /* already mmaped */
		return;

	fd = OpenTransientFilePerm(PG_ERRORS_DUMP_FILE, O_RDWR | O_CREAT | O_EXCL | PG_BINARY, S_IRUSR | S_IWUSR);
	if (fd <= 0 && errno == EEXIST) /* Race */
		fd = OpenTransientFilePerm(PG_ERRORS_DUMP_FILE, O_RDWR | PG_BINARY, S_IRUSR | S_IWUSR);

	/* Race? Inode or disk space shortage? lets just quit and try our luck next time */
	if (fd <= 0)
	{
		ereport(WARNING,
			(errcode_for_file_access(),
			 errmsg("could not open file \"%s\": %m", PG_ERRORS_DUMP_FILE)));
		return;
	}

	/* Get file size */
	if (fstat(fd, &sb) == -1)
	{
		ereport(WARNING,
			(errcode_for_file_access(),
			 errmsg("could not fstat file \"%s\": %m", PG_ERRORS_DUMP_FILE)));
		goto close;
	}

	/* Never truncate down */
	if (sb.st_size > sizeof(pg_errors_shmem))
	{
		/* backend is probably running old library, backend is tainted */
		backend_is_tainted = true;
		goto close;
	}
	/*
	 * Truncate up to shmem size, we dont want to risk SIGBUS.
	 * Because two different backends could theoretically load two different
	 * versions of library (e.g. due to library upgrade) with different pg_errors_shmem.
	 */
	else if (sb.st_size < sizeof(pg_errors_shmem) && ftruncate(fd, sizeof(pg_errors_shmem)) < 0)
	{
		ereport(WARNING,
			(errcode_for_file_access(),
			 errmsg("could not truncate file \"%s\": %m", PG_ERRORS_DUMP_FILE)));
		goto close;
	}

	shmem = mmap(NULL, sizeof(pg_errors_shmem), PROT_READ | PROT_WRITE, MAP_SHARED, fd, 0);
	if (shmem == MAP_FAILED)
	{
		ereport(WARNING,
			(errmsg("could not mmap file \"%s\": %m", PG_ERRORS_DUMP_FILE)));
		shmem = NULL;
	}

close:
	if (fd > 0 && CloseTransientFile(fd) != 0)
	{
		ereport(WARNING,
			(errcode_for_file_access(),
			 errmsg("could not close file \"%s\": %m", PG_ERRORS_DUMP_FILE)));
		return;
	}

	/* better luck next time */
	if (!shmem)
		return;

	/*
	 * Validate header in freshly mmaped shmem, possible cases:
	 *  - freshly created file
	 * 	- file corruption
	 *  - module upgrade
	 *  - current backend is running old version library (special note)
	 *  - PostgreSQL major version upgrade
	 */
	if (!is_header_valid())
	{
		/* I`m sure we can do fine without locking, but better safe than sorry */
		LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);
		/* do re-check, mayhaps some friendly neighbor already done all the work */
		if (!is_header_valid())
		{
			/* Is current backend is loaded with old library? Our greatest fear */
			if (shmem->hdr.magic == PG_ERRORS_HEADER_MAGIC &&
				shmem->hdr.pg_version_num == PG_MAJORVERSION_NUM &&
				shmem->hdr.lib_version_num > PG_ERRORS_LIB_VERSION)
					backend_is_tainted = true;
			else
			{
				memset(shmem, 0, sizeof(pg_errors_shmem));
				shmem->hdr.magic = PG_ERRORS_HEADER_MAGIC;
				shmem->hdr.lib_version_num = PG_ERRORS_LIB_VERSION;
				shmem->hdr.pg_version_num = PG_MAJORVERSION_NUM;
				shmem->hdr.shmem_size = sizeof(pg_errors_shmem);
			}
		}
		LWLockRelease(AddinShmemInitLock);
	}
}

/* Sanity check for header magic, lib_version, pg_version and expected shmem size */
bool
is_header_valid(void)
{
	return (shmem->hdr.magic == PG_ERRORS_HEADER_MAGIC &&
			shmem->hdr.lib_version_num == PG_ERRORS_LIB_VERSION &&
			shmem->hdr.pg_version_num == PG_MAJORVERSION_NUM &&
			shmem->hdr.shmem_size == sizeof(pg_errors_shmem));
}
