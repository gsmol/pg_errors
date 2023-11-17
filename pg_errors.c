#include "postgres.h"
#include <unistd.h>
#include "funcapi.h"
#include "miscadmin.h"
#include "pgstat.h"
#include "storage/fd.h"
#include "storage/ipc.h"
#include "postmaster/autovacuum.h"
#include "storage/lwlock.h"
#include "storage/shmem.h"

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
#define PG_ERRORS_HEADER_MAGIC 0xF0000001

static emit_log_hook_type prev_log_hook = NULL;
static shmem_startup_hook_type prev_shmem_startup_hook = NULL;

typedef struct pg_errors_header
{
	uint32		magic;
	uint32		pg_version_num;
} pg_errors_header;

typedef struct pg_errors_counter
{
	pg_atomic_uint64 statement_cancel;
	pg_atomic_uint64 statement_timeout;
	pg_atomic_uint64 lock_timeout;
	pg_atomic_uint64 idle_in_tx_timeout;
} pg_errors_counter;

typedef struct pg_errors_shmem
{
	LWLock	   *lock;			/* protect shmem */
	pg_errors_counter count;
} pg_errors_shmem;

/* Shared memory state */
static pg_errors_shmem * shmem = NULL;

/*---- Function declarations ----*/
void		_PG_init(void);
void		_PG_fini(void);
static void pg_errors_emit_log(ErrorData *edata);
static void pg_errors_emit_log_internal(ErrorData *edata);
static void pg_errors_shmem_shutdown(int code, Datum arg);
static void pg_errors_shmem_startup(void);
static void pg_errors_shmem_startup_internal(void);
static Datum pg_errors_get_internal(void);

/* register */
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

	if (!process_shared_preload_libraries_in_progress)
		return;

	RequestAddinShmemSpace(
						   MAXALIGN(sizeof(pg_errors_shmem))
		);
	RequestNamedLWLockTranche("pg_errors", 1);

	/* Setup hooks */
	prev_log_hook = emit_log_hook;
	emit_log_hook = pg_errors_emit_log;

	prev_shmem_startup_hook = shmem_startup_hook;
	shmem_startup_hook = pg_errors_shmem_startup;
}

/*
 * Module unload callback
 */
void
_PG_fini(void)
{
	shmem_startup_hook = prev_shmem_startup_hook;
	emit_log_hook = prev_log_hook;
}

/* init shmem for module */
void
pg_errors_shmem_startup(void)
{
	/* we are bound to do so */
	if (prev_shmem_startup_hook)
		prev_shmem_startup_hook();
	pg_errors_shmem_startup_internal();
}

void
pg_errors_emit_log(ErrorData *edata)
{
	/* we are bound to do so */
	if (prev_log_hook)
		prev_log_hook(edata);

	pg_errors_emit_log_internal(edata);
}

Datum
pg_errors_get(PG_FUNCTION_ARGS)
{
	return pg_errors_get_internal();
}

Datum
pg_errors_reset(PG_FUNCTION_ARGS)
{
	pg_atomic_write_u64(&(shmem->count.statement_cancel), 0);
	pg_atomic_write_u64(&(shmem->count.statement_timeout), 0);
	pg_atomic_write_u64(&(shmem->count.lock_timeout), 0);
	pg_atomic_write_u64(&(shmem->count.idle_in_tx_timeout), 0);
	PG_RETURN_VOID();
}


/*
 =========== INTERNAL ===========
 */

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

void
pg_errors_emit_log_internal(ErrorData *edata)
{
	/* Not interested in noncrit messages */
	if (edata->elevel < ERROR)
		return;

	if (IsAutoVacuumWorkerProcess())
		return;

	/* should not be possible, but better safe than sorry */
	if (!shmem)
		return;

	/* avoid recursion */
	if (in_error_recursion_trouble())
		return;

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

void
pg_errors_shmem_startup_internal(void)
{
	FILE	   *f = NULL;
	bool		found = false;
	pg_errors_header hdr;
	pg_errors_counter temp;

	/*
	 * Create or attach to the shared memory
	 */
	LWLockAcquire(AddinShmemInitLock, LW_EXCLUSIVE);
	shmem = ShmemInitStruct("pg_errors",
							sizeof(pg_errors_shmem),
							&found);
	LWLockRelease(AddinShmemInitLock);

	/*
	 * If we're in the postmaster (or a standalone backend...), set up a shmem
	 * exit hook to dump the statistics to disk.
	 */
	if (!IsUnderPostmaster)
		on_shmem_exit(pg_errors_shmem_shutdown, (Datum) 0);

	/* attached */
	if (found)
		return;

	/* First time, eh ... */
	shmem->lock = &(GetNamedLWLockTranche("pg_errors"))->lock;
	pg_atomic_exchange_u64(&shmem->count.statement_cancel, 0);
	pg_atomic_exchange_u64(&shmem->count.statement_timeout, 0);
	pg_atomic_exchange_u64(&shmem->count.lock_timeout, 0);
	pg_atomic_exchange_u64(&shmem->count.idle_in_tx_timeout, 0);

	/*
	 * Attempt to load old statistics
	 */
	f = AllocateFile(PG_ERRORS_DUMP_FILE, PG_BINARY_R);
	if (f == NULL)
	{
		if (errno == ENOENT)
			return;				/* No existing persisted file, so we're done */

		/* failed to open file due to some external reason */
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not allocate file \"%s\": %m", PG_ERRORS_DUMP_FILE)));
		goto err;
	}

	if ((fread(&hdr, sizeof(pg_errors_header), 1, f) != 1) ||
		(fread(&temp, sizeof(pg_errors_counter), 1, f) != 1))
	{
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not read file \"%s\": %m", PG_ERRORS_DUMP_FILE)));
		goto err;
	}

	/* LWLockAcquire(shmem->lock, LW_EXCLUSIVE); */
	/* rc = fread(&(shmem->count), sizeof(pg_errors_counter), 1, f); */
	/* LWLockRelease(shmem->lock); */

	/* validate header */
	if (hdr.magic != PG_ERRORS_HEADER_MAGIC || hdr.pg_version_num != PG_MAJORVERSION_NUM)
		goto err;

	pg_atomic_add_fetch_u64(&shmem->count.statement_cancel, temp.statement_cancel.value);
	pg_atomic_add_fetch_u64(&shmem->count.statement_timeout, temp.statement_timeout.value);
	pg_atomic_add_fetch_u64(&shmem->count.lock_timeout, temp.lock_timeout.value);
	pg_atomic_add_fetch_u64(&shmem->count.idle_in_tx_timeout, temp.idle_in_tx_timeout.value);

err:
	if (f && FreeFile(f))
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not close file \"%s\": %m", PG_ERRORS_DUMP_FILE)));
	unlink(PG_ERRORS_DUMP_FILE);
}

/*
 * shmem_shutdown hook: Dump statistics into file
 */
void
pg_errors_shmem_shutdown(int code, Datum arg)
{
	FILE	   *f = NULL;
	pg_errors_header hdr;

	hdr.magic = PG_ERRORS_HEADER_MAGIC;
	hdr.pg_version_num = PG_MAJORVERSION_NUM;

	/* Don't try to dump during a crash. */
	if (code || !shmem)
		return;

	/*
	 * Open temp file, dump stats, fsync and rename into place, so we
	 * atomically replace any old one.
	 */
	f = AllocateFile(PG_ERRORS_DUMP_FILE ".tmp", PG_BINARY_W);
	if (f == NULL)
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not open for writing file \"%s\": %m",
						PG_ERRORS_DUMP_FILE ".tmp")));

	else if ((fwrite(&hdr, sizeof(pg_errors_header), 1, f) == 1) &&
			 fwrite(&(shmem->count), sizeof(pg_errors_counter), 1, f) == 1)
		durable_rename(PG_ERRORS_DUMP_FILE ".tmp", PG_ERRORS_DUMP_FILE, WARNING);

	if (f && FreeFile(f))
		ereport(WARNING,
				(errcode_for_file_access(),
				 errmsg("could not write file \"%s\": %m",
						PG_ERRORS_DUMP_FILE ".tmp")));
}
