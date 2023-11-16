CREATE EXTENSION pg_errors;
--
-- simple and compound statements
--
SELECT pg_errors_reset();

SELECT * FROM pg_errors;

-- statement_timeout
BEGIN;
SET LOCAL statement_timeout to '1s';
SELECT pg_sleep(10);
COMMIT;

-- error
SET LOCAL statement_timeout to 1s;

-- check that counter are incremented
SELECT * FROM pg_errors;

-- check reset
SELECT * from pg_errors_reset();

-- check that reset works
SELECT * FROM pg_errors;

DROP EXTENSION pg_errors;
