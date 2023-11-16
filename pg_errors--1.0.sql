/* contrib/pg_errors/pg_errors--1.0.sql */

-- complain if script is sourced in psql, rather than via CREATE EXTENSION
\echo Use "CREATE EXTENSION pg_errors" to load this file. \quit

CREATE OR REPLACE FUNCTION pg_errors_reset()
RETURNS void
AS 'MODULE_PATHNAME'
LANGUAGE C PARALLEL SAFE;

-- Don't want this to be available to non-superusers.
REVOKE ALL ON FUNCTION pg_errors_reset() FROM PUBLIC;

CREATE OR REPLACE FUNCTION pg_errors_get(
    OUT statement_cancel int8,
    OUT statement_timeout int8,
    OUT lock_timeout int8,
    OUT idle_in_tx_timeout int8
)
RETURNS record
AS 'pg_errors'
LANGUAGE C PARALLEL SAFE;

-- Register a view on the function for ease of use.
CREATE VIEW pg_errors AS
  SELECT * FROM pg_errors_get();

GRANT SELECT ON pg_errors TO PUBLIC;
