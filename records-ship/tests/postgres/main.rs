//! Real-database tests of the records shipper: each runs against the PostgreSQL server whose connection string is
//! in the file named by `TUKUYOMI_TEST_PGSQL_DSN_FILE`, in a schema of its own that it makes and drops. They are
//! ignored by default, and never skipped when they are asked for.

mod outage;
mod refusals;
mod shipping;
mod support;
