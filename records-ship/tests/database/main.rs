//! Real-database tests of the records shipper. The PostgreSQL ones run against the server whose connection string is
//! in the file named by `TUKUYOMI_TEST_PGSQL_DSN_FILE`, each in a schema of its own that it makes and drops. The
//! MySQL ones run against the server whose connection string is in the file named by `TUKUYOMI_TEST_MYSQL_DSN_FILE`,
//! in the one database that string names: for that database is the only one the user has, they run one at a time and
//! drop the tables of the shipper at the start and at the end. They are ignored by default, and never skipped when
//! they are asked for.

mod mysql;
mod postgres;
mod support;
