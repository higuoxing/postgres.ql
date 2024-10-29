# postgres.ql

> Useful CodeQL scripts for doing static analysis on projects based on PostgreSQL.

- [return-in-PG_TRY.ql](./return-in-PG\_TRY.ql) for detecting suspicious control flow statements inside PG\_TRY block.
  - [postgres/postgres@5eac8ce](https://github.com/postgres/postgres/commit/5eac8cef24543767015a9b248af08bbfa10b1b70)
  - [postgres/postgres@57d0051](https://github.com/postgres/postgres/commit/57d0051706b897048063acc14c2c3454200c488f)

- [volatile-in-PG_TRY.ql](./volatile-in-PG\_TRY.ql) for detecting missed qualifiers for variables used in the PG\_TRY, PG\_CATCH block.
  - [citusdata/citus@ada3ba2](https://github.com/citusdata/citus/commit/ada3ba25072cc5be055b3bbdedfa2fe936443b0d)
  - [greenplum-db/gpdb-archive@cfa141f](https://github.com/greenplum-db/gpdb-archive/commit/cfa141f42ea3cef312e16013c0f43e44f0d647ba)
  - [greenplum-db/gpdb-archive@c807161](https://github.com/greenplum-db/gpdb-archive/commit/c807161ca795dfb7c2784d24a20915c741f4fe33)

- [typedef-checker.ql](./typedef-checker.ql) for detecting suspicious typedef casting.
  The idea is not proposed by myself but by Dmitry Dolgov in https://www.postgresql.org/message-id/flat/20230803165638.nyjgdqxg7korp54r%40erthalion.local
  - [greenplum-db/gpdb-archive@6fa4800](https://github.com/greenplum-db/gpdb-archive/commit/6fa4800539879ba21e2833835f035f2c2489ceee)
