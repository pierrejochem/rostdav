//! The layer between the data code and the Turso Database engine.
//!
//! The data layer was written against `sqlx` (`query(..).bind(..).fetch_one(..)`); this module
//! keeps that call style, so the queries read the same, and takes care of what the engine
//! needs from its caller:
//!
//! * **One writer.** Two connections that write at the same time make one of them fail with
//!   `Busy`. All writes therefore go through one connection behind a lock, and a transaction
//!   holds that lock from `BEGIN IMMEDIATE` to the end. Reads use a few other connections and
//!   see the last committed state while a write transaction is open.
//! * **Per-connection settings** (`foreign_keys`, `synchronous`, `busy_timeout`) are applied to
//!   every connection when it is opened.
//! * **Classification of errors**, for example a violated `UNIQUE` constraint.
//!
//! A statement made through [`Pool`] goes to the writer or to a reader by its first keyword;
//! a statement made through a [`Conn`] or [`Tx`] always runs on that connection.

use std::future::Future;
use std::ops::{Deref, DerefMut};
use std::sync::Arc;
use std::sync::atomic::{AtomicUsize, Ordering};

use tokio::sync::{Mutex, OwnedMutexGuard};
use turso::Value;

pub type Result<T> = std::result::Result<T, Error>;

/// An error from the engine.
#[derive(Debug)]
pub struct Error(turso::Error);

impl Error {
    /// A `UNIQUE` or primary key constraint was violated.
    pub fn is_unique_violation(&self) -> bool {
        matches!(&self.0, turso::Error::Constraint(m) if m.contains("UNIQUE") || m.contains("PRIMARY KEY"))
    }
}

impl std::fmt::Display for Error {
    fn fmt(&self, f: &mut std::fmt::Formatter<'_>) -> std::fmt::Result {
        self.0.fmt(f)
    }
}

impl std::error::Error for Error {}

impl From<turso::Error> for Error {
    fn from(e: turso::Error) -> Self {
        Error(e)
    }
}

fn decode_error(msg: String) -> Error {
    Error(turso::Error::ConversionFailure(msg))
}

// ---- values -------------------------------------------------------------------------------

/// What can be bound to a `?` parameter.
pub trait Encode {
    fn encode(self) -> Value;
}

macro_rules! encode_int {
    ($($t:ty),*) => {$(
        impl Encode for $t {
            #[allow(clippy::cast_possible_wrap, clippy::cast_lossless)]
            fn encode(self) -> Value { Value::Integer(self as i64) }
        }
    )*};
}
encode_int!(i64, i32, u32, u8, u16, u64, usize);

impl Encode for bool {
    fn encode(self) -> Value {
        Value::Integer(i64::from(self))
    }
}
impl Encode for f64 {
    fn encode(self) -> Value {
        Value::Real(self)
    }
}
impl Encode for &str {
    fn encode(self) -> Value {
        Value::Text(self.to_owned())
    }
}
impl Encode for String {
    fn encode(self) -> Value {
        Value::Text(self)
    }
}
impl Encode for &[u8] {
    fn encode(self) -> Value {
        Value::Blob(self.to_vec())
    }
}
impl Encode for Vec<u8> {
    fn encode(self) -> Value {
        Value::Blob(self)
    }
}
impl<T: Encode> Encode for Option<T> {
    fn encode(self) -> Value {
        self.map_or(Value::Null, Encode::encode)
    }
}
impl<T: Encode + Clone> Encode for &T {
    fn encode(self) -> Value {
        self.clone().encode()
    }
}

/// What a column can be read as.
pub trait Decode: Sized {
    fn decode(v: Value) -> Result<Self>;
}

fn mismatch<T>(what: &str, v: &Value) -> Result<T> {
    Err(decode_error(format!("expected {what}, found {v:?}")))
}

macro_rules! decode_int {
    ($($t:ty),*) => {$(
        impl Decode for $t {
            fn decode(v: Value) -> Result<Self> {
                match v {
                    Value::Integer(n) => <$t>::try_from(n).map_err(|_| decode_error(format!("{n} does not fit {}", stringify!($t)))),
                    other => mismatch("an integer", &other),
                }
            }
        }
    )*};
}
decode_int!(i64, i32, u32, u8, u16, u64, usize);

impl Decode for bool {
    fn decode(v: Value) -> Result<Self> {
        match v {
            Value::Integer(n) => Ok(n != 0),
            other => mismatch("a boolean (0 or 1)", &other),
        }
    }
}
impl Decode for f64 {
    fn decode(v: Value) -> Result<Self> {
        match v {
            Value::Real(x) => Ok(x),
            #[allow(clippy::cast_precision_loss)]
            Value::Integer(n) => Ok(n as f64),
            other => mismatch("a number", &other),
        }
    }
}
impl Decode for String {
    fn decode(v: Value) -> Result<Self> {
        match v {
            Value::Text(s) => Ok(s),
            other => mismatch("text", &other),
        }
    }
}
impl Decode for Vec<u8> {
    fn decode(v: Value) -> Result<Self> {
        match v {
            Value::Blob(b) => Ok(b),
            Value::Text(s) => Ok(s.into_bytes()),
            other => mismatch("a blob", &other),
        }
    }
}
impl<T: Decode> Decode for Option<T> {
    fn decode(v: Value) -> Result<Self> {
        match v {
            Value::Null => Ok(None),
            other => T::decode(other).map(Some),
        }
    }
}

/// One result row.
pub struct Row(Vec<Value>);

impl Row {
    /// Column `i`, converted.
    pub fn get<T: Decode>(&self, i: usize) -> Result<T> {
        let v = self
            .0
            .get(i)
            .cloned()
            .ok_or_else(|| decode_error(format!("no column {i}")))?;
        T::decode(v)
    }
}

/// A row as a Rust value: a tuple of columns.
pub trait FromRow: Sized {
    fn from_row(row: &Row) -> Result<Self>;
}

macro_rules! tuple_from_row {
    ($(($($n:tt $t:ident),+)),+) => {$(
        impl<$($t: Decode),+> FromRow for ($($t,)+) {
            fn from_row(row: &Row) -> Result<Self> { Ok(($(row.get::<$t>($n)?,)+)) }
        }
    )+};
}
tuple_from_row!(
    (0 A),
    (0 A, 1 B),
    (0 A, 1 B, 2 C),
    (0 A, 1 B, 2 C, 3 D),
    (0 A, 1 B, 2 C, 3 D, 4 E),
    (0 A, 1 B, 2 C, 3 D, 4 E, 5 F),
    (0 A, 1 B, 2 C, 3 D, 4 E, 5 F, 6 G),
    (0 A, 1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H),
    (0 A, 1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I),
    (0 A, 1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J),
    (0 A, 1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K),
    (0 A, 1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L),
    (0 A, 1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M),
    (0 A, 1 B, 2 C, 3 D, 4 E, 5 F, 6 G, 7 H, 8 I, 9 J, 10 K, 11 L, 12 M, 13 N)
);

// ---- connections --------------------------------------------------------------------------

/// A connection held for as long as the value lives (a write connection, or inside a [`Tx`]).
pub struct Conn(OwnedMutexGuard<turso::Connection>);

impl Deref for Conn {
    type Target = turso::Connection;
    fn deref(&self) -> &turso::Connection {
        &self.0
    }
}

/// Runs statements. Implemented for [`Pool`] and [`Conn`].
pub trait Executor {
    fn run(
        self,
        sql: &str,
        params: Vec<Value>,
        want_rows: bool,
    ) -> impl Future<Output = Result<(u64, Vec<Row>)>> + Send;
}

async fn run_on(
    conn: &turso::Connection,
    sql: &str,
    params: Vec<Value>,
    want_rows: bool,
) -> Result<(u64, Vec<Row>)> {
    if !want_rows {
        let n = conn.execute(sql, params).await?;
        return Ok((n, Vec::new()));
    }
    let mut rows = conn.query(sql, params).await?;
    let mut out = Vec::new();
    while let Some(r) = rows.next().await? {
        let mut v = Vec::with_capacity(r.column_count());
        for i in 0..r.column_count() {
            v.push(r.get_value(i)?);
        }
        out.push(Row(v));
    }
    Ok((0, out))
}

impl Executor for &mut Conn {
    fn run(
        self,
        sql: &str,
        params: Vec<Value>,
        want_rows: bool,
    ) -> impl Future<Output = Result<(u64, Vec<Row>)>> + Send {
        let sql = sql.to_owned();
        async move { run_on(&self.0, &sql, params, want_rows).await }
    }
}

/// Does this statement change anything? Decided by its first keyword (`WITH` by what follows).
fn is_write(sql: &str) -> bool {
    let s = sql.trim_start();
    let word: String = s
        .chars()
        .take_while(char::is_ascii_alphabetic)
        .collect::<String>()
        .to_ascii_uppercase();
    match word.as_str() {
        "SELECT" | "VALUES" => false,
        "WITH" => {
            let u = s.to_ascii_uppercase();
            u.contains("INSERT ") || u.contains("UPDATE ") || u.contains("DELETE ")
        }
        _ => true,
    }
}

const READERS: usize = 4;

struct PoolInner {
    writer: Arc<Mutex<turso::Connection>>,
    readers: Vec<Arc<Mutex<turso::Connection>>>,
    next: AtomicUsize,
    // keeps the engine alive for as long as the connections are used
    _db: turso::Database,
}

/// The database: one writer and a few readers.
#[derive(Clone)]
pub struct Pool(Arc<PoolInner>);

async fn open_connection(db: &turso::Database) -> Result<turso::Connection> {
    let conn = db.connect()?;
    conn.busy_timeout(std::time::Duration::from_secs(5))?;
    for pragma in ["PRAGMA foreign_keys = ON", "PRAGMA synchronous = FULL"] {
        // these answer with no rows
        conn.query(pragma, ()).await?;
    }
    Ok(conn)
}

impl Pool {
    /// Opens (and creates, if needed) the database file at `path`, in WAL mode.
    pub async fn open(path: &str) -> Result<Self> {
        let db = turso::Builder::new_local(path).build().await?;
        let writer = open_connection(&db).await?;
        writer.query("PRAGMA journal_mode = WAL", ()).await?;
        let mut readers = Vec::with_capacity(READERS);
        for _ in 0..READERS {
            readers.push(Arc::new(Mutex::new(open_connection(&db).await?)));
        }
        Ok(Pool(Arc::new(PoolInner {
            writer: Arc::new(Mutex::new(writer)),
            readers,
            next: AtomicUsize::new(0),
            _db: db,
        })))
    }

    /// The write connection, for as long as the returned value lives.
    pub async fn writer(&self) -> Conn {
        Conn(Arc::clone(&self.0.writer).lock_owned().await)
    }

    /// A connection for a series of reads (it never changes anything).
    pub async fn acquire(&self) -> Result<Conn> {
        Ok(self.reader().await)
    }

    async fn reader(&self) -> Conn {
        let n = self.0.readers.len();
        let start = self.0.next.fetch_add(1, Ordering::Relaxed);
        for i in 0..n {
            if let Ok(g) = Arc::clone(&self.0.readers[(start + i) % n]).try_lock_owned() {
                return Conn(g);
            }
        }
        Conn(Arc::clone(&self.0.readers[start % n]).lock_owned().await)
    }

    /// Starts a write transaction (`BEGIN IMMEDIATE`): the write lock is held until it ends.
    pub async fn begin(&self) -> Result<Tx> {
        let conn = self.writer().await;
        conn.execute("BEGIN IMMEDIATE", ()).await?;
        Ok(Tx(Some(conn)))
    }

    /// Releases the connections (they close when the last user is done).
    pub async fn close(&self) {
        let w = self.writer().await;
        // a last checkpoint, so the file alone holds everything
        let _ = w.query("PRAGMA wal_checkpoint(TRUNCATE)", ()).await;
    }
}

impl Executor for &Pool {
    fn run(
        self,
        sql: &str,
        params: Vec<Value>,
        want_rows: bool,
    ) -> impl Future<Output = Result<(u64, Vec<Row>)>> + Send {
        let sql = sql.to_owned();
        async move {
            let conn = if is_write(&sql) {
                self.writer().await
            } else {
                self.reader().await
            };
            run_on(&conn.0, &sql, params, want_rows).await
        }
    }
}

/// A write transaction. Ending it without [`commit`](Tx::commit) rolls it back.
pub struct Tx(Option<Conn>);

impl Tx {
    pub async fn commit(mut self) -> Result<()> {
        let conn = self.0.take().expect("transaction in use");
        conn.execute("COMMIT", ()).await?;
        Ok(())
    }

    pub async fn rollback(mut self) -> Result<()> {
        let conn = self.0.take().expect("transaction in use");
        conn.execute("ROLLBACK", ()).await?;
        Ok(())
    }
}

impl Deref for Tx {
    type Target = Conn;
    fn deref(&self) -> &Conn {
        self.0.as_ref().expect("transaction in use")
    }
}

impl DerefMut for Tx {
    fn deref_mut(&mut self) -> &mut Conn {
        self.0.as_mut().expect("transaction in use")
    }
}

impl Drop for Tx {
    fn drop(&mut self) {
        // not committed: undo it, and keep the write lock until that is done
        if let Some(conn) = self.0.take() {
            if let Ok(rt) = tokio::runtime::Handle::try_current() {
                rt.spawn(async move {
                    let _ = conn.execute("ROLLBACK", ()).await;
                });
            }
        }
    }
}

// ---- queries ------------------------------------------------------------------------------

/// A statement with its parameters.
pub struct Query {
    sql: String,
    params: Vec<Value>,
}

/// Outcome of a statement that changes rows.
pub struct Done {
    rows: u64,
}

impl Done {
    pub fn rows_affected(&self) -> u64 {
        self.rows
    }
}

pub fn query(sql: impl AsRef<str>) -> Query {
    Query {
        sql: sql.as_ref().to_owned(),
        params: Vec::new(),
    }
}

impl Query {
    pub fn bind(mut self, v: impl Encode) -> Self {
        self.params.push(v.encode());
        self
    }

    pub async fn execute(self, e: impl Executor) -> Result<Done> {
        let (rows, _) = e.run(&self.sql, self.params, false).await?;
        Ok(Done { rows })
    }
}

/// Rows decoded as `T`.
pub struct QueryAs<T> {
    q: Query,
    _t: std::marker::PhantomData<fn() -> T>,
}

pub fn query_as<T: FromRow>(sql: impl AsRef<str>) -> QueryAs<T> {
    QueryAs {
        q: query(sql),
        _t: std::marker::PhantomData,
    }
}

impl<T: FromRow> QueryAs<T> {
    pub fn bind(mut self, v: impl Encode) -> Self {
        self.q = self.q.bind(v);
        self
    }

    pub async fn fetch_all(self, e: impl Executor) -> Result<Vec<T>> {
        let (_, rows) = e.run(&self.q.sql, self.q.params, true).await?;
        rows.iter().map(T::from_row).collect()
    }

    pub async fn fetch_optional(self, e: impl Executor) -> Result<Option<T>> {
        let (_, rows) = e.run(&self.q.sql, self.q.params, true).await?;
        rows.first().map(T::from_row).transpose()
    }

    pub async fn fetch_one(self, e: impl Executor) -> Result<T> {
        self.fetch_optional(e)
            .await?
            .ok_or_else(|| Error(turso::Error::QueryReturnedNoRows))
    }
}

/// The first column of each row, decoded as `T`.
pub struct QueryScalar<T> {
    q: Query,
    _t: std::marker::PhantomData<fn() -> T>,
}

pub fn query_scalar<T: Decode>(sql: impl AsRef<str>) -> QueryScalar<T> {
    QueryScalar {
        q: query(sql),
        _t: std::marker::PhantomData,
    }
}

impl<T: Decode> QueryScalar<T> {
    pub fn bind(mut self, v: impl Encode) -> Self {
        self.q = self.q.bind(v);
        self
    }

    pub async fn fetch_all(self, e: impl Executor) -> Result<Vec<T>> {
        let (_, rows) = e.run(&self.q.sql, self.q.params, true).await?;
        rows.iter().map(|r| r.get::<T>(0)).collect()
    }

    pub async fn fetch_optional(self, e: impl Executor) -> Result<Option<T>> {
        let (_, rows) = e.run(&self.q.sql, self.q.params, true).await?;
        rows.first().map(|r| r.get::<T>(0)).transpose()
    }

    pub async fn fetch_one(self, e: impl Executor) -> Result<T> {
        self.fetch_optional(e)
            .await?
            .ok_or_else(|| Error(turso::Error::QueryReturnedNoRows))
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn statements_are_sorted_into_reads_and_writes() {
        for (sql, write) in [
            ("SELECT 1", false),
            ("  select * from t", false),
            ("VALUES (1)", false),
            ("WITH RECURSIVE n(x) AS (SELECT 1) SELECT x FROM n", false),
            (
                "WITH x AS (SELECT 1) DELETE FROM t WHERE id IN (SELECT * FROM x)",
                true,
            ),
            ("INSERT INTO t VALUES (1)", true),
            ("UPDATE t SET a = 1 RETURNING a", true),
            ("DELETE FROM t", true),
            ("PRAGMA journal_mode", true),
            ("CREATE TABLE t (a)", true),
        ] {
            assert_eq!(is_write(sql), write, "{sql}");
        }
    }
}
