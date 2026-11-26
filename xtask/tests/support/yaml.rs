//! Lot M3 (OpenSSF Scorecard, Vulnerabilities): the tests' reader of the
//! committed YAML (the workflows, dependabot.yml, the issue forms,
//! secret_scanning.yml).
//!
//! serde_yaml_ng 0.10 read them before, through unsafe-libyaml 0.2.11, a
//! machine translation of libyaml's C into unsafe Rust, archived upstream
//! (RUSTSEC-2024-0449, unmaintained: the `.cargo/audit.toml` exception it
//! needed, and one of the two "existing vulnerabilities" Scorecard counted).
//! serde-saphyr, a YAML parser in safe Rust (the advisory's suggestion),
//! parses now; this module holds the tree the tests walk, with the part of
//! serde_yaml_ng's `Value` they used, under the same names.
//!
//! It reads YAML as serde_yaml_ng did, on these points ([`options`]; each
//! is pinned by `xtask/tests/yaml_reader.rs`):
//! - only `true` and `false` (any case serde_yaml_ng took: `True`, `TRUE`)
//!   are booleans: `on:`, a workflow's trigger key, stays the string `on`
//!   (YAML 1.1 read `on`, `yes`, `off` as booleans; serde-saphyr does by
//!   default);
//! - a number spelled with a leading zero (`0755`) or an underscore
//!   (`1_000`) is a string, as serde_yaml_ng kept it;
//! - a mapping keeps its keys in their order, and a key given twice
//!   refuses the file;
//! - a merge key (`<<`) refuses the file: serde_yaml_ng kept it as an
//!   ordinary key, a tree no runner reads; no committed file has one.

use serde::de::{Deserialize, Deserializer, MapAccess, SeqAccess, Visitor};
use serde::ser::{Serialize, SerializeMap, SerializeSeq, Serializer};
use std::fmt;
use std::ops;

/// The error of [`from_str`].
pub type Error = serde_saphyr::Error;

/// A YAML sequence.
pub type Sequence = Vec<Value>;

/// One YAML node.
#[derive(Clone, Debug, Default, PartialEq)]
pub enum Value {
    /// `null`, `~` or an empty value.
    #[default]
    Null,
    Bool(bool),
    Number(Number),
    String(String),
    Sequence(Sequence),
    Mapping(Mapping),
}

/// A YAML number, printed as serde_yaml_ng printed it.
#[derive(Clone, Copy, Debug, PartialEq)]
pub enum Number {
    PosInt(u64),
    NegInt(i64),
    Float(f64),
}

impl fmt::Display for Number {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match *self {
            Number::PosInt(n) => write!(f, "{n}"),
            Number::NegInt(n) => write!(f, "{n}"),
            Number::Float(x) if x.is_nan() => f.write_str(".nan"),
            Number::Float(x) if x.is_infinite() => {
                f.write_str(if x > 0.0 { ".inf" } else { "-.inf" })
            }
            // `1.0`, not `1` (Display's): the shortest spelling that reads
            // back as the same float, as serde_yaml_ng's
            Number::Float(x) => write!(f, "{x:?}"),
        }
    }
}

/// A YAML mapping: its entries in the order the text gives them.
#[derive(Clone, Debug, Default, PartialEq)]
pub struct Mapping {
    entries: Vec<(Value, Value)>,
}

/// What [`Value::get`] and [`Mapping::get`] look up: a key (`&str`,
/// `String`, a [`Value`]) or a sequence index (`usize`).
pub trait Index {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value>;
    fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value>;
    /// The mapping key this index names, if it names one.
    fn key(&self) -> Option<Value>;
}

impl Index for usize {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        v.as_sequence()?.get(*self)
    }
    fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
        v.as_sequence_mut()?.get_mut(*self)
    }
    fn key(&self) -> Option<Value> {
        None
    }
}

impl Index for str {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        v.as_mapping()?.get(self)
    }
    fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
        v.as_mapping_mut()?.get_mut(self)
    }
    fn key(&self) -> Option<Value> {
        Some(Value::String(self.to_string()))
    }
}

impl Index for String {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        self.as_str().index_into(v)
    }
    fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
        self.as_str().index_into_mut(v)
    }
    fn key(&self) -> Option<Value> {
        self.as_str().key()
    }
}

impl Index for Value {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        match self {
            Value::Number(Number::PosInt(i)) if v.is_sequence() => {
                usize::try_from(*i).ok()?.index_into(v)
            }
            _ => v.as_mapping()?.get(self),
        }
    }
    fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
        match self {
            Value::Number(Number::PosInt(i)) if v.is_sequence() => {
                usize::try_from(*i).ok()?.index_into_mut(v)
            }
            _ => v.as_mapping_mut()?.get_mut(self),
        }
    }
    fn key(&self) -> Option<Value> {
        Some(self.clone())
    }
}

impl<T: Index + ?Sized> Index for &T {
    fn index_into<'v>(&self, v: &'v Value) -> Option<&'v Value> {
        (**self).index_into(v)
    }
    fn index_into_mut<'v>(&self, v: &'v mut Value) -> Option<&'v mut Value> {
        (**self).index_into_mut(v)
    }
    fn key(&self) -> Option<Value> {
        (**self).key()
    }
}

impl Mapping {
    pub fn new() -> Self {
        Self::default()
    }
    fn position<I: Index + ?Sized>(&self, key: &I) -> Option<usize> {
        let key = key.key()?;
        self.entries.iter().position(|(k, _)| *k == key)
    }
    pub fn get<I: Index>(&self, key: I) -> Option<&Value> {
        self.position(&key).map(|i| &self.entries[i].1)
    }
    pub fn get_mut<I: Index>(&mut self, key: I) -> Option<&mut Value> {
        self.position(&key).map(|i| &mut self.entries[i].1)
    }
    pub fn contains_key<I: Index>(&self, key: I) -> bool {
        self.position(&key).is_some()
    }
    /// Sets `key` to `value`: in its place if the key is there (the old
    /// value returned), last otherwise.
    pub fn insert(&mut self, key: Value, value: Value) -> Option<Value> {
        match self.entries.iter_mut().find(|(k, _)| *k == key) {
            Some((_, v)) => Some(std::mem::replace(v, value)),
            None => {
                self.entries.push((key, value));
                None
            }
        }
    }
    pub fn len(&self) -> usize {
        self.entries.len()
    }
    pub fn is_empty(&self) -> bool {
        self.entries.is_empty()
    }
    pub fn iter(&self) -> impl Iterator<Item = (&Value, &Value)> {
        self.entries.iter().map(|(k, v)| (k, v))
    }
    pub fn iter_mut(&mut self) -> impl Iterator<Item = (&Value, &mut Value)> {
        self.entries.iter_mut().map(|(k, v)| (&*k, v))
    }
    pub fn keys(&self) -> impl Iterator<Item = &Value> {
        self.entries.iter().map(|(k, _)| k)
    }
    pub fn values(&self) -> impl Iterator<Item = &Value> {
        self.entries.iter().map(|(_, v)| v)
    }
}

impl<'a> IntoIterator for &'a Mapping {
    type Item = (&'a Value, &'a Value);
    type IntoIter = std::iter::Map<
        std::slice::Iter<'a, (Value, Value)>,
        fn(&'a (Value, Value)) -> (&'a Value, &'a Value),
    >;
    fn into_iter(self) -> Self::IntoIter {
        self.entries.iter().map(|(k, v)| (k, v))
    }
}

impl Value {
    pub fn get<I: Index>(&self, index: I) -> Option<&Value> {
        index.index_into(self)
    }
    pub fn get_mut<I: Index>(&mut self, index: I) -> Option<&mut Value> {
        index.index_into_mut(self)
    }
    pub fn is_null(&self) -> bool {
        matches!(self, Value::Null)
    }
    pub fn is_string(&self) -> bool {
        matches!(self, Value::String(_))
    }
    pub fn is_sequence(&self) -> bool {
        matches!(self, Value::Sequence(_))
    }
    pub fn is_mapping(&self) -> bool {
        matches!(self, Value::Mapping(_))
    }
    pub fn as_str(&self) -> Option<&str> {
        match self {
            Value::String(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_bool(&self) -> Option<bool> {
        match self {
            Value::Bool(b) => Some(*b),
            _ => None,
        }
    }
    pub fn as_u64(&self) -> Option<u64> {
        match self {
            Value::Number(Number::PosInt(n)) => Some(*n),
            Value::Number(Number::NegInt(n)) => u64::try_from(*n).ok(),
            _ => None,
        }
    }
    pub fn as_i64(&self) -> Option<i64> {
        match self {
            Value::Number(Number::PosInt(n)) => i64::try_from(*n).ok(),
            Value::Number(Number::NegInt(n)) => Some(*n),
            _ => None,
        }
    }
    pub fn as_f64(&self) -> Option<f64> {
        match self {
            Value::Number(Number::PosInt(n)) => Some(*n as f64),
            Value::Number(Number::NegInt(n)) => Some(*n as f64),
            Value::Number(Number::Float(x)) => Some(*x),
            _ => None,
        }
    }
    pub fn as_sequence(&self) -> Option<&Sequence> {
        match self {
            Value::Sequence(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_sequence_mut(&mut self) -> Option<&mut Sequence> {
        match self {
            Value::Sequence(s) => Some(s),
            _ => None,
        }
    }
    pub fn as_mapping(&self) -> Option<&Mapping> {
        match self {
            Value::Mapping(m) => Some(m),
            _ => None,
        }
    }
    pub fn as_mapping_mut(&mut self) -> Option<&mut Mapping> {
        match self {
            Value::Mapping(m) => Some(m),
            _ => None,
        }
    }
}

static NULL: Value = Value::Null;

/// `value["key"]`, `value[0]`: the node, or `Null` when there is none (as
/// serde_yaml_ng's).
impl<I: Index> ops::Index<I> for Value {
    type Output = Value;
    fn index(&self, index: I) -> &Value {
        index.index_into(self).unwrap_or(&NULL)
    }
}

impl From<&str> for Value {
    fn from(s: &str) -> Self {
        Value::String(s.to_string())
    }
}

impl From<String> for Value {
    fn from(s: String) -> Self {
        Value::String(s)
    }
}

impl From<bool> for Value {
    fn from(b: bool) -> Self {
        Value::Bool(b)
    }
}

impl PartialEq<str> for Value {
    fn eq(&self, other: &str) -> bool {
        self.as_str() == Some(other)
    }
}

impl PartialEq<&str> for Value {
    fn eq(&self, other: &&str) -> bool {
        self.as_str() == Some(*other)
    }
}

impl<'de> Deserialize<'de> for Value {
    fn deserialize<D: Deserializer<'de>>(d: D) -> Result<Self, D::Error> {
        struct V;
        impl<'de> Visitor<'de> for V {
            type Value = Value;
            fn expecting(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
                f.write_str("any YAML value")
            }
            fn visit_bool<E>(self, b: bool) -> Result<Value, E> {
                Ok(Value::Bool(b))
            }
            fn visit_i64<E>(self, n: i64) -> Result<Value, E> {
                Ok(Value::Number(if n < 0 {
                    Number::NegInt(n)
                } else {
                    Number::PosInt(n as u64)
                }))
            }
            fn visit_u64<E>(self, n: u64) -> Result<Value, E> {
                Ok(Value::Number(Number::PosInt(n)))
            }
            fn visit_f64<E>(self, x: f64) -> Result<Value, E> {
                Ok(Value::Number(Number::Float(x)))
            }
            fn visit_str<E>(self, s: &str) -> Result<Value, E> {
                Ok(Value::String(s.to_string()))
            }
            fn visit_string<E>(self, s: String) -> Result<Value, E> {
                Ok(Value::String(s))
            }
            fn visit_unit<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_none<E>(self) -> Result<Value, E> {
                Ok(Value::Null)
            }
            fn visit_some<D: Deserializer<'de>>(self, d: D) -> Result<Value, D::Error> {
                Value::deserialize(d)
            }
            fn visit_seq<A: SeqAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut out = Vec::new();
                while let Some(v) = a.next_element()? {
                    out.push(v);
                }
                Ok(Value::Sequence(out))
            }
            fn visit_map<A: MapAccess<'de>>(self, mut a: A) -> Result<Value, A::Error> {
                let mut m = Mapping::new();
                // a key given twice is refused before (`options`)
                while let Some((k, v)) = a.next_entry::<Value, Value>()? {
                    m.insert(k, v);
                }
                Ok(Value::Mapping(m))
            }
        }
        d.deserialize_any(V)
    }
}

impl Serialize for Value {
    fn serialize<S: Serializer>(&self, s: S) -> Result<S::Ok, S::Error> {
        match self {
            Value::Null => s.serialize_unit(),
            Value::Bool(b) => s.serialize_bool(*b),
            Value::Number(Number::PosInt(n)) => s.serialize_u64(*n),
            Value::Number(Number::NegInt(n)) => s.serialize_i64(*n),
            Value::Number(Number::Float(x)) => s.serialize_f64(*x),
            Value::String(t) => s.serialize_str(t),
            Value::Sequence(items) => {
                let mut seq = s.serialize_seq(Some(items.len()))?;
                for v in items {
                    seq.serialize_element(v)?;
                }
                seq.end()
            }
            Value::Mapping(m) => {
                let mut map = s.serialize_map(Some(m.len()))?;
                for (k, v) in m {
                    map.serialize_entry(k, v)?;
                }
                map.end()
            }
        }
    }
}

/// How the committed YAML is read (the module's head says why).
pub fn options() -> serde_saphyr::Options {
    let mut o = serde_saphyr::Options::default();
    o.strict_booleans = true;
    o.leading_zero_numbers_as_strings = true;
    o.underscored_numbers_as_strings = true;
    o.duplicate_keys = serde_saphyr::DuplicateKeyPolicy::Error;
    o.merge_keys = serde_saphyr::MergeKeyPolicy::Error;
    o
}

/// One YAML document as a tree.
pub fn from_str(text: &str) -> Result<Value, Error> {
    serde_saphyr::from_str_with_options(text, options())
}

/// A node written back as YAML: a string with a line break as a literal
/// block (`|`), its lines as they are, and no other string folded over
/// lines (serde_yaml_ng's, so a test's `contains` sees a line whole).
pub fn to_string(value: &Value) -> Result<String, serde_saphyr::SerializeError> {
    let mut opts = serde_saphyr::SerializerOptions::default();
    opts.prefer_block_scalars = true;
    // a single-line string is folded (`>`) past this many characters
    opts.folded_wrap_chars = usize::MAX;
    serde_saphyr::to_string_with_options(value, opts)
}
