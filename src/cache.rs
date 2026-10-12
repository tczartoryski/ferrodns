//! RRset cache with trust ranking (RFC 2181 §5.4.1), negative caching
//! (RFC 2308) and NXDOMAIN-cut semantics (RFC 8020).

use crate::wire::{Name, RData, RType, Record};
use std::collections::HashMap;
use std::net::IpAddr;
use std::time::Instant;

/// How much we trust a cached RRset. Higher ranks are never overwritten by lower
/// ranks while still alive, which blocks the classic "glue overwrites answer"
/// poisoning path.
#[derive(Clone, Copy, PartialEq, Eq, PartialOrd, Ord, Debug)]
pub enum Trust {
    /// Address records from the additional section of a referral.
    Glue,
    /// NS records from the authority section of a referral, or non-authoritative data.
    Referral,
    /// Data from the answer section of an authoritative response.
    AuthAnswer,
}

#[derive(Clone, Debug)]
pub struct CacheConfig {
    pub max_entries: usize,
    pub max_ttl: u32,
    pub max_negative_ttl: u32,
}

impl Default for CacheConfig {
    fn default() -> Self {
        CacheConfig {
            max_entries: 100_000,
            max_ttl: 86_400,
            max_negative_ttl: 10_800,
        }
    }
}

struct Entry<T> {
    value: T,
    inserted: Instant,
    ttl: u32,
}

impl<T> Entry<T> {
    fn remaining(&self, now: Instant) -> Option<u32> {
        let age = now.saturating_duration_since(self.inserted).as_secs();
        (age < self.ttl as u64).then(|| self.ttl - age as u32)
    }
}

struct RRset {
    records: Vec<Record>,
    trust: Trust,
}

/// Result of a cache lookup for a client question.
#[derive(Debug, Clone, PartialEq)]
pub enum Lookup {
    Hit(Vec<Record>),
    NxDomain(Option<Record>),
    NoData(Option<Record>),
}

#[derive(Debug, Default, Clone, Copy)]
pub struct CacheStats {
    pub hits: u64,
    pub misses: u64,
    pub inserts: u64,
    pub evictions: u64,
}

pub struct Cache {
    cfg: CacheConfig,
    rrsets: HashMap<(Name, RType), Entry<RRset>>,
    nodata: HashMap<(Name, RType), Entry<Option<Record>>>,
    nxdomain: HashMap<Name, Entry<Option<Record>>>,
    pub stats: CacheStats,
}

fn with_ttl(records: &[Record], ttl: u32) -> Vec<Record> {
    records
        .iter()
        .map(|r| Record { ttl, ..r.clone() })
        .collect()
}

impl Cache {
    pub fn new(cfg: CacheConfig) -> Cache {
        Cache {
            cfg,
            rrsets: HashMap::new(),
            nodata: HashMap::new(),
            nxdomain: HashMap::new(),
            stats: CacheStats::default(),
        }
    }

    pub fn len(&self) -> usize {
        self.rrsets.len() + self.nodata.len() + self.nxdomain.len()
    }

    pub fn is_empty(&self) -> bool {
        self.len() == 0
    }

    /// Answer a client question from cache, if possible.
    pub fn lookup(&mut self, name: &Name, rtype: RType, now: Instant) -> Option<Lookup> {
        // RFC 8020: an NXDOMAIN at a name means nothing exists below it either.
        for anc in name.self_and_ancestors() {
            if let Some(e) = self.nxdomain.get(&anc)
                && let Some(left) = e.remaining(now)
            {
                self.stats.hits += 1;
                return Some(Lookup::NxDomain(e.value.as_ref().map(|s| Record {
                    ttl: left,
                    ..s.clone()
                })));
            }
        }
        if let Some(recs) = self.get_rrset(name, rtype, Trust::AuthAnswer, now) {
            self.stats.hits += 1;
            return Some(Lookup::Hit(recs));
        }
        if let Some(e) = self.nodata.get(&(name.clone(), rtype))
            && let Some(left) = e.remaining(now)
        {
            self.stats.hits += 1;
            return Some(Lookup::NoData(e.value.as_ref().map(|s| Record {
                ttl: left,
                ..s.clone()
            })));
        }
        self.stats.misses += 1;
        None
    }

    /// Fetch a live RRset with at least `min_trust`, TTLs rewritten to time remaining.
    pub fn get_rrset(
        &self,
        name: &Name,
        rtype: RType,
        min_trust: Trust,
        now: Instant,
    ) -> Option<Vec<Record>> {
        let e = self.rrsets.get(&(name.clone(), rtype))?;
        let left = e.remaining(now)?;
        (e.value.trust >= min_trust).then(|| with_ttl(&e.value.records, left))
    }

    /// Insert one RRset (all records must share owner and type).
    pub fn insert_rrset(&mut self, records: Vec<Record>, trust: Trust, now: Instant) {
        let Some(first) = records.first() else { return };
        let key = (first.name.clone(), first.rtype);
        let ttl = records
            .iter()
            .map(|r| r.ttl)
            .min()
            .unwrap_or(0)
            .min(self.cfg.max_ttl);
        if ttl == 0 {
            return;
        }
        if let Some(existing) = self.rrsets.get(&key)
            && existing.remaining(now).is_some()
            && existing.value.trust > trust
        {
            return;
        }
        // Fresh positive data invalidates negative entries that contradict it.
        self.nodata.remove(&key);
        for anc in key.0.self_and_ancestors() {
            self.nxdomain.remove(&anc);
        }
        self.make_room(now);
        self.rrsets.insert(
            key,
            Entry {
                value: RRset { records, trust },
                inserted: now,
                ttl,
            },
        );
        self.stats.inserts += 1;
    }

    /// Cache a negative answer. Per RFC 2308 the TTL is min(SOA TTL, SOA MINIMUM);
    /// without an SOA we don't cache at all.
    pub fn insert_negative(
        &mut self,
        name: &Name,
        rtype: RType,
        nxdomain: bool,
        soa: Option<Record>,
        now: Instant,
    ) {
        let Some(ttl) = soa
            .as_ref()
            .and_then(|r| r.soa().map(|s| r.ttl.min(s.minimum)))
        else {
            return;
        };
        let ttl = ttl.min(self.cfg.max_negative_ttl);
        if ttl == 0 {
            return;
        }
        self.make_room(now);
        let e = Entry {
            value: soa,
            inserted: now,
            ttl,
        };
        if nxdomain {
            self.nxdomain.insert(name.clone(), e);
        } else {
            self.nodata.insert((name.clone(), rtype), e);
        }
        self.stats.inserts += 1;
    }

    /// The deepest cached delegation (zone, NS names) covering `name`.
    pub fn delegation(&self, name: &Name, now: Instant) -> Option<(Name, Vec<Name>)> {
        name.self_and_ancestors().into_iter().find_map(|zone| {
            let ns = self.get_rrset(&zone, RType::NS, Trust::Glue, now)?;
            let names: Vec<Name> = ns.iter().filter_map(|r| r.target().cloned()).collect();
            (!names.is_empty()).then_some((zone, names))
        })
    }

    /// Cached addresses for a nameserver name (any trust level).
    pub fn addresses(&self, name: &Name, ipv6: bool, now: Instant) -> Vec<IpAddr> {
        let mut out = Vec::new();
        let types: &[RType] = if ipv6 {
            &[RType::A, RType::AAAA]
        } else {
            &[RType::A]
        };
        for &t in types {
            for r in self
                .get_rrset(name, t, Trust::Glue, now)
                .unwrap_or_default()
            {
                match r.data {
                    RData::A(ip) => out.push(IpAddr::V4(ip)),
                    RData::Aaaa(ip) => out.push(IpAddr::V6(ip)),
                    _ => {}
                }
            }
        }
        out
    }

    fn make_room(&mut self, now: Instant) {
        if self.len() < self.cfg.max_entries {
            return;
        }
        let before = self.len();
        self.rrsets.retain(|_, e| e.remaining(now).is_some());
        self.nodata.retain(|_, e| e.remaining(now).is_some());
        self.nxdomain.retain(|_, e| e.remaining(now).is_some());
        // Still full of live data: drop an arbitrary tenth. (LRU is on the roadmap.)
        let target = self.cfg.max_entries * 9 / 10;
        if self.len() >= self.cfg.max_entries {
            let drop: Vec<_> = self
                .rrsets
                .keys()
                .take(self.len().saturating_sub(target))
                .cloned()
                .collect();
            for k in drop {
                self.rrsets.remove(&k);
            }
        }
        self.stats.evictions += (before - self.len()) as u64;
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Soa;
    use std::net::Ipv4Addr;
    use std::time::Duration;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn a(name: &str, ttl: u32, last: u8) -> Record {
        Record::new(n(name), ttl, RData::A(Ipv4Addr::new(192, 0, 2, last)))
    }

    fn soa(zone: &str, ttl: u32, minimum: u32) -> Record {
        Record::new(
            n(zone),
            ttl,
            RData::Soa(Soa {
                mname: n("ns.example"),
                rname: n("h.example"),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum,
            }),
        )
    }

    #[test]
    fn ttl_counts_down_and_expires() {
        let mut c = Cache::new(CacheConfig::default());
        let t0 = Instant::now();
        c.insert_rrset(vec![a("www.example", 60, 1)], Trust::AuthAnswer, t0);
        let Some(Lookup::Hit(r)) =
            c.lookup(&n("www.example"), RType::A, t0 + Duration::from_secs(20))
        else {
            panic!()
        };
        assert_eq!(r[0].ttl, 40);
        assert!(
            c.lookup(&n("www.example"), RType::A, t0 + Duration::from_secs(61))
                .is_none()
        );
    }

    #[test]
    fn glue_cannot_overwrite_answer() {
        let mut c = Cache::new(CacheConfig::default());
        let t0 = Instant::now();
        c.insert_rrset(vec![a("ns1.example", 300, 1)], Trust::AuthAnswer, t0);
        c.insert_rrset(vec![a("ns1.example", 300, 66)], Trust::Glue, t0);
        let Some(Lookup::Hit(r)) = c.lookup(&n("ns1.example"), RType::A, t0) else {
            panic!()
        };
        assert_eq!(r[0].data, RData::A(Ipv4Addr::new(192, 0, 2, 1)));
    }

    #[test]
    fn glue_is_not_served_as_an_answer() {
        let mut c = Cache::new(CacheConfig::default());
        let t0 = Instant::now();
        c.insert_rrset(vec![a("ns1.example", 300, 1)], Trust::Glue, t0);
        assert!(c.lookup(&n("ns1.example"), RType::A, t0).is_none());
        assert_eq!(c.addresses(&n("ns1.example"), false, t0).len(), 1);
    }

    #[test]
    fn negative_ttl_uses_soa_minimum_and_rfc8020() {
        let mut c = Cache::new(CacheConfig::default());
        let t0 = Instant::now();
        c.insert_negative(
            &n("nope.example"),
            RType::A,
            true,
            Some(soa("example", 3600, 30)),
            t0,
        );
        assert!(matches!(
            c.lookup(&n("nope.example"), RType::AAAA, t0),
            Some(Lookup::NxDomain(_))
        ));
        // RFC 8020: names below an NXDOMAIN are NXDOMAIN too.
        assert!(matches!(
            c.lookup(&n("deep.nope.example"), RType::A, t0),
            Some(Lookup::NxDomain(_))
        ));
        assert!(
            c.lookup(&n("nope.example"), RType::A, t0 + Duration::from_secs(31))
                .is_none()
        );
        // No SOA, no negative caching.
        c.insert_negative(&n("x.example"), RType::A, false, None, t0);
        assert!(c.lookup(&n("x.example"), RType::A, t0).is_none());
    }

    #[test]
    fn delegation_finds_deepest_zone() {
        let mut c = Cache::new(CacheConfig::default());
        let t0 = Instant::now();
        let ns = |zone: &str, target: &str| Record::new(n(zone), 3600, RData::Ns(n(target)));
        c.insert_rrset(vec![ns("example", "a.ns.example")], Trust::Referral, t0);
        c.insert_rrset(vec![ns("sub.example", "b.ns.example")], Trust::Referral, t0);
        let (zone, names) = c.delegation(&n("www.sub.example"), t0).unwrap();
        assert_eq!(zone, n("sub.example"));
        assert_eq!(names, vec![n("b.ns.example")]);
    }

    #[test]
    fn eviction_bounds_size() {
        let mut c = Cache::new(CacheConfig {
            max_entries: 100,
            ..Default::default()
        });
        let t0 = Instant::now();
        for i in 0..1000 {
            c.insert_rrset(
                vec![a(&format!("h{i}.example"), 300, 1)],
                Trust::AuthAnswer,
                t0,
            );
        }
        assert!(c.len() <= 100);
        assert!(c.stats.evictions > 0);
    }
}
