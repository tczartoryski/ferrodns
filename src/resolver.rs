//! Iterative resolution: start at the deepest known delegation (or the root),
//! follow referrals down the tree, chase CNAMEs, and cache everything we're
//! allowed to trust along the way.

use crate::cache::{Cache, CacheConfig, Lookup, Trust};
use crate::hints::{self, Hint};
use crate::rng;
use crate::trace::{self, Event, Trace};
use crate::transport::{Transport, TransportError};
use crate::wire::{Edns, Message, Name, RClass, RData, RType, Record, rcode};
use std::collections::{HashMap, HashSet};
use std::fmt;
use std::net::{IpAddr, SocketAddr};
use std::path::PathBuf;
use std::sync::Mutex;
use std::sync::atomic::{AtomicU64, Ordering};
use std::time::{Duration, Instant};

/// EDNS UDP payload size we advertise (DNS Flag Day 2020 recommendation).
pub const EDNS_UDP_SIZE: u16 = 1232;

#[derive(Clone, Debug)]
pub struct Config {
    pub roots: Vec<Hint>,
    /// Destination port for upstream queries.
    pub port: u16,
    /// Explicit routes for a portable simulated network (never populated by default).
    pub endpoints: HashMap<IpAddr, SocketAddr>,
    pub timeout: Duration,
    pub ipv6: bool,
    /// Upstream queries allowed per client question (bounds work per request).
    pub max_queries: usize,
    /// Nesting limit for resolving glueless nameserver names.
    pub max_depth: usize,
    pub max_cname: usize,
    pub max_referrals: usize,
    pub cache: CacheConfig,
    /// Trace each request reaching the resolver (pre-resolution packet rejections are excluded).
    pub trace_dir: Option<PathBuf>,
}

impl Default for Config {
    fn default() -> Self {
        Config {
            roots: hints::internet_roots(false),
            port: 53,
            endpoints: HashMap::new(),
            timeout: Duration::from_millis(1500),
            ipv6: false,
            max_queries: 100,
            max_depth: 6,
            max_cname: 10,
            max_referrals: 20,
            cache: CacheConfig::default(),
            trace_dir: None,
        }
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum ResolveError {
    QueryBudgetExhausted,
    DepthExceeded,
    CnameLoop,
    TooManyReferrals,
    NoServers(Name),
    AllServersFailed(Name),
}

impl fmt::Display for ResolveError {
    fn fmt(&self, f: &mut fmt::Formatter<'_>) -> fmt::Result {
        match self {
            ResolveError::QueryBudgetExhausted => write!(f, "upstream query budget exhausted"),
            ResolveError::DepthExceeded => write!(f, "nameserver resolution nested too deeply"),
            ResolveError::CnameLoop => write!(f, "CNAME loop or chain too long"),
            ResolveError::TooManyReferrals => write!(f, "too many referrals"),
            ResolveError::NoServers(z) => write!(f, "no usable nameserver addresses for {z}"),
            ResolveError::AllServersFailed(z) => write!(f, "all nameservers for {z} failed"),
        }
    }
}

impl std::error::Error for ResolveError {}

/// The final answer for a client question.
#[derive(Debug, Clone, PartialEq)]
pub struct Resolution {
    pub rcode: u8,
    pub answers: Vec<Record>,
    pub authority: Vec<Record>,
}

#[derive(Default)]
pub struct Stats {
    pub client_queries: AtomicU64,
    pub upstream_queries: AtomicU64,
    pub upstream_failures: AtomicU64,
    pub tcp_fallbacks: AtomicU64,
}

/// Outcome of one step of resolution for one name.
enum Step {
    Answer(Vec<Record>),
    Cname(Record),
    NxDomain(Option<Record>),
    NoData(Option<Record>),
}

/// How we interpret one upstream response.
#[derive(Debug, Clone, PartialEq)]
pub enum Classified {
    Answer(Vec<Record>),
    Cname(Record),
    Referral {
        zone: Name,
        ns: Vec<Record>,
        glue: Vec<Record>,
    },
    NxDomain(Option<Record>),
    NoData(Option<Record>),
    /// Unusable response: try another server.
    Lame(String),
}

/// Per-request state: work budget and optional trace.
struct Ctx {
    budget: usize,
    trace: Option<Vec<Event>>,
    start: Instant,
}

impl Ctx {
    fn log(
        &mut self,
        kind: &'static str,
        depth: usize,
        name: &Name,
        qtype: RType,
        msg: impl FnOnce() -> String,
    ) {
        if let Some(t) = self.trace.as_mut() {
            t.push(Event {
                t_ms: self.start.elapsed().as_secs_f64() * 1000.0,
                dur_ms: 0.0,
                depth,
                kind,
                zone: None,
                server: None,
                ip: None,
                qname: name.to_string(),
                qtype: qtype.to_string(),
                transport: None,
                outcome: None,
                detail: msg(),
            });
        }
    }
}

struct Srtt {
    ms: f64,
    updated: Instant,
}

pub struct Resolver {
    cfg: Config,
    cache: Mutex<Cache>,
    transport: Transport,
    /// Smoothed RTT per nameserver address, used to prefer fast servers.
    srtt: Mutex<HashMap<IpAddr, Srtt>>,
    pub stats: Stats,
}

impl Resolver {
    pub fn new(cfg: Config) -> Resolver {
        Resolver {
            cache: Mutex::new(Cache::new(cfg.cache.clone())),
            transport: Transport {
                port: cfg.port,
                timeout: cfg.timeout,
                endpoints: cfg.endpoints.clone(),
            },
            srtt: Mutex::new(HashMap::new()),
            stats: Stats::default(),
            cfg,
        }
    }

    pub fn cache_len(&self) -> usize {
        self.cache.lock().unwrap().len()
    }

    pub fn cache_stats(&self) -> crate::cache::CacheStats {
        self.cache.lock().unwrap().stats
    }

    pub fn resolve(&self, name: &Name, qtype: RType) -> Result<Resolution, ResolveError> {
        self.resolve_traced(name, qtype, false).0
    }

    /// Resolve, optionally recording a human-readable trace of every step.
    pub fn resolve_traced(
        &self,
        name: &Name,
        qtype: RType,
        trace: bool,
    ) -> (Result<Resolution, ResolveError>, Vec<String>) {
        let (res, recorded) = self.resolve_recorded(name, qtype, trace);
        let text = if trace {
            recorded.events.iter().map(Event::text).collect()
        } else {
            vec![]
        };
        (res, text)
    }

    /// Record a structured trace, including failures, without repeating resolution.
    pub fn resolve_with_trace(
        &self,
        name: &Name,
        qtype: RType,
    ) -> (Result<Resolution, ResolveError>, Trace) {
        self.resolve_recorded(name, qtype, true)
    }

    fn resolve_recorded(
        &self,
        name: &Name,
        qtype: RType,
        record: bool,
    ) -> (Result<Resolution, ResolveError>, Trace) {
        self.stats.client_queries.fetch_add(1, Ordering::Relaxed);
        let started_at = trace::timestamp();
        let mut ctx = Ctx {
            budget: self.cfg.max_queries,
            trace: (record || self.cfg.trace_dir.is_some()).then(Vec::new),
            start: Instant::now(),
        };
        let res = self.resolve_inner(name, qtype, &mut ctx, 0);
        let trace = Trace {
            name: name.to_string(),
            qtype: qtype.to_string(),
            started_at,
            total_ms: ctx.start.elapsed().as_secs_f64() * 1000.0,
            rcode: rcode::name(res.as_ref().map_or(rcode::SERVFAIL, |r| r.rcode)).into(),
            answers: res
                .as_ref()
                .map(|r| r.answers.iter().map(ToString::to_string).collect())
                .unwrap_or_default(),
            events: ctx.trace.unwrap_or_default(),
        };
        if let Some(dir) = &self.cfg.trace_dir
            && let Err(e) = trace.write_in_dir(dir)
        {
            eprintln!("trace-dir {}: {e}", dir.display());
        }
        (res, trace)
    }

    fn resolve_inner(
        &self,
        name: &Name,
        qtype: RType,
        ctx: &mut Ctx,
        depth: usize,
    ) -> Result<Resolution, ResolveError> {
        let mut answers = Vec::new();
        let mut current = name.clone();
        let mut seen = HashSet::from([name.clone()]);
        for _ in 0..=self.cfg.max_cname {
            match self.resolve_step(&current, qtype, ctx, depth)? {
                Step::Answer(recs) => {
                    answers.extend(recs);
                    return Ok(Resolution {
                        rcode: rcode::NOERROR,
                        answers,
                        authority: vec![],
                    });
                }
                Step::Cname(rec) => {
                    let target = rec.target().cloned().expect("CNAME has a target");
                    ctx.log("cname", depth, &current, qtype, || {
                        format!("CNAME {current} -> {target}")
                    });
                    answers.push(rec);
                    if !seen.insert(target.clone()) {
                        return Err(ResolveError::CnameLoop);
                    }
                    current = target;
                }
                Step::NxDomain(soa) => {
                    return Ok(Resolution {
                        rcode: rcode::NXDOMAIN,
                        answers,
                        authority: soa.into_iter().collect(),
                    });
                }
                Step::NoData(soa) => {
                    return Ok(Resolution {
                        rcode: rcode::NOERROR,
                        answers,
                        authority: soa.into_iter().collect(),
                    });
                }
            }
        }
        Err(ResolveError::CnameLoop)
    }

    fn check_cache(&self, name: &Name, qtype: RType, ctx: &mut Ctx, depth: usize) -> Option<Step> {
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap();
        let step = match cache.lookup(name, qtype, now) {
            Some(Lookup::Hit(r)) => Step::Answer(r),
            Some(Lookup::NxDomain(s)) => Step::NxDomain(s),
            Some(Lookup::NoData(s)) => Step::NoData(s),
            None if qtype != RType::CNAME => {
                let c = cache.get_rrset(name, RType::CNAME, Trust::AuthAnswer, now)?;
                Step::Cname(c.into_iter().next()?)
            }
            None => return None,
        };
        drop(cache);
        ctx.log("cache_hit", depth, name, qtype, || {
            let what = match &step {
                Step::Answer(r) => format!("{} record(s)", r.len()),
                Step::Cname(_) => "CNAME".into(),
                Step::NxDomain(_) => "NXDOMAIN".into(),
                Step::NoData(_) => "NODATA".into(),
            };
            format!("cache hit: {name} {qtype} -> {what}")
        });
        Some(step)
    }

    fn resolve_step(
        &self,
        name: &Name,
        qtype: RType,
        ctx: &mut Ctx,
        depth: usize,
    ) -> Result<Step, ResolveError> {
        if let Some(step) = self.check_cache(name, qtype, ctx, depth) {
            return Ok(step);
        }
        let (mut zone, mut ns_names) = self.closest_delegation(name);
        for _ in 0..self.cfg.max_referrals {
            let servers = match self.zone_servers(&zone, &ns_names, ctx, depth) {
                Ok(s) => s,
                // A cached delegation whose addresses expired and can't be re-derived
                // (in-zone NS without glue): back up to the parent and get fresh glue.
                Err(ResolveError::NoServers(z)) if !z.is_root() => {
                    ctx.log("glueless", depth, name, qtype, || {
                        format!("no addresses for {z} nameservers; restarting from parent")
                    });
                    let parent = z.parent().unwrap_or_default();
                    (zone, ns_names) = self.closest_delegation(&parent);
                    continue;
                }
                Err(e) => return Err(e),
            };
            match self.ask(&zone, &servers, name, qtype, ctx, depth)? {
                Classified::Answer(r) => return Ok(Step::Answer(r)),
                Classified::Cname(r) => return Ok(Step::Cname(r)),
                Classified::NxDomain(s) => return Ok(Step::NxDomain(s)),
                Classified::NoData(s) => return Ok(Step::NoData(s)),
                Classified::Referral {
                    zone: child, ns, ..
                } => {
                    zone = child;
                    ns_names = ns.iter().filter_map(|r| r.target().cloned()).collect();
                }
                Classified::Lame(_) => unreachable!("ask() retries lame servers"),
            }
        }
        Err(ResolveError::TooManyReferrals)
    }

    fn closest_delegation(&self, name: &Name) -> (Name, Vec<Name>) {
        let cached = self.cache.lock().unwrap().delegation(name, Instant::now());
        cached.unwrap_or_else(|| {
            let mut names: Vec<Name> = self.cfg.roots.iter().map(|h| h.name.clone()).collect();
            names.dedup();
            (Name::root(), names)
        })
    }

    /// Addresses for a zone's nameservers, resolving glueless NS names if needed,
    /// ordered fastest-first.
    fn zone_servers(
        &self,
        zone: &Name,
        ns_names: &[Name],
        ctx: &mut Ctx,
        depth: usize,
    ) -> Result<Vec<(IpAddr, Name)>, ResolveError> {
        let now = Instant::now();
        let mut out: Vec<(IpAddr, Name)> = Vec::new();
        {
            let cache = self.cache.lock().unwrap();
            for ns in ns_names {
                for a in cache.addresses(ns, self.cfg.ipv6, now) {
                    out.push((a, ns.clone()));
                }
            }
        }
        if out.is_empty() && zone.is_root() {
            out = self
                .cfg
                .roots
                .iter()
                .filter(|h| self.cfg.ipv6 || h.addr.is_ipv4())
                .map(|h| (h.addr, h.name.clone()))
                .collect();
        }
        if out.is_empty() {
            // Glueless delegation: the parent told us NS names but no addresses.
            if depth + 1 > self.cfg.max_depth {
                return Err(ResolveError::DepthExceeded);
            }
            let mut names = ns_names.to_vec();
            rng::shuffle(&mut names);
            for ns in names {
                if ns.is_subdomain_of(zone) {
                    // Needs glue from the parent; asking would loop.
                    continue;
                }
                ctx.log("glueless", depth, &ns, RType::A, || {
                    format!("glueless delegation for {zone}: resolving {ns} A")
                });
                match self.resolve_inner(&ns, RType::A, ctx, depth + 1) {
                    Ok(res) => {
                        for r in res.answers {
                            if let RData::A(ip) = r.data {
                                out.push((IpAddr::V4(ip), ns.clone()));
                            }
                        }
                    }
                    Err(ResolveError::QueryBudgetExhausted) => {
                        return Err(ResolveError::QueryBudgetExhausted);
                    }
                    Err(_) => continue,
                }
                if !out.is_empty() {
                    break;
                }
            }
        }
        if out.is_empty() {
            return Err(ResolveError::NoServers(zone.clone()));
        }
        self.order_servers(&mut out);
        Ok(out)
    }

    /// Fastest first by smoothed RTT. Unknown servers get a tiny random score so
    /// they're explored early; stale estimates (>10 min) are forgotten so a server
    /// that timed out once gets another chance.
    fn order_servers(&self, servers: &mut [(IpAddr, Name)]) {
        let now = Instant::now();
        let srtt = self.srtt.lock().unwrap();
        let mut keyed: Vec<(f64, (IpAddr, Name))> = servers
            .iter()
            .cloned()
            .map(|s| {
                let k = match srtt.get(&s.0) {
                    Some(e) if now.duration_since(e.updated) < Duration::from_secs(600) => e.ms,
                    _ => (rng::u64() % 1000) as f64 / 1000.0,
                };
                (k, s)
            })
            .collect();
        keyed.sort_by(|a, b| a.0.total_cmp(&b.0));
        for (slot, (_, s)) in servers.iter_mut().zip(keyed) {
            *slot = s;
        }
    }

    fn record_rtt(&self, addr: IpAddr, sample: Option<Duration>) {
        let mut srtt = self.srtt.lock().unwrap();
        let now = Instant::now();
        let e = srtt.entry(addr).or_insert(Srtt {
            ms: 0.0,
            updated: now,
        });
        e.ms = match sample {
            // EWMA like BIND/Unbound: 70% history, 30% new sample.
            Some(d) if e.ms > 0.0 => 0.7 * e.ms + 0.3 * d.as_secs_f64() * 1000.0,
            Some(d) => d.as_secs_f64() * 1000.0,
            // Timeout: back off hard so we try other servers first.
            None => (e.ms.max(self.cfg.timeout.as_secs_f64() * 1000.0) * 2.0).min(60_000.0),
        };
        e.updated = now;
    }

    /// Ask a zone's servers in order until one gives a usable answer.
    fn ask(
        &self,
        zone: &Name,
        servers: &[(IpAddr, Name)],
        qname: &Name,
        qtype: RType,
        ctx: &mut Ctx,
        depth: usize,
    ) -> Result<Classified, ResolveError> {
        for (addr, nsname) in servers {
            if ctx.budget == 0 {
                return Err(ResolveError::QueryBudgetExhausted);
            }
            ctx.budget -= 1;
            self.stats.upstream_queries.fetch_add(1, Ordering::Relaxed);
            let q = Message::query(
                rng::u16(),
                qname.clone(),
                qtype,
                false,
                Some(Edns::new(EDNS_UDP_SIZE)),
            );
            let start = Instant::now();
            match self.transport.exchange(*addr, &q) {
                Ok(x) => {
                    self.record_rtt(*addr, Some(x.rtt));
                    if x.tcp {
                        self.stats.tcp_fallbacks.fetch_add(1, Ordering::Relaxed);
                    }
                    let c = classify(&x.response, qname, qtype, zone);
                    if let Some(events) = ctx.trace.as_mut() {
                        events.push(Event {
                            t_ms: start.duration_since(ctx.start).as_secs_f64() * 1000.0,
                            dur_ms: x.rtt.as_secs_f64() * 1000.0,
                            depth,
                            kind: "query",
                            zone: Some(zone.to_string()),
                            server: Some(nsname.to_string()),
                            ip: Some(addr.to_string()),
                            qname: qname.to_string(),
                            qtype: qtype.to_string(),
                            transport: Some(if x.tcp { "tcp" } else { "udp" }),
                            outcome: Some(match &c {
                                Classified::Answer(_) => "answer",
                                Classified::Cname(_) => "cname",
                                Classified::Referral { .. } => "referral",
                                Classified::NxDomain(_) => "nxdomain",
                                Classified::NoData(_) => "nodata",
                                Classified::Lame(_) => "lame",
                            }),
                            detail: describe(&c),
                        });
                    }
                    if let Classified::Lame(_) = c {
                        self.stats.upstream_failures.fetch_add(1, Ordering::Relaxed);
                        continue;
                    }
                    self.cache_response(&x.response, zone, &c, qname, qtype);
                    return Ok(c);
                }
                Err(e) => {
                    self.record_rtt(*addr, None);
                    self.stats.upstream_failures.fetch_add(1, Ordering::Relaxed);
                    if let Some(events) = ctx.trace.as_mut() {
                        events.push(Event {
                            t_ms: start.duration_since(ctx.start).as_secs_f64() * 1000.0,
                            dur_ms: start.elapsed().as_secs_f64() * 1000.0,
                            depth,
                            kind: "query",
                            zone: Some(zone.to_string()),
                            server: Some(nsname.to_string()),
                            ip: Some(addr.to_string()),
                            qname: qname.to_string(),
                            qtype: qtype.to_string(),
                            // TransportError does not expose whether TCP fallback was attempted.
                            transport: None,
                            outcome: Some(if matches!(e, TransportError::Timeout) {
                                "timeout"
                            } else {
                                "error"
                            }),
                            detail: e.to_string(),
                        });
                    }
                }
            }
        }
        Err(ResolveError::AllServersFailed(zone.clone()))
    }

    fn cache_response(
        &self,
        resp: &Message,
        zone: &Name,
        c: &Classified,
        qname: &Name,
        qtype: RType,
    ) {
        let now = Instant::now();
        let mut cache = self.cache.lock().unwrap();
        match c {
            Classified::Answer(_) | Classified::Cname(_) => {
                // Only cache answer records on the CNAME chain starting at qname,
                // and only if they're inside the zone we asked (bailiwick).
                let mut chain = HashSet::from([qname.clone()]);
                for r in &resp.answers {
                    if r.rtype == RType::CNAME
                        && chain.contains(&r.name)
                        && let Some(t) = r.target()
                    {
                        chain.insert(t.clone());
                    }
                }
                let trust = if resp.header.aa {
                    Trust::AuthAnswer
                } else {
                    Trust::Referral
                };
                let wanted: Vec<Record> = resp
                    .answers
                    .iter()
                    .filter(|r| {
                        chain.contains(&r.name)
                            && r.name.is_subdomain_of(zone)
                            && r.class == RClass::IN
                    })
                    .cloned()
                    .collect();
                for set in group_rrsets(wanted) {
                    cache.insert_rrset(set, trust, now);
                }
            }
            Classified::Referral { ns, glue, .. } => {
                cache.insert_rrset(ns.clone(), Trust::Referral, now);
                for set in group_rrsets(glue.clone()) {
                    cache.insert_rrset(set, Trust::Glue, now);
                }
            }
            Classified::NxDomain(soa) => {
                cache.insert_negative(qname, qtype, true, soa.clone(), now)
            }
            Classified::NoData(soa) => cache.insert_negative(qname, qtype, false, soa.clone(), now),
            Classified::Lame(_) => {}
        }
    }
}

fn group_rrsets(records: Vec<Record>) -> Vec<Vec<Record>> {
    let mut sets: Vec<Vec<Record>> = Vec::new();
    for r in records {
        match sets
            .iter_mut()
            .find(|s| s[0].name == r.name && s[0].rtype == r.rtype)
        {
            Some(s) => s.push(r),
            None => sets.push(vec![r]),
        }
    }
    sets
}

fn find_soa(resp: &Message, qname: &Name, zone: &Name) -> Option<Record> {
    resp.authority
        .iter()
        .find(|r| {
            r.rtype == RType::SOA && r.name.is_subdomain_of(zone) && qname.is_subdomain_of(&r.name)
        })
        .cloned()
}

/// Interpret an upstream response to (qname, qtype) from a server for `zone`.
/// This is where most resolver security lives: anything outside the zone's
/// bailiwick or not about the question is ignored.
pub fn classify(resp: &Message, qname: &Name, qtype: RType, zone: &Name) -> Classified {
    let rc = resp.header.rcode;
    if rc != rcode::NOERROR && rc != rcode::NXDOMAIN {
        return Classified::Lame(format!("rcode {}", rcode::name(rc)));
    }
    if !qname.is_subdomain_of(zone) {
        return Classified::Lame("question outside zone".into());
    }
    let answer: Vec<Record> = resp
        .answers
        .iter()
        .filter(|r| r.name == *qname && r.rtype == qtype && r.class == RClass::IN)
        .cloned()
        .collect();
    if !answer.is_empty() {
        return Classified::Answer(answer);
    }
    if qtype != RType::CNAME
        && let Some(c) = resp
            .answers
            .iter()
            .find(|r| r.name == *qname && r.rtype == RType::CNAME)
    {
        return Classified::Cname(c.clone());
    }
    if rc == rcode::NXDOMAIN {
        return Classified::NxDomain(find_soa(resp, qname, zone));
    }
    // Referral: NS records for a zone strictly below the one we asked, covering qname.
    if let Some(first_ns) = resp.authority.iter().find(|r| r.rtype == RType::NS) {
        let child = first_ns.name.clone();
        if child != *zone && child.is_subdomain_of(zone) && qname.is_subdomain_of(&child) {
            let ns: Vec<Record> = resp
                .authority
                .iter()
                .filter(|r| r.rtype == RType::NS && r.name == child)
                .cloned()
                .collect();
            let targets: HashSet<&Name> = ns.iter().filter_map(|r| r.target()).collect();
            let glue: Vec<Record> = resp
                .additional
                .iter()
                .filter(|r| {
                    (r.rtype == RType::A || r.rtype == RType::AAAA)
                        && targets.contains(&r.name)
                        // Bailiwick: a server for `zone` may only vouch for addresses inside `zone`.
                        && r.name.is_subdomain_of(zone)
                })
                .cloned()
                .collect();
            return Classified::Referral {
                zone: child,
                ns,
                glue,
            };
        }
        if !resp.header.aa {
            return Classified::Lame(format!("referral to {child} does not lead toward {qname}"));
        }
    }
    let soa = find_soa(resp, qname, zone);
    if resp.header.aa || soa.is_some() {
        return Classified::NoData(soa);
    }
    Classified::Lame("empty non-authoritative response".into())
}

fn describe(c: &Classified) -> String {
    match c {
        Classified::Answer(r) => {
            let mut v: Vec<String> = r
                .iter()
                .take(3)
                .map(|r| {
                    let s = r.data.to_string();
                    if s.len() > 40 {
                        format!("{}…", &s[..s.floor_char_boundary(40)])
                    } else {
                        s
                    }
                })
                .collect();
            if r.len() > 3 {
                v.push(format!("(+{} more)", r.len() - 3));
            }
            format!("ANSWER {}", v.join(", "))
        }
        Classified::Cname(r) => format!("CNAME {}", r.data),
        Classified::Referral { zone, ns, glue } => {
            format!("referral to {zone} ({} NS, {} glue)", ns.len(), glue.len())
        }
        Classified::NxDomain(_) => "NXDOMAIN".into(),
        Classified::NoData(_) => "NODATA".into(),
        Classified::Lame(why) => format!("lame: {why}"),
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use crate::wire::Soa;
    use std::net::Ipv4Addr;

    fn n(s: &str) -> Name {
        s.parse().unwrap()
    }

    fn resp() -> Message {
        let mut m = Message::query(1, n("www.example.com"), RType::A, false, None);
        m.header.qr = true;
        m
    }

    fn a(name: &str, last: u8) -> Record {
        Record::new(n(name), 300, RData::A(Ipv4Addr::new(192, 0, 2, last)))
    }

    #[test]
    fn referral_drops_out_of_bailiwick_glue() {
        let mut m = resp();
        m.authority.push(Record::new(
            n("example.com"),
            3600,
            RData::Ns(n("ns1.example.com")),
        ));
        m.authority.push(Record::new(
            n("example.com"),
            3600,
            RData::Ns(n("ns.other.net")),
        ));
        m.additional.push(a("ns1.example.com", 1));
        // A .com server has no business telling us where ns.other.net lives.
        m.additional.push(a("ns.other.net", 66));
        // Nor an unrelated name.
        m.additional.push(a("www.bank.com", 66));
        let c = classify(&m, &n("www.example.com"), RType::A, &n("com"));
        let Classified::Referral { zone, ns, glue } = c else {
            panic!("{c:?}")
        };
        assert_eq!(zone, n("example.com"));
        assert_eq!(ns.len(), 2);
        assert_eq!(glue, vec![a("ns1.example.com", 1)]);
    }

    #[test]
    fn upward_referral_is_lame() {
        let mut m = resp();
        m.authority.push(Record::new(
            Name::root(),
            3600,
            RData::Ns(n("a.root-servers.net")),
        ));
        let c = classify(&m, &n("www.example.com"), RType::A, &n("example.com"));
        assert!(matches!(c, Classified::Lame(_)), "{c:?}");
    }

    #[test]
    fn sideways_referral_is_lame() {
        let mut m = resp();
        m.authority.push(Record::new(
            n("evil.com"),
            3600,
            RData::Ns(n("ns.evil.com")),
        ));
        let c = classify(&m, &n("www.example.com"), RType::A, &n("com"));
        assert!(matches!(c, Classified::Lame(_)), "{c:?}");
    }

    #[test]
    fn nodata_and_nxdomain() {
        let soa = Record::new(
            n("example.com"),
            3600,
            RData::Soa(Soa {
                mname: n("ns1.example.com"),
                rname: n("h.example.com"),
                serial: 1,
                refresh: 1,
                retry: 1,
                expire: 1,
                minimum: 60,
            }),
        );
        let mut m = resp();
        m.header.aa = true;
        m.authority.push(soa.clone());
        assert_eq!(
            classify(&m, &n("www.example.com"), RType::A, &n("example.com")),
            Classified::NoData(Some(soa.clone()))
        );
        m.header.rcode = rcode::NXDOMAIN;
        assert_eq!(
            classify(&m, &n("www.example.com"), RType::A, &n("example.com")),
            Classified::NxDomain(Some(soa))
        );
    }

    #[test]
    fn servfail_is_lame() {
        let mut m = resp();
        m.header.rcode = rcode::SERVFAIL;
        assert!(matches!(
            classify(&m, &n("www.example.com"), RType::A, &n("com")),
            Classified::Lame(_)
        ));
    }

    #[test]
    fn cname_answer() {
        let mut m = resp();
        m.header.aa = true;
        m.answers.push(Record::new(
            n("www.example.com"),
            300,
            RData::Cname(n("web.example.net")),
        ));
        let c = classify(&m, &n("www.example.com"), RType::A, &n("example.com"));
        assert!(matches!(c, Classified::Cname(_)));
    }
}
