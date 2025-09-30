//! ptypes - Parser types
use ring::digest::Digest;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Write};

use crate::errors::AttributeError;
use crate::lex::Token;
use crate::zpl;

/// The datastructure version of the ZPL policy after parsing.
/// Just a bunch of defines and allows.
#[derive(Default)]
pub struct Policy {
    pub digest: Option<Digest>,
    pub defines: Vec<Class>,
    pub nevers: Vec<AllowClause>,
    pub allows: Vec<AllowClause>,
}

/// FPos is a "file position" to better report errors in the ZPL parsing.
#[derive(Debug, Clone, Default)]
pub struct FPos {
    pub line: usize,
    pub col: usize,
}

impl FPos {
    pub fn new(line: usize, col: usize) -> Self {
        FPos { line, col }
    }
}

impl From<Token> for FPos {
    fn from(tok: Token) -> Self {
        FPos {
            line: tok.line,
            col: tok.col,
        }
    }
}

impl From<&Token> for FPos {
    fn from(tok: &Token) -> Self {
        FPos {
            line: tok.line,
            col: tok.col,
        }
    }
}

impl fmt::Display for FPos {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "line:{}, col:{}", self.line, self.col)
    }
}

/// A parsed "allow" statement.
///
/// Originally this was parsed into three clauses that mapped to a permission
/// statement: and ENDPOINT cluase, a USER clause and a SERVICE clause.  The
/// endpoint and user clauses were assumed to be on the LHS of the statment,
/// and the service clause on the RHS. Think: users on endpoints can access services.
///
/// However, over time it has become clear that it is better to think in terms
/// of CLIENTS and SERVERS.  Clients access services on servers.  Clients are LHS (left hand side) and
/// serviers are RHS.  Both clients and servers can have attributes in any of the
/// three classes (user, endpoint, service).  A client may also indicate that
/// it is a service.
///
/// The server side (RHS) must always have at least a service clause.
///
/// Attributes of the classes may not always be in the domain of the class. For example, the
/// service clause may have endpoint attributes in it.
#[derive(Clone, Debug)]
pub struct AllowClause {
    pub clause_id: usize, // Within a given zpl policy, each allow clause gets a unique id.
    pub span: (FPos, FPos),
    pub client: Vec<Clause>,
    pub server: Vec<Clause>,
    pub signal: Option<Signal>,
}

impl fmt::Display for AllowClause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}] ALLOW  <{} -> {}>\n",
            self.clause_id, self.span.0, self.span.1
        )?;
        for c in &self.client {
            write!(f, "      {:?}\n", c)?;
        }
        write!(f, "    TO ACCESS\n")?;
        for c in &self.server {
            write!(f, "     {:?}\n", c)?;
        }
        if let Some(sig) = &self.signal {
            write!(f, "    AND SIGNAL\n      {:?}\n", sig)?;
        }
        Ok(())
    }
}

impl AllowClause {
    /// Default `fmt` for allow assumes the allow is just a normal allow.
    /// Use this debug stringer to get a NEVER thrown in to the output.
    pub fn to_string_never(&self) -> String {
        let mut f = String::new();
        write!(f, "[{}] NEVER ALLOW\n", self.clause_id).unwrap();
        for c in &self.client {
            write!(f, "      {:?}\n", c).unwrap();
        }
        write!(f, "    TO ACCESS\n").unwrap();
        for c in &self.server {
            write!(f, "     {:?}\n", c).unwrap();
        }
        if let Some(sig) = &self.signal {
            write!(f, "    AND SIGNAL\n      {:?}\n", sig).unwrap();
        }
        f
    }

    pub fn get_server_service_clause(&self) -> Option<Clause> {
        for c in &self.server {
            if c.flavor == ClassFlavor::Service {
                return Some(c.clone());
            }
        }
        None
    }
}

/// A parsed "clause" which appears in allow statements. For example, a user-clause describes
/// the user component of the allow.  The other two are device-clause and service-clause.
/// Each clause may have a set of attributes on it.
#[derive(Default, Clone, Debug)]
#[allow(dead_code)]
pub struct Clause {
    pub flavor: ClassFlavor,
    pub class: String,
    pub class_tok: Token,
    pub with: Vec<Attribute>,
    // TODO: pub without: Vec<Attribute>,
}

impl Clause {
    pub fn new(flavor: ClassFlavor, class: &str, class_tok: Token) -> Self {
        Clause {
            flavor,
            class: class.to_string(),
            class_tok,
            with: vec![],
        }
    }

    #[allow(dead_code)]
    pub fn add_attr(&mut self, attr: Attribute) {
        self.with.push(attr);
    }

    /// Given a clause (and classes map) return the number of "with" attributes that are
    /// required by the clause class (and parent classes if any).
    ///
    #[allow(dead_code)]
    pub fn with_attr_count(&self, classes_map: &HashMap<String, Class>) -> usize {
        let mut cur_class = &self.class;
        let mut with_count = self.with.len();

        loop {
            let clz = classes_map.get(cur_class).expect("class not found"); // at this point only valid classes are present
            with_count += clz.with_attrs.len();
            if clz.is_builtin() || cur_class == &clz.parent {
                break;
            }
            cur_class = &clz.parent;
        }
        with_count
    }
}

impl fmt::Display for Clause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} with [", self.class)?;
        for attr in &self.with {
            write!(f, " {},", attr)?;
        }
        write!(f, "]")
    }
}

// TODO could also use polio::Signal instead...not sure if that would cause problems
#[derive(Clone, Debug)]
pub struct Signal {
    pub message: String,
    pub service_class_name: String,
}

#[allow(dead_code)]
impl Signal {
    pub fn new(message: String, service_class_name: String) -> Self {
        Signal {
            message,
            service_class_name,
        }
    }
}

impl fmt::Display for Signal {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f, "{} to {}", self.message, self.service_class_name)
    }
}

/// A defined class in ZPL has a type which we call "flavor".
#[derive(Debug, Clone, PartialEq, Eq, Copy, Default)]
pub enum ClassFlavor {
    #[default]
    Undefined, // they all start here
    Endpoint,
    User,
    Service,
}

impl Display for ClassFlavor {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            ClassFlavor::Endpoint => write!(f, "endpoint"),
            ClassFlavor::User => write!(f, "user"),
            ClassFlavor::Service => write!(f, "service"),
            ClassFlavor::Undefined => write!(f, "undefined"),
        }
    }
}

/// A class is created from a ZPL define statement.
/// There are also three built in classes: user, service, and endpoint.
#[derive(Debug, Clone)]
pub struct Class {
    pub flavor: ClassFlavor,
    pub parent: String,
    pub name: String,
    pub aka: String,
    pub pos: FPos, // location of the define token
    pub with_attrs: Vec<Attribute>,
    pub extensible: bool,
    pub class_id: usize,
    // TODO: withouts
}

impl Class {
    /// Returns the built in classes.
    pub fn defaults() -> Vec<Class> {
        vec![
            Class::default_user(),
            Class::default_service(),
            Class::default_endpoint(),
            Class::default_visa_service(),
        ]
    }
    pub fn default_user() -> Class {
        Class {
            flavor: ClassFlavor::User,
            parent: zpl::DEF_CLASS_USER_NAME.to_string(),
            name: zpl::DEF_CLASS_USER_NAME.to_string(),
            aka: zpl::DEF_CLASS_USER_AKA.to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
            extensible: true,
            class_id: usize::MAX - 1,
        }
    }
    pub fn default_service() -> Class {
        Class {
            flavor: ClassFlavor::Service,
            parent: zpl::DEF_CLASS_SERVICE_NAME.to_string(),
            name: zpl::DEF_CLASS_SERVICE_NAME.to_string(),
            aka: zpl::DEF_CLASS_SERVICE_AKA.to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
            extensible: true,
            class_id: usize::MAX - 2,
        }
    }
    pub fn default_visa_service() -> Class {
        Class {
            flavor: ClassFlavor::Service,
            parent: zpl::DEF_CLASS_SERVICE_NAME.to_string(),
            name: zpl::DEF_CLASS_VISA_SERVICE_NAME.to_string(),
            aka: zpl::DEF_CLASS_VISA_SERVICE_AKA.to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
            extensible: false,
            class_id: usize::MAX - 3,
        }
    }
    pub fn default_endpoint() -> Class {
        Class {
            flavor: ClassFlavor::Endpoint,
            parent: zpl::DEF_CLASS_ENDPOINT_NAME.to_string(),
            name: zpl::DEF_CLASS_ENDPOINT_NAME.to_string(),
            aka: zpl::DEF_CLASS_ENDPOINT_AKA.to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
            extensible: true,
            class_id: usize::MAX - 4,
        }
    }
    pub fn is_builtin(&self) -> bool {
        self.name == zpl::DEF_CLASS_USER_NAME
            || self.name == zpl::DEF_CLASS_SERVICE_NAME
            || self.name == zpl::DEF_CLASS_ENDPOINT_NAME
            || self.name == zpl::DEF_CLASS_VISA_SERVICE_NAME
    }
}

/// An attribute must live in one of our domains. When parsing sometimes we
/// end up in an intermediate state where we don't know the domain yet so
/// we use `Unspecified`.  An error will occur if we try to write policy
/// and there remain any unspecified domains.
#[derive(Debug, Clone, PartialEq, Eq, Hash, Copy)]
pub enum AttrDomain {
    Unspecified,
    Endpoint,
    User,
    Service,
    ZprInternal, // For compiler/visa-service use only
}

impl fmt::Display for AttrDomain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AttrDomain::Endpoint => write!(f, "{}", zpl::ATTR_DOMAIN_ENDPOINT),
            AttrDomain::User => write!(f, "{}", zpl::ATTR_DOMAIN_USER),
            AttrDomain::Service => write!(f, "{}", zpl::ATTR_DOMAIN_SERVICE),
            AttrDomain::ZprInternal => write!(f, "{}", zpl::ATTR_DOMAIN_ZPR_INTERNAL),
            AttrDomain::Unspecified => write!(f, "UNSPECIFIED"),
        }
    }
}

impl AttrDomain {
    pub fn from_flavor(class: ClassFlavor) -> Self {
        match class {
            ClassFlavor::Endpoint => AttrDomain::Endpoint,
            ClassFlavor::User => AttrDomain::User,
            ClassFlavor::Service => AttrDomain::Service,
            ClassFlavor::Undefined => AttrDomain::Unspecified,
        }
    }
}

/// A ZPL attribute. Could be a tule type attibute, eg "user.role:marketing" or a
/// tag type.  An attribute may be optional or required, and may be multi-valued
/// or single-valued.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    domain: AttrDomain,
    name: String, // For a tag this is the tag name, else this is the attribute name.
    pub values: Option<Vec<String>>, // For a tag, this is always None.
    attr_type: AttrT,
    pub optional: bool,
}

#[derive(Debug, Clone, PartialEq, Eq, Hash)]
pub enum AttrT {
    Tag,
    SingleValued,
    MultiValued,
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let key = format!("{}.{}", self.domain, self.name);
        if let Some(v) = &self.values {
            if v.is_empty() {
                write!(f, "{key}:")?
            } else if v.len() == 1 {
                write!(f, "{key}:{}", v[0])?
            } else {
                write!(f, "{key}:{{{}}}", v.join(", "))?
            }
        } else if self.is_tag() {
            write!(f, "#{}", key)?
        } else {
            write!(f, "{}", key)?;
            if self.is_multi_valued() {
                write!(f, "{}", "{}")?;
            }
            if self.optional {
                write!(f, "?")?;
            }
        }
        Ok(())
    }
}

#[derive(Clone, Copy, Debug, PartialEq, Eq, Hash)]
pub enum DomainFallback {
    UseHint(AttrDomain),
    UseUnspecified,
    ErrorIfMissing,
}

pub struct TagAttrBuilder {
    raw_name: String,
    optional: bool,
    domain_fb: DomainFallback,
}

pub struct TupleAttrBuilder {
    raw_name: String,
    attr_type: AttrT,
    values: Option<Vec<String>>,
    optional: bool,
    domain_fb: DomainFallback,
}

impl TagAttrBuilder {
    fn new<N: Into<String>>(name: N) -> Self {
        TagAttrBuilder {
            raw_name: name.into(),
            optional: false,
            domain_fb: DomainFallback::ErrorIfMissing,
        }
    }

    fn optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    pub fn domain_hint(mut self, domain: AttrDomain) -> Self {
        self.domain_fb = DomainFallback::UseHint(domain);
        self
    }

    pub fn allow_unspecified(mut self) -> Self {
        self.domain_fb = DomainFallback::UseUnspecified;
        self
    }

    pub fn build(self) -> Result<Attribute, AttributeError> {
        let (domain, name) = resolve_domain(&self.raw_name, self.domain_fb)?;
        Ok(Attribute {
            domain,
            name,
            values: None,
            attr_type: AttrT::Tag,
            optional: self.optional,
        })
    }
}

impl TupleAttrBuilder {
    fn new<N: Into<String>>(name: N) -> Self {
        TupleAttrBuilder {
            raw_name: name.into(),
            attr_type: AttrT::SingleValued,
            values: None,
            optional: false,
            domain_fb: DomainFallback::ErrorIfMissing,
        }
    }

    pub fn single(mut self) -> Self {
        self.attr_type = AttrT::SingleValued;
        self
    }

    /// Note that single-valued is the default.
    pub fn multi(mut self) -> Self {
        self.attr_type = AttrT::MultiValued;
        self
    }

    pub fn multi_if(mut self, multi: bool) -> Self {
        if multi {
            self.attr_type = AttrT::MultiValued;
        } else {
            self.attr_type = AttrT::SingleValued;
        }
        self
    }

    pub fn optional(mut self, optional: bool) -> Self {
        self.optional = optional;
        self
    }

    pub fn value<V: Into<String>>(mut self, v: V) -> Self {
        self.values = Some(vec![v.into()]);
        self
    }

    /// If you sent more than one value the resulting tuple will be
    /// multi-valued type (you do not need to explicitly call `multi()`).
    pub fn values(mut self, vals: Vec<String>) -> Self {
        self.values = Some(vals);
        self
    }

    pub fn values_opt(mut self, opt_vals: Option<Vec<String>>) -> Self {
        if opt_vals.is_some() {
            self.values = opt_vals;
        }
        self
    }

    pub fn domain_hint(mut self, hint: AttrDomain) -> Self {
        self.domain_fb = DomainFallback::UseHint(hint);
        self
    }

    pub fn allow_unspecified(mut self) -> Self {
        self.domain_fb = DomainFallback::UseUnspecified;
        self
    }

    pub fn build(self) -> Result<Attribute, AttributeError> {
        let (domain, name) = resolve_domain(&self.raw_name, self.domain_fb)?;
        let attr_type = match (&self.values, self.attr_type) {
            (_, AttrT::MultiValued) => AttrT::MultiValued, // explicitly set by caller
            (Some(v), AttrT::SingleValued) if v.len() > 1 => AttrT::MultiValued, // inferred from values
            _ => AttrT::SingleValued,
        };
        Ok(Attribute {
            domain,
            name,
            values: self.values,
            attr_type,
            optional: self.optional,
        })
    }
}

fn resolve_domain(name: &str, fb: DomainFallback) -> Result<(AttrDomain, String), AttributeError> {
    match Attribute::parse_domain(name) {
        Ok(pair) => Ok(pair),
        Err(_) => match fb {
            DomainFallback::UseHint(hint) => Ok((hint, name.into())),
            DomainFallback::UseUnspecified => Ok((AttrDomain::Unspecified, name.into())),
            DomainFallback::ErrorIfMissing => Err(AttributeError::InvalidDomain(name.into())),
        },
    }
}

impl Attribute {
    /// New API using the builders.  The other new_xxx functions that create tags use this.
    pub fn tag<N: Into<String>>(name: N) -> TagAttrBuilder {
        TagAttrBuilder::new(name)
    }

    /// New API using the builders.  The other new_xxx functions that create singel or
    /// multi-value attributes use this.
    pub fn tuple<N: Into<String>>(name: N) -> TupleAttrBuilder {
        TupleAttrBuilder::new(name)
    }

    /// For non-tag attributes.
    pub fn new_multiple_attribute_with_domain_hint<S: Into<String>>(
        domain_hint: AttrDomain,
        name: S,
        values: Option<Vec<String>>,
        optional: bool,
    ) -> Result<Self, AttributeError> {
        Attribute::tuple(name)
            .multi()
            .values_opt(values)
            .optional(optional)
            .domain_hint(domain_hint)
            .build()
    }

    /// For non-tag attributes.
    ///
    pub fn new_single_attribute_with_domain_hint<S: Into<String>>(
        domain_hint: AttrDomain,
        name: S,
        values: Option<Vec<String>>,
        optional: bool,
    ) -> Result<Self, AttributeError> {
        Attribute::tuple(name)
            .single()
            .values_opt(values)
            .optional(optional)
            .domain_hint(domain_hint)
            .build()
    }

    /// For non-tag attributes.
    ///
    pub fn new_blank_attribute_with_domain_hint<S: Into<String>>(
        domain_hint: AttrDomain,
        name: S,
        multiple: bool,
        optional: bool,
    ) -> Result<Self, AttributeError> {
        Attribute::tuple(name)
            .optional(optional)
            .domain_hint(domain_hint)
            .multi_if(multiple)
            .build()
    }

    /// Create a tuple type attribute and will set domain unspecified if not present on the `name`.
    /// Defaults to a single-value attribute unless multiple values are provided.
    pub fn new_attr_domain_opt<S: Into<String>>(
        name: S,
        values: Vec<String>,
    ) -> Result<Self, AttributeError> {
        Attribute::tuple(name)
            .values(values)
            .allow_unspecified()
            .build()
    }

    /// Easy way to create a tuple type attribute with a single value.
    pub fn new_single_valued<S: Into<String>>(name: S, value: S) -> Result<Self, AttributeError> {
        Attribute::tuple(name).single().value(value).build()
    }

    /// Create a tuple type attribute or panic if name is invalid.
    pub fn must_new_single_valued<S: Into<String>>(name: S, value: S) -> Self {
        Attribute::new_single_valued(name, value).expect("invalid attribute")
    }

    /// Create required, tuple type (single value) attribute without specifying a value.
    pub fn attr_name_only<S: Into<String>>(name: S) -> Result<Self, AttributeError> {
        Attribute::tuple(name).single().build()
    }

    /// Easy way top create a TAG type attribute.
    /// Returns error if domain is not parseable.
    pub fn new_tag<S: Into<String>>(name: S) -> Result<Self, AttributeError> {
        Attribute::tag(name).build()
    }

    /// Create new attribute. If the `name` includes a valid domain prefix, the domain will be set to that.
    /// Otherwise the domain will be set to `domain_hint`.
    pub fn new_tag_with_domain_hint<S: Into<String>>(
        domain_hint: AttrDomain,
        name: S,
        optional: bool,
    ) -> Result<Self, AttributeError> {
        Attribute::tag(name)
            .domain_hint(domain_hint)
            .optional(optional)
            .build()
    }

    /// Create a tag attribute and will set domain to [AttrDomain::Unspecified] if not present on the `name`.
    pub fn new_tag_domain_opt<S: Into<String>>(name: S) -> Result<Self, AttributeError> {
        Attribute::tag(name).allow_unspecified().build()
    }

    /// Create required, tuple-type, multi-values attribute without specifying a value.
    pub fn attr_name_only_multi<S: Into<String>>(name: S) -> Result<Self, AttributeError> {
        Attribute::tuple(name).multi().build()
    }

    /// Special constructor for ZPR internal attributes with a single value.
    ///
    /// ## Panics
    /// - if passed `name` does not start with `zpr`.
    pub fn must_zpr_internal_attr<S: Into<String>>(name: S, value: S) -> Self {
        if let Some(name_without_domain) = name
            .into()
            .strip_prefix(&format!("{}.", zpl::ATTR_DOMAIN_ZPR_INTERNAL))
        {
            match Attribute::tuple(name_without_domain)
                .domain_hint(AttrDomain::ZprInternal)
                .value(value)
                .build()
            {
                Ok(atr) => atr,
                Err(e) => panic!("invalid attribute: {}", e),
            }
        } else {
            panic!("zpr internal attribute must start with 'zpr.'");
        }
    }

    /// Special constructor for ZPR internal attribute with single value but
    /// sets the MULTI_VALUE flag.
    ///
    /// ## Panics
    /// - if passed `name` does not start with `zpr`.
    pub fn must_zpr_internal_attr_mv<S: Into<String>>(name: S, value: S) -> Self {
        if let Some(name_without_domain) = name
            .into()
            .strip_prefix(&format!("{}.", zpl::ATTR_DOMAIN_ZPR_INTERNAL))
        {
            match Attribute::tuple(name_without_domain)
                .domain_hint(AttrDomain::ZprInternal)
                .multi()
                .value(value)
                .build()
            {
                Ok(atr) => atr,
                Err(e) => panic!("invalid attribute: {}", e),
            }
        } else {
            panic!("zpr internal attribute must start with 'zpr.'");
        }
    }

    /// Create and return a new attribute with the same characteristics of this one but with the new name provided.
    /// If `new_name` includes a valid domain prefix, the returned attribute will have that domain.
    pub fn clone_with_new_name<S: Into<String>>(&self, new_name: S) -> Self {
        let mut new_a = self.clone();
        let new_name = new_name.into();
        let (dom, name) = match Attribute::parse_domain(&new_name) {
            Ok((d, n)) => (d, n),
            // If the new name does not have a domain prefix, use the current domain.
            Err(_) => (self.domain.clone(), new_name.to_string()),
        };
        new_a.name = name;
        new_a.domain = dom;
        new_a
    }

    pub fn is_tag(&self) -> bool {
        self.attr_type == AttrT::Tag
    }

    pub fn is_single_valued(&self) -> bool {
        self.attr_type == AttrT::SingleValued
    }

    pub fn is_multi_valued(&self) -> bool {
        self.attr_type == AttrT::MultiValued
    }

    /// ## Panics
    /// - If this is a tag.
    pub fn set_multi_valued(&mut self) {
        if self.is_tag() {
            panic!("Attribute::set_multi_valued: cannot set multi-valued on a tag attribute");
        }
        self.attr_type = AttrT::MultiValued;
    }

    /// Parse off one the ZPR domains from the key.  Does not work with ZPR internal domain.
    /// Returns `(<domain>, <rest>)` from given key.
    pub fn parse_domain(key: &str) -> Result<(AttrDomain, String), AttributeError> {
        if let Some(renamed) = key.strip_prefix(&format!("{}.", zpl::ATTR_DOMAIN_ENDPOINT)) {
            Ok((AttrDomain::Endpoint, renamed.to_string()))
        } else if let Some(renamed) = key.strip_prefix(&format!("{}.", zpl::ATTR_DOMAIN_USER)) {
            Ok((AttrDomain::User, renamed.to_string()))
        } else if let Some(renamed) = key.strip_prefix(&format!("{}.", zpl::ATTR_DOMAIN_SERVICE)) {
            Ok((AttrDomain::Service, renamed.to_string()))
        } else {
            Err(AttributeError::InvalidDomain(key.to_string()))
        }
    }

    pub fn get_domain_ref(&self) -> &AttrDomain {
        &self.domain
    }

    pub fn is_unspecified_domain(&self) -> bool {
        self.domain == AttrDomain::Unspecified
    }

    pub fn is_domain(&self, domain: AttrDomain) -> bool {
        self.domain == domain
    }

    /// Update the domain.
    pub fn set_domain(&mut self, domain: AttrDomain) {
        self.domain = domain;
    }

    /// The the ZPL name for the key of this attribute. The key is just the attribute name
    /// unless this is a tag, in which case the key is "\<domain\>.zpr.tag".
    pub fn zpl_key(&self) -> String {
        if self.is_tag() {
            format!("{}.zpr.tag", self.domain)
        } else {
            format!("{}.{}", self.domain, self.name)
        }
    }

    /// The ZPL value for this attribute. If there is no value an empty string is returned.
    /// If there are multiple values a comma separated list is returned.
    pub fn zpl_value(&self) -> String {
        if self.is_tag() {
            format!("{}.{}", self.domain, self.name)
        } else if let Some(v) = &self.values {
            v.join(", ")
        } else {
            "".to_string()
        }
    }

    /// If this is a tag you get the domain qualified tag name as the single value.
    /// Otherwise, you get the set of values (which may be empty).
    pub fn zpl_values(&self) -> Vec<String> {
        if self.is_tag() {
            return vec![format!("{}.{}", self.domain, self.name)];
        }
        if let Some(v) = &self.values {
            v.clone()
        } else {
            vec![]
        }
    }

    /// Write an attribute key name as it might appear in zplc.
    /// Value of the attribute is ignored.
    /// - tags look like `#domain.name`
    /// - regular tuples look like `domain.name`
    /// - multi-valued attributes look like `domain.name{}`
    pub fn zplc_key(&self) -> String {
        let mut f = String::new();
        let key = format!("{}.{}", self.domain, self.name);
        if self.is_tag() {
            write!(f, "#").unwrap();
        }
        write!(f, "{}", key).unwrap();
        if self.is_multi_valued() {
            write!(f, "{}", "{}").unwrap();
        }
        f
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_attributes_kv() {
        let a = Attribute::new_single_valued("user.role", "admin").unwrap();
        assert_eq!(a.domain, AttrDomain::User);
        assert_eq!(a.name, "role");
        assert_eq!(a.values, Some(vec!["admin".to_string()]));
        assert_eq!(a.is_multi_valued(), false);
        assert_eq!(a.is_tag(), false);
        assert_eq!(a.optional, false);
        assert_eq!("user.role:admin", a.to_string());
        assert_eq!("user.role", a.zpl_key());
        assert_eq!("admin", a.zpl_value());
    }

    #[test]
    fn test_attributes_tag() {
        let a = Attribute::new_tag("endpoint.hardened").unwrap();
        assert_eq!(a.domain, AttrDomain::Endpoint);
        assert_eq!(a.name, "hardened");
        assert_eq!(a.values, None);
        assert_eq!(a.is_multi_valued(), false);
        assert_eq!(a.is_tag(), true);
        assert_eq!(a.optional, false);
        assert_eq!("#endpoint.hardened", a.to_string());
        assert_eq!("endpoint.zpr.tag", a.zpl_key());
        assert_eq!("endpoint.hardened", a.zpl_value());
    }

    #[test]
    fn test_attrributes_internal() {
        let a = Attribute::must_zpr_internal_attr("zpr.role", "admin");
        assert_eq!(a.domain, AttrDomain::ZprInternal);
        assert_eq!(a.name, "role");
        assert_eq!(a.values, Some(vec!["admin".to_string()]));
        assert_eq!(a.is_multi_valued(), false);
        assert_eq!(a.is_tag(), false);
        assert_eq!(a.optional, false);
        assert_eq!("zpr.role:admin", a.to_string());
        assert_eq!("zpr.role", a.zpl_key());
        assert_eq!("admin", a.zpl_value());
    }

    #[test]
    fn test_zplc_key_regular_attribute() {
        let a = Attribute::new_single_valued("user.role", "admin").unwrap();
        assert_eq!("user.role", a.zplc_key());
    }

    #[test]
    fn test_zplc_key_tag_attribute() {
        let a = Attribute::new_tag("endpoint.hardened").unwrap();
        assert_eq!("#endpoint.hardened", a.zplc_key());
    }

    #[test]
    fn test_zplc_key_multi_valued_attribute() {
        let a = Attribute::attr_name_only_multi("user.groups").unwrap();
        assert_eq!("user.groups{}", a.zplc_key());
    }

    // ZPLC does not use "?" notation.
    #[test]
    fn test_zplc_key_optional() {
        let mut a = Attribute::attr_name_only("service.role").unwrap();
        a.optional = true;
        assert_eq!("service.role", a.zplc_key());
        let mut a = Attribute::new_tag("endpoint.secure").unwrap();
        a.optional = true;
        assert_eq!("#endpoint.secure", a.zplc_key());
        let mut a = Attribute::attr_name_only_multi("user.permissions").unwrap();
        a.optional = true;
        assert_eq!("user.permissions{}", a.zplc_key());
    }

    #[test]
    fn test_zplc_key_zpr_internal_attribute() {
        let a = Attribute::must_zpr_internal_attr("zpr.adapter.cn", "test");
        assert_eq!("zpr.adapter.cn", a.zplc_key());
    }

    #[test]
    fn test_zplc_key_zpr_internal_multi_valued() {
        let a = Attribute::must_zpr_internal_attr_mv("zpr.roles", "admin");
        assert_eq!("zpr.roles{}", a.zplc_key());
    }

    #[test]
    fn test_zplc_key_all_domains() {
        // Test each domain type
        let user_attr = Attribute::new_single_valued("user.name", "alice").unwrap();
        assert_eq!("user.name", user_attr.zplc_key());

        let service_attr = Attribute::new_single_valued("service.type", "web").unwrap();
        assert_eq!("service.type", service_attr.zplc_key());

        let endpoint_attr = Attribute::new_single_valued("endpoint.ip", "192.168.1.1").unwrap();
        assert_eq!("endpoint.ip", endpoint_attr.zplc_key());

        let zpr_attr = Attribute::must_zpr_internal_attr("zpr.test", "value");
        assert_eq!("zpr.test", zpr_attr.zplc_key());
    }
}
