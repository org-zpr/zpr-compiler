//! ptypes - Parser types
use ring::digest::Digest;
use std::collections::HashMap;
use std::fmt;

use crate::errors::AttributeError;
use crate::lex::Token;
use crate::zpl;

/// The datastructure version of the ZPL policy after parsing.
/// Just a bunch of defines and allows.
#[derive(Default)]
pub struct Policy {
    pub digest: Option<Digest>,
    pub defines: Vec<Class>,
    pub allows: Vec<AllowClause>,
}

/// FPos is a "file position" to better report errors in the ZPL parsing.
#[derive(Debug, Clone, Default)]
pub struct FPos {
    pub line: usize,
    pub col: usize,
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

/// A parsed "allow" statement.
#[derive(Clone, Debug)]
pub struct AllowClause {
    pub id: usize, // Within a given zpl policy, each allow clause gets a unique id.
    pub device: Clause,
    pub user: Clause,
    pub service: Clause,
}

impl fmt::Display for AllowClause {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(
            f,
            "[{}] ALLOW {}\n   WITH {}\n      TO ACCESS {}",
            self.id, self.device, self.user, self.service
        )
    }
}

/// A parsed "clause" which appears in allow statements. For example, a user-clause describes
/// the user component of the allow.  The other two are device-clause and service-clause.
/// Each clause may have a set of attributes on it.
#[derive(Default, Clone, Debug)]
#[allow(dead_code)]
pub struct Clause {
    pub class: String,
    pub class_tok: Token,
    pub with: Vec<Attribute>,
    // TODO: pub without: Vec<Attribute>,
}

impl Clause {
    pub fn new(class: &str, class_tok: Token) -> Self {
        Clause {
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

/// A defined class in ZPL has a type which we call "flavor".
#[derive(Debug, Clone, PartialEq, Eq, Copy)]
pub enum ClassFlavor {
    Undefined, // they all start here
    Device,
    User,
    Service,
}

/// A class is created from a ZPL define statement.
/// There are also three built in classes: user, service, and endpoint.
#[derive(Debug)]
pub struct Class {
    pub flavor: ClassFlavor,
    pub parent: String,
    pub name: String,
    pub aka: String,
    pub pos: FPos, // location of the define token
    pub with_attrs: Vec<Attribute>,
    // TODO: withouts
}

impl Class {
    /// Returns the built in classes.
    pub fn defaults() -> Vec<Class> {
        vec![
            Class::default_user(),
            Class::default_service(),
            Class::default_device(),
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
        }
    }
    pub fn default_device() -> Class {
        Class {
            flavor: ClassFlavor::Device,
            parent: zpl::DEF_CLASS_DEVICE_NAME.to_string(),
            name: zpl::DEF_CLASS_DEVICE_NAME.to_string(),
            aka: zpl::DEF_CLASS_DEVICE_AKA.to_string(),
            pos: FPos { line: 0, col: 0 },
            with_attrs: vec![],
        }
    }
    pub fn is_builtin(&self) -> bool {
        self.name == zpl::DEF_CLASS_USER_NAME
            || self.name == zpl::DEF_CLASS_SERVICE_NAME
            || self.name == zpl::DEF_CLASS_DEVICE_NAME
    }
}

#[derive(Debug, Clone, PartialEq, Eq)]
pub enum AttrDomain {
    Unspecified,
    Device,
    User,
    Service,
}

impl TryFrom<&str> for AttrDomain {
    type Error = AttributeError;

    fn try_from(s: &str) -> Result<Self, AttributeError> {
        match s {
            zpl::ATTR_DOMAIN_DEVICE => Ok(AttrDomain::Device),
            zpl::ATTR_DOMAIN_USER => Ok(AttrDomain::User),
            zpl::ATTR_DOMAIN_SERVICE => Ok(AttrDomain::Service),
            _ => Err(AttributeError::InvalidDomain(s.to_string())),
        }
    }
}

impl fmt::Display for AttrDomain {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        match self {
            AttrDomain::Device => write!(f, "{}", zpl::ATTR_DOMAIN_DEVICE),
            AttrDomain::User => write!(f, "{}", zpl::ATTR_DOMAIN_USER),
            AttrDomain::Service => write!(f, "{}", zpl::ATTR_DOMAIN_SERVICE),
            AttrDomain::Unspecified => write!(f, "UNSPECIFIED"),
        }
    }
}

impl AttrDomain {
    pub fn from_flavor(class: ClassFlavor) -> Self {
        match class {
            ClassFlavor::Device => AttrDomain::Device,
            ClassFlavor::User => AttrDomain::User,
            ClassFlavor::Service => AttrDomain::Service,
            ClassFlavor::Undefined => AttrDomain::Unspecified,
        }
    }
}

/// A ZPL attribute. Could be a tule type attibute, eg "role:marketing" or a
/// tag type.  An attribute may be optional or required, and may be multi-valued
/// or single-valued.
#[derive(Debug, Clone, PartialEq)]
pub struct Attribute {
    domain: AttrDomain,
    name: String,
    pub value: Option<String>,
    pub multi_valued: bool,
    pub tag: bool,
    pub optional: bool,
}

impl fmt::Display for Attribute {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        let key = format!("{}.{}", self.domain, self.name);
        if let Some(v) = &self.value {
            write!(f, "{}:{}", key, v)?
        } else if self.tag {
            write!(f, "#{}", key)?
        } else {
            write!(f, "{}", key)?
        }
        if self.multi_valued {
            write!(f, "+")?
        }
        if self.optional {
            return write!(f, "?");
        }
        Ok(())
    }
}

impl Attribute {
    /// Crate new attribute. If the `name` includes a valid domain prefix, the domain will be set to that.
    /// Otherwise the domain will be set to `domain_hint`.
    pub fn new_with_domain_hint(
        domain_hint: AttrDomain,
        name: &str,
        value: Option<String>,
        multi_valued: bool,
        tag: bool,
        optional: bool,
    ) -> Self {
        let (dom, rest) = Attribute::parse_domain(name).unwrap_or_else(|_| {
            // If the new name does not have a domain prefix, use the current domain.
            (domain_hint.clone(), name.to_string())
        });
        Attribute {
            domain: dom,
            name: rest,
            value,
            multi_valued,
            tag,
            optional,
        }
    }

    /// Parse off one the ZPR domains from the key.
    /// Returns (<domain>, <rest>) from given key.
    fn parse_domain(key: &str) -> Result<(AttrDomain, String), AttributeError> {
        if let Some(renamed) = key.strip_prefix(&format!("{}.", zpl::ATTR_DOMAIN_DEVICE)) {
            Ok((AttrDomain::Device, renamed.to_string()))
        } else if let Some(renamed) = key.strip_prefix(&format!("{}.", zpl::ATTR_DOMAIN_USER)) {
            Ok((AttrDomain::User, renamed.to_string()))
        } else if let Some(renamed) = key.strip_prefix(&format!("{}.", zpl::ATTR_DOMAIN_SERVICE)) {
            Ok((AttrDomain::Service, renamed.to_string()))
        } else {
            Err(AttributeError::InvalidDomain(key.to_string()))
        }
    }

    /// Easy way top create a TAG type attribute.
    pub fn tag(name: &str) -> Result<Self, AttributeError> {
        let (dom, rest) = Attribute::parse_domain(name)?;
        Ok(Attribute {
            domain: dom,
            name: rest,
            value: None,
            multi_valued: false,
            tag: true,
            optional: false,
        })
    }

    pub fn tag_domain_opt(name: &str) -> Self {
        let (dom, rest) = Attribute::parse_domain(name)
            .unwrap_or_else(|_| (AttrDomain::Unspecified, name.to_string()));
        Attribute {
            domain: dom,
            name: rest,
            value: None,
            multi_valued: false,
            tag: true,
            optional: false,
        }
    }

    /// Easy way to create a tuple type attribute.
    pub fn attr(name: &str, value: &str) -> Result<Self, AttributeError> {
        let (dom, rest) = Attribute::parse_domain(name)?;
        Ok(Attribute {
            domain: dom,
            name: rest,
            value: Some(value.to_string()),
            multi_valued: false,
            tag: false,
            optional: false,
        })
    }

    pub fn attr_or_panic(name: &str, value: &str) -> Self {
        Attribute::attr(name, value).expect("invalid attribute")
    }

    /// Hmm, special case.
    pub fn zpr_internal_attr(name: &str, value: &str) -> Self {
        if !name.starts_with("zpr.") {
            panic!("zpr internal attribute must start with 'zpr.'");
        }
        Attribute {
            domain: AttrDomain::Unspecified, // TODO: Add the ZPR domain?
            name: name.to_string(),
            value: Some(value.to_string()),
            multi_valued: false,
            tag: false,
            optional: false,
        }
    }

    pub fn attr_domain_opt(name: &str, value: &str) -> Self {
        let (dom, rest) = Attribute::parse_domain(name)
            .unwrap_or_else(|_| (AttrDomain::Unspecified, name.to_string()));
        Attribute {
            domain: dom,
            name: rest,
            value: Some(value.to_string()),
            multi_valued: false,
            tag: false,
            optional: false,
        }
    }

    pub fn is_unspecified_domain(&self) -> bool {
        self.domain == AttrDomain::Unspecified
    }

    /// Create required, tuple type attribute without specifying a value.
    pub fn attr_name_only(name: &str) -> Result<Self, AttributeError> {
        let (dom, rest) = Attribute::parse_domain(name)?;
        Ok(Attribute {
            domain: dom,
            name: rest,
            value: None,
            multi_valued: false,
            tag: false,
            optional: false,
        })
    }

    /// Create and return a new attribute with the same characteristics of this one but with the new name provided.
    /// If `new_name` includes a valid domain prefix, the returned attribute will have that domain.
    pub fn set_name(&self, new_name: &str) -> Self {
        let mut new_a = self.clone();
        let (dom, name) = Attribute::parse_domain(new_name).unwrap_or_else(|_| {
            // If the new name does not have a domain prefix, use the current domain.
            (self.domain.clone(), new_name.to_string())
        });
        new_a.name = name;
        new_a.domain = dom;
        new_a
    }

    /// Update the domain.
    pub fn set_domain(&mut self, domain: AttrDomain) {
        self.domain = domain;
    }

    /// The the ZPL name for the key of this attribute. The key is just the attribute name
    /// unless this is a tag, in which case the key is "<domain>.zpr.tag".
    pub fn zpl_key(&self) -> String {
        if self.tag {
            format!("{}.zpr.tag", self.domain)
        } else {
            format!("{}.{}", self.domain, self.name)
        }
    }

    /// The ZPL value for this attribute. If there is no value an empty string is returned.
    pub fn zpl_value(&self) -> String {
        if self.tag {
            format!("{}.{}", self.domain, self.name)
        } else if let Some(v) = &self.value {
            v.clone()
        } else {
            "".to_string()
        }
    }
}
