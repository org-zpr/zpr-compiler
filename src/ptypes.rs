//! ptypes - Parser types
use ring::digest::Digest;
use std::collections::HashMap;
use std::fmt;
use std::fmt::{Display, Write};

use crate::lex::Token;
use crate::zpl;
use zpr::policy_types::{AttrDomain, Attribute};

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
            write!(f, " {},", attr.to_instance_string())?;
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

impl Into<AttrDomain> for ClassFlavor {
    fn into(self) -> AttrDomain {
        match self {
            ClassFlavor::Endpoint => AttrDomain::Endpoint,
            ClassFlavor::User => AttrDomain::User,
            ClassFlavor::Service => AttrDomain::Service,
            ClassFlavor::Undefined => AttrDomain::Unspecified,
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
