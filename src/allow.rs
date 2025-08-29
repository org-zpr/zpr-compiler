//! allow.rs - parser for allow statements

use std::collections::HashMap;
use std::iter::Peekable;

use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{AllowClause, AttrDomain, Attribute, Class, ClassFlavor, Clause};
use crate::putil;
use crate::zpl;

#[derive(Debug, Default)]
struct ParseAllowState {
    root_tok: Token,
    endpoint_clause: Option<Clause>,
    user_clause: Option<Clause>,
    service_clause: Option<Clause>,
}

impl ParseAllowState {
    fn new(root_tok: Token) -> ParseAllowState {
        ParseAllowState {
            root_tok,
            ..Default::default()
        }
    }

    /// This consumes all the clauses or panics.
    fn to_allow_clause(&mut self, id: usize) -> AllowClause {
        AllowClause {
            id,
            endpoint: self
                .endpoint_clause
                .take()
                .expect("endpoint clause not set"),
            user: self.user_clause.take().expect("user clause not set"),
            service: self.service_clause.take().expect("service clause not set"),
        }
    }
}

/// First token is an ALLOW which is checked by caller.
///
/// Format of the allow statement is:
///
/// allow <user-clause> on <endpoint-clause> to access <service-clause>
///
/// If there are both endpoint and user clauses they are separated by 'on'.
/// You can omit either user or endpoint clauses:
///
/// allow <user-clause> to access <service-clause>
/// allow <endpoint-clause> to access <service-clause>
///
/// `classes_idx` maps class names and AKA names to their canonical names (eg, "services" -> "service").
/// `classs_map` maps class canonical name to [Class] struct.
pub fn parse_allow(
    allow_statement: &[Token],
    statement_id: usize,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<AllowClause, CompilationError> {
    if allow_statement.is_empty() {
        panic!("parse_allow called with empty statement");
    }
    if allow_statement[0].tt != TokenType::Allow {
        panic!("parse_allow called with non-ALLOW statement");
    }

    let root_tok = &allow_statement[0];
    let mut parse_state = ParseAllowState::new(root_tok.clone());
    let mut tokens = allow_statement[1..].iter().peekable();
    let mut ps = PState::new(&parse_state.root_tok);

    // To parse this we start parsing and break if we hit a ON or a TO.
    ps.parse_tags_attrs_and_classname(
        &mut tokens,
        classes_idx,
        &ParseOpts::stop_at_any(&[TokenType::To, TokenType::On]),
        "endpoint or user clause",
    )?;

    match tokens.peek() {
        Some(tok) => {
            let cn = ps.class_name.as_ref().unwrap();

            // If we hit a TO then we expect either a DEVICE or USER clause
            match tok.tt {
                TokenType::To => {
                    // Must have eitherr a device or user clause.
                    match classes_map.get(cn).unwrap().flavor {
                        ClassFlavor::User => {
                            // Device clause is skipped, so use default.
                            parse_state.endpoint_clause = Some(Clause::new(
                                zpl::DEF_CLASS_ENDPOINT_NAME,
                                parse_state.root_tok.clone(),
                            ));
                            let uc = ps.to_clause("user")?;
                            parse_state.user_clause = Some(uc);
                        }
                        ClassFlavor::Endpoint => {
                            // User clause is skipped, so use default.
                            parse_state.user_clause = Some(Clause::new(
                                zpl::DEF_CLASS_USER_NAME,
                                parse_state.root_tok.clone(),
                            ));
                            let dc = ps.to_clause("endpoint")?;
                            parse_state.endpoint_clause = Some(dc);
                        }
                        _ => {
                            return Err(CompilationError::AllowStmtParseError(
                                format!("not a user or endpoint clause: '{}'", cn),
                                parse_state.root_tok.line,
                                parse_state.root_tok.col,
                            ));
                        }
                    }
                }

                // If we hit an ON then we expect a USER clause.
                TokenType::On => {
                    // Hit ON which means we must have parsed a user clause, and we expect a device clause to follow.
                    if classes_map.get(cn).unwrap().flavor == ClassFlavor::User {
                        let dc = ps.to_clause("user")?;
                        parse_state.user_clause = Some(dc);
                    } else {
                        return Err(CompilationError::AllowStmtParseError(
                            format!("not a user clause: '{}'", cn),
                            parse_state.root_tok.line,
                            parse_state.root_tok.col,
                        ));
                    }
                }

                // Hmm what's this?
                _ => {
                    return Err(CompilationError::AllowStmtParseError(
                        format!("expected a TO or ON, found '{:?}'", tok.tt),
                        parse_state.root_tok.line,
                        parse_state.root_tok.col,
                    ));
                }
            }
        }
        None => {
            // end of tokens!
            return Err(CompilationError::AllowStmtParseError(
                "expected a TO or WITH not EOF".to_string(),
                parse_state.root_tok.line,
                parse_state.root_tok.col,
            ));
        }
    }

    // If we get this far, we have parsed up to a ON or a TO.
    // If it's a ON then we expect an endpoint clause next.
    // If it's a TO then we expect a service clause next.
    let tok = tokens.next().unwrap();
    match tok.tt {
        TokenType::On => {
            if parse_state.user_clause.is_none() {
                panic!("assertion fails - no user clause");
            }
            // Ok, now parse an ENDPOINT clause, returns having found but not parsed 'TO'.
            if !try_parse_allow_endpoint_clause(
                &mut parse_state,
                &mut tokens,
                classes_idx,
                classes_map,
            )? {
                // Hmm, a non error failure?
                return Err(CompilationError::AllowStmtParseError(
                    "expected an endpoint clause to follow ON".to_string(),
                    tok.line,
                    tok.col,
                ));
            }
            // pop the TO off, leaving the 'access'.
            putil::require_tt(
                &parse_state.root_tok,
                tokens.next(),
                "TO",
                "allow",
                TokenType::To,
            )?;
        }
        TokenType::To => { /* continue to parse service clause */ }
        _ => {
            // We already peek'd the iterator above, so this case should not happen.
            panic!("assertion fails - expected WITH or TO token");
        }
    }

    if parse_state.endpoint_clause.is_none() {
        panic!("assertion fails - no endpoint clause");
    }

    // The remaining tokens should start with "access ..." which we pass to the service class parser.
    parse_allow_service_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?;

    let mut ac = parse_state.to_allow_clause(statement_id);

    // Set any UNSPECIFIED (lacking domain) attributes to the domain of the clause they are in.
    for attr in &mut ac.endpoint.with {
        if attr.is_unspecified_domain() {
            attr.set_domain(AttrDomain::Endpoint);
        }
    }
    for attr in &mut ac.user.with {
        if attr.is_unspecified_domain() {
            attr.set_domain(AttrDomain::User);
        }
    }
    for attr in &mut ac.service.with {
        if attr.is_unspecified_domain() {
            attr.set_domain(AttrDomain::Service);
        }
    }

    validate_clause(&ac, classes_map)?;
    Ok(ac)
}

// The place to catch semantic errors before returning the clause.
fn validate_clause(
    ac: &AllowClause,
    classes_map: &HashMap<String, Class>,
) -> Result<(), CompilationError> {
    if ac.user.with_attr_count(classes_map) + ac.endpoint.with_attr_count(classes_map) == 0 {
        return Err(CompilationError::AllowStmtParseError(
            "user and/or endpoint must specify at least one discriminating attribute".to_string(),
            ac.user.class_tok.line,
            ac.user.class_tok.col,
        ));
    }
    Ok(())
}

/// Parse from <endpoint-clause> up to the 'TO' (of 'TO ACCESS')
/// If this succeeds, it sets the endpoint clause in the [ParseAllowState].
fn try_parse_allow_endpoint_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<bool, CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    let mut ps = PState::new(&pa_state.root_tok);

    ps.parse_tags_attrs_and_classname(
        tokens,
        classes_idx,
        &ParseOpts::stop_at(TokenType::To),
        "endpoint clause",
    )?;

    // This is a good parse if we actually got a endpoint flavor class.
    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor == ClassFlavor::Endpoint {
        let ec = ps.to_clause("endpoint")?;
        pa_state.endpoint_clause = Some(ec);
        Ok(true)
    } else {
        Ok(false) // not an endpoint clause
    }
}

/// Parse the final bit of the allow statement which is the service clause.
/// The passed tokens MUST start with "ACCESS".
///
/// The service clause may have a trailing ON <endpoint-clause>.
fn parse_allow_service_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<(), CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    // Pop off the "ACCESS" token...
    putil::require_tt(
        &pa_state.root_tok,
        tokens.next(),
        "ACCESS",
        "allow",
        TokenType::Access,
    )?;

    // Need a service clause now -- parse to end of statement.
    let mut ps = PState::new(&pa_state.root_tok);
    let popts = ParseOpts::stop_at_any(&[TokenType::On, TokenType::Eos]);
    ps.parse_tags_attrs_and_classname(tokens, classes_idx, &popts, "service clause")?;

    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor != ClassFlavor::Service {
        return Err(CompilationError::AllowStmtParseError(
            format!("not a service class: '{}'", cn),
            pa_state.root_tok.line,
            pa_state.root_tok.col,
        ));
    }
    let mut service_clause = ps.to_clause("service")?;

    // If we read an ON then we need to parse an endpoint clause.
    if let Some(tok) = tokens.next() {
        if tok.tt == TokenType::On {
            let mut nested_ps = PState::new(&pa_state.root_tok);

            nested_ps.parse_tags_attrs_and_classname(
                tokens,
                classes_idx,
                &ParseOpts::default(),
                "service endpoint clause",
            )?;

            // This is a good parse if we actually got a endpoint flavor class.
            let cn = nested_ps.class_name.as_ref().unwrap();
            if classes_map.get(cn).unwrap().flavor == ClassFlavor::Endpoint {
                let service_ec = nested_ps.to_clause("endpoint")?;

                // Since ZPL could use a defined class in the on clause we need to walk the tree and
                // gather any attributes.
                let mut all_endpoint_attrs = collect_all_attributes(&service_ec.class, classes_map);
                all_endpoint_attrs.extend(service_ec.with);

                for ec_attr in &all_endpoint_attrs {
                    let mut domained_attr = ec_attr.clone();
                    if domained_attr.is_unspecified_domain() {
                        domained_attr.set_domain(AttrDomain::Endpoint);
                    } else if !domained_attr.is_domain(AttrDomain::Endpoint) {
                        // This is not permitted. You can only talk about endpoints in the ON clause.
                        return Err(CompilationError::AllowStmtParseError(
                            format!(
                                "illegal non-endpoint attribute in service ON clause: '{domained_attr}'"
                            ),
                            pa_state.root_tok.line,
                            pa_state.root_tok.col,
                        ));
                    }
                    service_clause.with.push(domained_attr); // TODO: Are these already in endpoint domain?
                }
            } else {
                return Err(CompilationError::AllowStmtParseError(
                    format!(
                        "expected an endpoint class in service ON clause, got: '{}'",
                        cn
                    ),
                    pa_state.root_tok.line,
                    pa_state.root_tok.col,
                ));
            }
        }
    }

    pa_state.service_clause = Some(service_clause);
    Ok(())
}

// Note that this does not check for duplicates.
fn collect_all_attributes(
    class_name: &str,
    classes_map: &HashMap<String, Class>,
) -> Vec<Attribute> {
    let mut attrs = Vec::new();
    let mut current_class = class_name;
    loop {
        if let Some(class_data) = classes_map.get(current_class) {
            // Built-in has no with attrs
            if class_data.is_builtin() {
                break;
            }
            attrs.extend(class_data.with_attrs.clone());
            let parent = &class_data.parent;
            if parent == current_class {
                break;
            }
            current_class = parent;
        }
    }
    attrs
}

struct PState {
    root_tok: Token,
    class_name: Option<String>,
    class_name_token: Option<Token>,
    attrs: Vec<Attribute>,
}

struct ParseOpts {
    // stop parsing if we see (but do not consume) one of these tokens
    break_at: Vec<TokenType>,

    // Stop after this many occurrances of break_at token. Note only last occurance is not consumed.
    break_at_count: usize,
}

impl ParseOpts {
    fn stop_at(break_at: TokenType) -> Self {
        Self {
            break_at: vec![break_at],
            break_at_count: 1,
        }
    }
    fn stop_at_any(tokens: &[TokenType]) -> Self {
        Self {
            break_at: tokens.to_vec(),
            break_at_count: 1,
        }
    }
    fn is_stop_token(&self, tt: &TokenType) -> bool {
        self.break_at.contains(tt)
    }
}

impl Default for ParseOpts {
    fn default() -> Self {
        Self {
            break_at: vec![TokenType::Eos],
            break_at_count: 1,
        }
    }
}

impl PState {
    fn new(root_tok: &Token) -> PState {
        PState {
            root_tok: root_tok.clone(),
            class_name: None,
            class_name_token: None,
            attrs: Vec::new(),
        }
    }

    fn to_clause(&self, kind: &str) -> Result<Clause, CompilationError> {
        if self.class_name.is_none() {
            return Err(CompilationError::AllowStmtParseError(
                format!("expected a class name in a {} clause", kind),
                self.root_tok.line,
                self.root_tok.col,
            ));
        }
        Ok(Clause {
            class: self.class_name.clone().unwrap(), // flavor is not checked
            class_tok: self.class_name_token.as_ref().unwrap().clone(), // always set if class_name is set
            with: self.attrs.clone(),
        })
    }

    fn parse_tags_attrs_and_classname<'a, I>(
        &mut self,
        tokens: &mut Peekable<I>,
        classes: &HashMap<String, String>,
        opts: &ParseOpts,
        context: &str,
    ) -> Result<(), CompilationError>
    where
        I: Iterator<Item = &'a Token>,
    {
        let mut tcount = 0;
        let mut break_count = 0;
        while let Some(tokref) = tokens.peek() {
            tcount += 1;
            if opts.is_stop_token(&tokref.tt) {
                break_count += 1;
                if break_count >= opts.break_at_count {
                    break;
                }
            }
            match &tokref.tt {
                TokenType::And | TokenType::Comma => {
                    // These are delimiter tokens.
                    tokens.next();
                }
                TokenType::Tuple((name, value)) => {
                    // This is an attribute.
                    let attr = Attribute::attr_domain_opt(name, value);
                    self.attrs.push(attr);
                    tokens.next();
                }
                TokenType::Literal(s) => {
                    // This could be a class name or a tag name.
                    if let Some(class) = classes.get(s) {
                        if self.class_name.is_some() {
                            // We already have a class name.
                            let tok = tokens.next().unwrap();
                            return Err(CompilationError::MultipleClassNames(
                                format!("found class '{class}' but class already set: {context}"),
                                tok.line,
                                tok.col,
                            ));
                        }
                        self.class_name = Some(class.clone());
                        let tok = tokens.next().unwrap();
                        self.class_name_token = Some(tok.clone());
                    } else {
                        self.attrs.push(Attribute::tag_domain_opt(s));
                        tokens.next();
                    }
                }
                TokenType::With => {
                    // We used to support a postfix form of attributes but no longer.
                    // If we see this we report an error to help people covert old ZPL.
                    let tok = tokens.next().unwrap();
                    return Err(CompilationError::AllowStmtParseError(
                        format!(
                            "postfix attribute form using WITH no longer supported: {}",
                            context
                        ),
                        tok.line,
                        tok.col,
                    ));
                }
                _ => {
                    let tok = tokens.next().unwrap();
                    return Err(CompilationError::SyntaxError(
                        format!("{} ({:?})", context, tok.tt),
                        tok.line,
                        tok.col,
                    ));
                }
            };
        }
        if tcount == 0 {
            return Err(CompilationError::AllowStmtParseError(
                format!("{} is empty", context),
                self.root_tok.line,
                self.root_tok.col,
            ));
        }

        if self.class_name.is_none() {
            return Err(CompilationError::AllowStmtParseError(
                format!("expected a class name in {}", context),
                self.root_tok.line,
                self.root_tok.col,
            ));
        }

        Ok(())
    }
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::{context::CompilationCtx, lex::tokenize_str};

    #[test]
    fn test_parses_valid_on_clause() {
        let valids = vec![
            "allow blue users to access services on level:seven endpoints",
            "allow blue users to access services on orange endpoints",
            "allow blue users to access services on orange, level:seven endpoints",
            "allow blue users on green endpoints to access services",
        ];

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            class_index.insert(name.clone(), name.clone());
            class_index.insert(class.aka.clone(), name.clone());
        }

        let cctx = CompilationCtx::default();

        for statement in &valids {
            let tz = tokenize_str(statement, &cctx).unwrap();
            let tokens = tz.tokens;
            match parse_allow(&tokens, 1, &class_index, &classes) {
                Ok(_clause) => {
                    // great!
                }
                Err(err) => {
                    panic!(
                        "valid statement failed to parse: '{}', err: {:?}",
                        statement, err
                    );
                }
            }
        }
    }

    #[test]
    fn test_fails_on_invalid_on_clause() {
        let invalids = vec![
            "allow blue users to access services on",
            "allow blue users to access services on level:seven on endpoints",
            "allow on blue users to access services",
            "allow blue users to access services on orange",
        ];

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            class_index.insert(name.clone(), name.clone());
            class_index.insert(class.aka.clone(), name.clone());
        }

        let cctx = CompilationCtx::default();

        for statement in &invalids {
            let tz = tokenize_str(statement, &cctx).unwrap();
            let tokens = tz.tokens;
            match parse_allow(&tokens, 1, &class_index, &classes) {
                Ok(clause) => {
                    panic!(
                        "invalid statement failed to generate error: '{}', clause: {:?}",
                        statement, clause
                    );
                }
                Err(_err) => {
                    // ok
                }
            }
        }
    }

    #[test]
    fn test_sets_attrs_correctly_trailing_on() {
        let statement = "allow blue users to access services on level:seven endpoints";

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            class_index.insert(name.clone(), name.clone());
            class_index.insert(class.aka.clone(), name.clone());
        }

        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let tokens = tz.tokens;
        let clause = parse_allow(&tokens, 1, &class_index, &classes).unwrap();

        // Blue tag goes on user.
        clause
            .user
            .with
            .iter()
            .find(|a| a.to_string() == "#user.blue")
            .expect("blue tag missing from user clause");
        // level:seven attr goes in as an endpoint domain attribute on the service.
        clause
            .service
            .with
            .iter()
            .find(|a| a.to_string() == "endpoint.level:seven")
            .expect("level:seven tag missing from service clause");
    }

    #[test]
    fn test_sets_attrs_correctly_user_on() {
        let statement = "allow blue users on level:seven endpoints to access services";

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            class_index.insert(name.clone(), name.clone());
            class_index.insert(class.aka.clone(), name.clone());
        }

        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let tokens = tz.tokens;
        let clause = parse_allow(&tokens, 1, &class_index, &classes).unwrap();

        // Blue tag goes on user.
        clause
            .user
            .with
            .iter()
            .find(|a| a.to_string() == "#user.blue")
            .expect("blue tag missing from user clause");
        // level:seven attr goes in as an endpoint attribute
        clause
            .endpoint
            .with
            .iter()
            .find(|a| a.to_string() == "endpoint.level:seven")
            .expect("level:seven tag missing from endpoint clause");
    }

    #[test]
    fn test_sets_attrs_correctly_two_on() {
        let statement =
            "allow blue users on level:seven endpoints to access services on level:eight endpoints";

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            class_index.insert(name.clone(), name.clone());
            class_index.insert(class.aka.clone(), name.clone());
        }

        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let tokens = tz.tokens;
        let clause = parse_allow(&tokens, 1, &class_index, &classes).unwrap();

        // Blue tag goes on user.
        clause
            .user
            .with
            .iter()
            .find(|a| a.to_string() == "#user.blue")
            .expect("blue tag missing from user clause");
        // level:seven attr goes in as an endpoint attribute
        clause
            .endpoint
            .with
            .iter()
            .find(|a| a.to_string() == "endpoint.level:seven")
            .expect("level:seven tag missing from endpoint clause");
        // level:eight attr goes in as an endpoint domain attribute on the service.
        clause
            .service
            .with
            .iter()
            .find(|a| a.to_string() == "endpoint.level:eight")
            .expect("level:eight tag missing from service clause");
    }
}
