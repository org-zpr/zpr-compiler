//! allow.rs - parser for allow statements

use std::collections::HashMap;
use std::iter::Peekable;

use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{AllowClause, AttrDomain, Attribute, Class, ClassFlavor, Clause, FPos, Signal};
use crate::putil;
use crate::zpl;

#[derive(Debug, Default)]
struct ParseAllowState {
    root_tok: Token,
    client_endpoint_clause: Option<Clause>,
    client_user_clause: Option<Clause>,
    client_service_clause: Option<Clause>,
    service_clause: Option<Clause>,
    signal_clause: Option<Signal>,
}

impl ParseAllowState {
    fn new(root_tok: Token) -> ParseAllowState {
        ParseAllowState {
            root_tok: root_tok.clone(),
            ..Default::default()
        }
    }

    /// True when we have none of the client clauses set.
    fn client_clauses_is_none(&self) -> bool {
        self.client_endpoint_clause.is_none()
            && self.client_user_clause.is_none()
            && self.client_service_clause.is_none()
    }

    /// This consumes all the clauses or panics.
    ///
    /// Note that every allow clause will get a user and endpoint clause in the client vector
    /// even if they are just the default.
    ///
    /// The `server` vector in the [AllowClause] will just have one element -- a service clause
    /// that may have attributes from other domains (eg, endpoint or user attributes).
    fn to_allow_clause(&mut self, clause_id: usize, last_tok: Token) -> AllowClause {
        let mut client_user_clause = self.client_user_clause.take().unwrap_or(Clause::new(
            ClassFlavor::User,
            zpl::DEF_CLASS_USER_NAME,
            self.root_tok.clone(),
        ));

        let mut client_endpoint_clause = self.client_endpoint_clause.take().unwrap_or(Clause::new(
            ClassFlavor::Endpoint,
            zpl::DEF_CLASS_ENDPOINT_NAME,
            self.root_tok.clone(),
        ));

        // For now keep service as none if it is not yet defined.
        let mut opt_client_service_clause = self.client_service_clause.take();

        // Move any non endpoint attributes from the endpoint clause into the correct one.
        let mut keep_attrs = Vec::new();
        for attr in client_endpoint_clause.with {
            match attr.get_domain_ref() {
                &AttrDomain::Service => {
                    if let Some(ref mut sc) = opt_client_service_clause {
                        sc.with.push(attr)
                    } else {
                        let mut cl = Clause::new(
                            ClassFlavor::Service,
                            zpl::DEF_CLASS_SERVICE_NAME,
                            self.root_tok.clone(),
                        );
                        cl.with.push(attr);
                        opt_client_service_clause = Some(cl)
                    }
                }
                &AttrDomain::User => client_user_clause.with.push(attr),
                _ => keep_attrs.push(attr),
            }
        }
        client_endpoint_clause.with = keep_attrs;

        // Move any non user attributes from the user clause into the correct one.
        let mut keep_attrs = Vec::new();
        for attr in client_user_clause.with {
            match attr.get_domain_ref() {
                &AttrDomain::Service => {
                    if let Some(ref mut sc) = opt_client_service_clause {
                        sc.with.push(attr)
                    } else {
                        let mut cl = Clause::new(
                            ClassFlavor::Service,
                            zpl::DEF_CLASS_SERVICE_NAME,
                            self.root_tok.clone(),
                        );
                        cl.with.push(attr);
                        opt_client_service_clause = Some(cl)
                    }
                }
                &AttrDomain::Endpoint => client_endpoint_clause.with.push(attr),
                _ => keep_attrs.push(attr),
            }
        }
        client_user_clause.with = keep_attrs;

        let mut client_clauses = Vec::new();
        client_clauses.push(client_user_clause);
        client_clauses.push(client_endpoint_clause);
        if let Some(sc) = opt_client_service_clause.take() {
            client_clauses.push(sc);
        }
        AllowClause {
            clause_id,
            span: (
                self.root_tok.clone().into(),
                FPos::new(last_tok.line, last_tok.col + last_tok.size - 1),
            ),
            client: client_clauses,
            // TODO: Note that above we spend a lot of time to move the attributes on each
            // client class into the client class of the attribute domain. We do not to that (yet?)
            // for the service clause.
            server: vec![self.service_clause.take().expect("service clause not set")],
            signal: self.signal_clause.take(),
        }
    }
}

/// First token is an ALLOW which is checked by caller.
///
/// Format of the allow statement is:
///
/// allow (<user-clause>|<service-clause>) on <endpoint-clause> to access <service-clause>
///
/// If there are both endpoint and user/service clauses they are separated by 'on'.
/// You can omit either user or endpoint clauses:
///
/// allow <user-clause> to access <service-clause>
/// allow <service-clause> to access <service-clause>
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
    let _ = ps.parse_tags_attrs_and_classname(
        &mut tokens,
        classes_idx,
        &ParseOpts::stop_at_any(&[TokenType::To, TokenType::On]),
        "client (LHS) clause",
    )?;

    match tokens.peek() {
        Some(tok) => {
            let cn = ps.class_name.as_ref().unwrap();

            // If we hit a TO then we expect one to have parsed an endpoint, user or even service clause.
            // The LHS can only name one class.  There may be other attributes in different classes
            // applied.  Eg, 'service.blue, orange users'.
            match tok.tt {
                TokenType::To => {
                    // Must have either a device or user clause.
                    match classes_map.get(cn).unwrap().flavor {
                        ClassFlavor::User => {
                            let uc = ps.to_clause(ClassFlavor::User)?;
                            parse_state.client_user_clause = Some(uc);
                        }
                        ClassFlavor::Endpoint => {
                            let dc = ps.to_clause(ClassFlavor::Endpoint)?;
                            parse_state.client_endpoint_clause = Some(dc);
                        }
                        ClassFlavor::Service => {
                            let dc = ps.to_clause(ClassFlavor::Service)?;
                            parse_state.client_service_clause = Some(dc);
                        }
                        _ => {
                            return Err(CompilationError::AllowStmtParseError(
                                format!("not a valid client (LHS) clause: '{}'", cn),
                                parse_state.root_tok.line,
                                parse_state.root_tok.col,
                            ));
                        }
                    }
                }

                // If we hit an ON then we expect to have parsed a user or service clause.
                TokenType::On => {
                    // Hit ON which means we must have parsed a user clause, and we expect an endpoint clause to follow.
                    match classes_map.get(cn).unwrap().flavor {
                        ClassFlavor::User => {
                            let dc = ps.to_clause(ClassFlavor::User)?;
                            parse_state.client_user_clause = Some(dc);
                        }
                        ClassFlavor::Service => {
                            let dc = ps.to_clause(ClassFlavor::Service)?;
                            parse_state.client_service_clause = Some(dc);
                        }
                        _ => {
                            return Err(CompilationError::AllowStmtParseError(
                                format!("not a user clause: '{}'", cn),
                                parse_state.root_tok.line,
                                parse_state.root_tok.col,
                            ));
                        }
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
                "expected a TO or ON not EOF".to_string(),
                parse_state.root_tok.line,
                parse_state.root_tok.col,
            ));
        }
    }

    // If we get this far, we have parsed up to a ON or a TO.
    // If it's a ON then we expect an endpoint clause next.
    // If it's a TO then we expect a RHS service clause next.
    let tok = tokens.next().unwrap();
    match tok.tt {
        TokenType::On => {
            if parse_state.client_clauses_is_none() {
                panic!("assertion fails - no client clauses on LHS");
            }
            if parse_state.client_endpoint_clause.is_some() {
                return Err(CompilationError::AllowStmtParseError(
                    format!("endpoint clause on RHS preceeds ON"),
                    parse_state.root_tok.line,
                    parse_state.root_tok.col,
                ));
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
            let _ = putil::require_tt(
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
            panic!("assertion fails - expected ON or TO token");
        }
    }

    if parse_state.client_clauses_is_none() {
        panic!("assertion fails - no client clauses");
    }

    // The remaining tokens should start with "access ..." or "signal ..." which we pass to the service class parser.
    // If there is a signal token at the end, only that token will remain after this function.
    let mut last_tok =
        parse_allow_service_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?;

    if let Some(_tok) = tokens.peek() {
        last_tok =
            parse_allow_signal_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?;
    }

    let mut ac = parse_state.to_allow_clause(statement_id, last_tok);

    // Set any UNSPECIFIED (lacking domain) attributes to the domain of the clause they are in.

    for client_clause in &mut ac.client {
        for attr in &mut client_clause.with {
            if attr.is_unspecified_domain() {
                let canonical_class_name = classes_idx.get(&client_clause.class).unwrap();
                let flavor = classes_map.get(canonical_class_name).unwrap().flavor;
                attr.set_domain(AttrDomain::from_flavor(flavor));
            }
        }
    }
    for server_clause in &mut ac.server {
        for attr in &mut server_clause.with {
            if attr.is_unspecified_domain() {
                let canonical_class_name = classes_idx.get(&server_clause.class).unwrap();
                let flavor = classes_map.get(canonical_class_name).unwrap().flavor;
                attr.set_domain(AttrDomain::from_flavor(flavor));
            }
        }
    }

    validate_clause(&ac, root_tok, classes_map)?;
    Ok(ac)
}

// The place to catch semantic errors before returning the clause.
fn validate_clause(
    ac: &AllowClause,
    root_tok: &Token,
    _classes_map: &HashMap<String, Class>,
) -> Result<(), CompilationError> {
    check_clause_composition(&ac.client, root_tok, "in LHS of allow statement")?;
    check_clause_composition(&ac.server, root_tok, "in RHS of allow statement")?;

    // Finally, the RHS requires a service clause.
    if ac.get_server_service_clause().is_none() {
        return Err(CompilationError::AllowStmtParseError(
            "missing a service clause on RHS".into(),
            root_tok.line,
            root_tok.col,
        ));
    }

    Ok(())
}

// Sanity check: each client and server vector can have at most one class of each flavor.
fn check_clause_composition(
    clauses: &[Clause],
    root_tok: &Token,
    explain: &str,
) -> Result<(), CompilationError> {
    let mut usr_ep_svc = (0, 0, 0);
    for clause in clauses {
        match clause.flavor {
            ClassFlavor::User => usr_ep_svc.0 += 1,
            ClassFlavor::Endpoint => usr_ep_svc.1 += 1,
            ClassFlavor::Service => usr_ep_svc.2 += 1,
            _ => (),
        }
    }
    if let Some(err_msg) = match usr_ep_svc {
        (a, _, _) if a > 1 => Some(format!("too many user clauses {explain}")),
        (_, b, _) if b > 1 => Some(format!("too may endpoint clauses {explain}")),
        (_, _, c) if c > 1 => Some(format!("too many service clauses {explain}")),
        _ => None,
    } {
        return Err(CompilationError::AllowStmtParseError(
            err_msg.into(),
            root_tok.line,
            root_tok.col,
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
        let ec = ps.to_clause(ClassFlavor::Endpoint)?;
        pa_state.client_endpoint_clause = Some(ec);
        Ok(true)
    } else {
        Ok(false) // not an endpoint clause
    }
}

/// Parse service clause.
/// The passed tokens MUST start with "ACCESS". There may be a "SIGNAL"
/// token after the "ACCESS" tokens
///
/// The service clause may have a trailing ON <endpoint-clause>.
/// There may also be a signal clause after the service clause. If there is a
/// signal clause, tokens will remain in the queue after this function, otherwise
/// this function will process all the tokens.
///
/// On a successful parse this returns the last token parsed.
fn parse_allow_service_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<Token, CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    // Pop off the "ACCESS" token...
    let _ = putil::require_tt(
        &pa_state.root_tok,
        tokens.next(),
        "ACCESS",
        "allow",
        TokenType::Access,
    )?;

    // Need a service clause now -- parse to end of statement.
    let mut ps = PState::new(&pa_state.root_tok);
    // Signal clause will always
    let popts = ParseOpts::stop_at_any(&[TokenType::On, TokenType::Eos, TokenType::Signal]);
    let mut last_token =
        ps.parse_tags_attrs_and_classname(tokens, classes_idx, &popts, "service clause")?;

    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor != ClassFlavor::Service {
        return Err(CompilationError::AllowStmtParseError(
            format!("not a service class: '{}'", cn),
            pa_state.root_tok.line,
            pa_state.root_tok.col,
        ));
    }
    let mut service_clause = ps.to_clause(ClassFlavor::Service)?;

    // If there are tokens remaining, there are three valid possibilities: we have
    // an ON token, we have a SIGNAL clause, or we have an ON followed by a SIGNAL.
    // If we have an ON followed by a SIGNAL, the queue will match the first branch
    // of the match, then exit the function with the signal still in the queue.
    if let Some(tok) = tokens.peek() {
        match tok.tt {
            TokenType::On => {
                // Previously used tokens.next() above, changed to peek because if we read a
                // Signal that should remain for error checking outside this function call
                tokens.next();

                let mut nested_ps = PState::new(&pa_state.root_tok);

                last_token = nested_ps.parse_tags_attrs_and_classname(
                    tokens,
                    classes_idx,
                    &ParseOpts::stop_at_any(&[TokenType::Eos, TokenType::Signal]),
                    "service endpoint clause",
                )?;

                // This is a good parse if we actually got a endpoint or signal flavor class.
                let cn = nested_ps.class_name.as_ref().unwrap();
                if classes_map.get(cn).unwrap().flavor == ClassFlavor::Endpoint {
                    let service_ec = nested_ps.to_clause(ClassFlavor::Endpoint)?;

                    // Since ZPL could use a defined class in the on clause we need to walk the tree and
                    // gather any attributes.
                    let mut all_endpoint_attrs =
                        collect_all_attributes(&service_ec.class, classes_map);
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
            TokenType::Signal => { // Want to fall through
            }
            _ => {
                return Err(CompilationError::AllowStmtParseError(
                    format!("Expected 'on' or 'signal' not {:?}", tok.tt),
                    pa_state.root_tok.line,
                    pa_state.root_tok.col,
                ));
            }
        }
    }

    pa_state.service_clause = Some(service_clause);
    Ok(last_token)
}

// Expects a signal clause of the form SIGNAL <STRING> TO <SERVICE>
// Since a signal clause is the final clause of the allow statement,
// we expect the EOS token, thus the queue will be empty after execution.
//
// On successful parse this returns the last token parsed and the tokens
// iterator is empty.
fn parse_allow_signal_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    _classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<Token, CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    // Pop off the SIGNAL token
    let _ = putil::require_tt(
        &pa_state.root_tok,
        tokens.next(),
        "SIGNAL",
        "allow",
        TokenType::Signal,
    )?;

    let message: String;
    let target: String;

    // The first part of the signal clause should be a literal to signal
    if let Some(tok) = tokens.next() {
        message = match &tok.tt {
            TokenType::Literal(msg) => msg.clone(),
            _ => {
                return Err(CompilationError::ParseError(
                    format!("Expected a Literal, found: {:?}", tok.tt),
                    tok.line,
                    tok.col,
                ));
            }
        };
    } else {
        return Err(CompilationError::ParseError(
            format!("Signal clause requires a payload"),
            pa_state.root_tok.line,
            pa_state.root_tok.col, // TODO this will provide col 1, not the col where the signal is
        ));
    }

    // The next part should be the token TO
    let _ = putil::require_tt(
        &pa_state.root_tok,
        tokens.next(),
        "TO",
        "allow",
        TokenType::To,
    )?;

    let last_tok: Token;

    // The final portion of the signal clause must be an existing service class
    if let Some(tok) = tokens.next() {
        last_tok = tok.clone();
        // The service does not share a name with a reserved keyword
        if let TokenType::Literal(ref service_name) = tok.tt {
            // We require the requested service to exist in the list of services
            target = if let Some(service_class) = classes_map.get(service_name) {
                if service_class.flavor != ClassFlavor::Service {
                    return Err(CompilationError::ParseError(
                        format!(
                            "{service_name} is not a service, it is of type {:?}",
                            service_class.flavor
                        ),
                        pa_state.root_tok.line,
                        pa_state.root_tok.col, // TODO this will provide col 1, not the col where the signal is
                    ));
                }
                service_class.name.clone()
            } else {
                return Err(CompilationError::ParseError(
                    format!("Invalid service name: {service_name}"),
                    pa_state.root_tok.line,
                    pa_state.root_tok.col, // TODO this will provide col 1, not the col where the signal is
                ));
            };
        } else {
            return Err(CompilationError::ParseError(
                format!("Expected a Literal, found: {:?}", tok.tt),
                tok.line,
                tok.col,
            ));
        }
    } else {
        return Err(CompilationError::ParseError(
            format!("Signal clause requires a service"),
            pa_state.root_tok.line,
            pa_state.root_tok.col, // TODO this will provide col 1, not the col where the signal is
        ));
    }

    // Nothing should follow the signal clause
    // TODO allow for multiple signal clauses
    if tokens.peek().is_some() {
        return Err(CompilationError::ParseError(
            format!("No data should follow a signal clause"),
            pa_state.root_tok.line,
            pa_state.root_tok.col, // TODO this will provide col 1, not the col where the signal is
        ));
    }

    pa_state.signal_clause = Some(Signal::new(message, target));
    return Ok(last_tok);
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
    /// The parsed class name
    class_name: Option<String>,
    class_name_token: Option<Token>,
    /// Additionl parsed attributes
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

    fn to_clause(&self, flavor: ClassFlavor) -> Result<Clause, CompilationError> {
        if self.class_name.is_none() {
            return Err(CompilationError::AllowStmtParseError(
                format!("expected a class name in a {flavor} clause"),
                self.root_tok.line,
                self.root_tok.col,
            ));
        }
        Ok(Clause {
            flavor,
            class: self.class_name.clone().unwrap(), // flavor is not checked
            class_tok: self.class_name_token.as_ref().unwrap().clone(), // always set if class_name is set
            with: self.attrs.clone(),
        })
    }

    /// Parse a class and its attributes.
    ///
    /// On a successful parse, this returns the last token parsed.
    fn parse_tags_attrs_and_classname<'a, I>(
        &mut self,
        tokens: &mut Peekable<I>,
        classes: &HashMap<String, String>,
        opts: &ParseOpts,
        context: &str,
    ) -> Result<Token, CompilationError>
    where
        I: Iterator<Item = &'a Token>,
    {
        let mut last_token = Token::default();
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
                    last_token = tokens.next().unwrap().clone();
                }
                TokenType::Tuple((name, value)) => {
                    // This is an attribute.
                    let attr = Attribute::tuple(name)
                        .values(value.to_vec())
                        .allow_unspecified()
                        .build()?;
                    self.attrs.push(attr);
                    last_token = tokens.next().unwrap().clone();
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
                        last_token = tok.clone();
                    } else {
                        self.attrs
                            .push(Attribute::tag(s).allow_unspecified().build()?);
                        last_token = tokens.next().unwrap().clone();
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

        Ok(last_token)
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
            "allow blue users to access services and signal \"blue\" to service",
            "allow blue users on green endpoints to access services and signal \"blue\" to service",
            "allow blue users to access services on level:seven endpoints and signal \"blue\" to service",
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
            "allow blue users to signal to services",
            "allow signal to services",
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

        assert_eq!(2, clause.client.len(), "{:?}", clause.client); // user & endpoint
        let mut matched = false;
        for lhs_clause in &clause.client {
            if lhs_clause.flavor == ClassFlavor::User {
                matched = true;
                lhs_clause
                    .with
                    .iter()
                    .find(|a| a.to_string() == "#user.blue")
                    .expect("blue tag missing from user clause");
            }
        }
        assert!(matched, "failed to find a user clause");
        matched = false;

        // level:seven attr goes in as an endpoint domain attribute on the service.
        assert_eq!(1, clause.server.len(), "{:?}", clause.server); // service only
        for rhs_clause in &clause.server {
            if rhs_clause.flavor == ClassFlavor::Service {
                matched = true;
                rhs_clause
                    .with
                    .iter()
                    .find(|a| a.to_string() == "endpoint.level:seven")
                    .expect("level:seven tag missing from service clause");
            }
        }
        assert!(matched, "failed to find endpoint class in RHS");
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

        assert_eq!(2, clause.client.len()); // users, endpoints
        let mut matched_user = false;
        let mut matched_endpoint = false;
        for lhs_clause in clause.client {
            // Blue tag goes on user.
            if lhs_clause.flavor == ClassFlavor::User {
                matched_user = true;
                lhs_clause
                    .with
                    .iter()
                    .find(|a| a.to_string() == "#user.blue")
                    .expect("blue tag missing from user clause");
            } else if lhs_clause.flavor == ClassFlavor::Endpoint {
                // level:seven attr goes in as an endpoint attribute
                matched_endpoint = true;
                lhs_clause
                    .with
                    .iter()
                    .find(|a| a.to_string() == "endpoint.level:seven")
                    .expect("level:seven tag missing from endpoint clause");
            }
        }
        assert!(matched_user, "failed to locate user clause in LHS");
        assert!(matched_endpoint, "failed to locate endpoint clause in LHS");
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

        assert_eq!(2, clause.client.len()); // users, endpoints
        assert_eq!(1, clause.server.len()); // services

        let mut matched_user = false;
        let mut matched_endpoint = false;
        let mut matched_service = false;

        for lhs_clause in clause.client {
            match lhs_clause.flavor {
                ClassFlavor::User => {
                    // Blue tag goes on user.
                    matched_user = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_string() == "#user.blue")
                        .expect("blue tag missing from user clause");
                }
                ClassFlavor::Endpoint => {
                    // level:seven attr goes in as an endpoint attribute
                    matched_endpoint = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_string() == "endpoint.level:seven")
                        .expect("level:seven tag missing from endpoint clause");
                }
                _ => (),
            }
        }
        assert!(matched_user, "failed to locate user clause in LHS");
        assert!(matched_endpoint, "failed to locate endpoint clause in LHS");

        for rhs_clause in clause.server {
            match rhs_clause.flavor {
                ClassFlavor::Service => {
                    matched_service = true;
                    rhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_string() == "endpoint.level:eight")
                        .expect("level:eight tag missing from service clause");
                }
                _ => (),
            }
        }
        assert!(matched_service, "failed to locate service clause in RHS");
    }

    #[test]
    fn test_sets_service_attrs_lhs() {
        let statement = "allow blue services on level:seven endpoints to access services on level:eight endpoints";

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

        assert_eq!(3, clause.client.len()); // services, users, endpoints
        assert_eq!(1, clause.server.len()); // services

        let mut matched_user = false;
        let mut matched_endpoint = false;
        let mut matched_service = false;

        for lhs_clause in clause.client {
            match lhs_clause.flavor {
                ClassFlavor::User => {
                    // no attrs.
                    matched_user = true;
                    assert!(lhs_clause.with.is_empty());
                }
                ClassFlavor::Service => {
                    matched_service = true;
                    // Blue tag goes on service.
                    matched_user = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_string() == "#service.blue")
                        .expect(
                            format!("blue tag missing from service clause: {:?}", lhs_clause)
                                .as_str(),
                        );
                }
                ClassFlavor::Endpoint => {
                    // level:seven attr goes in as an endpoint attribute
                    matched_endpoint = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_string() == "endpoint.level:seven")
                        .expect("level:seven tag missing from endpoint clause");
                }
                _ => (),
            }
        }
        assert!(matched_user, "failed to locate user clause in LHS");
        assert!(matched_endpoint, "failed to locate endpoint clause in LHS");
        assert!(matched_service, "failed to locate service clause in LHS");

        for rhs_clause in clause.server {
            match rhs_clause.flavor {
                ClassFlavor::Service => {
                    matched_service = true;
                    rhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_string() == "endpoint.level:eight")
                        .expect("level:eight tag missing from service clause");
                }
                _ => (),
            }
        }
        assert!(matched_service, "failed to locate service clause in RHS");
    }

    #[test]
    fn test_multi_value_attrs() {
        let statement = "allow colors:{blue, red} users on levels:{1, 2} endpoints to access services on levels:{9, 10} endpoints";

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

        assert_eq!(2, clause.client.len()); // users, endpoints
        assert_eq!(1, clause.server.len()); // services

        let mut matched_user = false;
        let mut matched_endpoint = false;
        let mut matched_service = false;

        for lhs_clause in clause.client {
            match lhs_clause.flavor {
                ClassFlavor::User => {
                    // Blue tag goes on user.
                    matched_user = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_string() == "user.colors:{blue, red}")
                        .expect("blue tag missing from user clause");
                }
                ClassFlavor::Endpoint => {
                    // level:seven attr goes in as an endpoint attribute
                    matched_endpoint = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_string() == "endpoint.levels:{1, 2}")
                        .expect("level:seven tag missing from endpoint clause");
                }
                _ => (),
            }
        }
        assert!(matched_user, "failed to locate user clause in LHS");
        assert!(matched_endpoint, "failed to locate endpoint clause in LHS");

        for rhs_clause in clause.server {
            match rhs_clause.flavor {
                ClassFlavor::Service => {
                    matched_service = true;
                    rhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_string() == "endpoint.levels:{9, 10}")
                        .expect("level:eight tag missing from service clause");
                }
                _ => (),
            }
        }
        assert!(matched_service, "failed to locate service clause in RHS");
    }
}
