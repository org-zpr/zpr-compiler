//! allow.rs - parser for allow statements

use std::collections::HashMap;
use std::iter::Peekable;

use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{AllowClause, Class, ClassFlavor, Clause, FPos, Signal};
use crate::putil;
use crate::zpl;
use zpr::policy_types::{AttrDomain, Attribute};

#[derive(Debug, Default)]
struct ParseAllowState {
    root_tok: Token,
    client_device_clause: Option<Clause>,
    client_user_clause: Option<Clause>,
    client_service_clause: Option<Clause>,
    service_clause: Option<Clause>,
    link_clause: Option<Clause>,
    signal_clause: Option<Signal>,
    /// True when the author wrote a trailing `ON <device-clause>` after the
    /// service clause. Its attributes are folded into `service_clause.with`
    /// during parsing, so this flag is the only record that a server-side
    /// device spec was written (issue #144).
    service_on_device_clause_written: bool,
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
        self.client_device_clause.is_none()
            && self.client_user_clause.is_none()
            && self.client_service_clause.is_none()
    }

    /// This consumes all the clauses or panics.
    ///
    /// Note that every allow clause will get a user and device clause in the client vector
    /// even if they are just the default.
    ///
    /// The `server` vector in the [AllowClause] will just have one element -- a service clause
    /// that may have attributes from other domains (eg, device or user attributes).
    fn to_allow_clause(
        &mut self,
        clause_id: usize,
        last_tok: Token,
        inject_authority_markers: bool,
    ) -> AllowClause {
        // A written actor class spec asserts a live authentication for its
        // namespace (issue #144): `allow users ...` must compile to at least
        // `has user.authority`, not to an empty client condition. Inject the
        // marker here, BEFORE the defaults are substituted below, because the
        // `Option` is the only record of whether the author actually wrote
        // the clause -- the default clauses substituted below assert nothing.
        // `never allow` statements skip this: injecting there would narrow a
        // deny, so it would stop denying unauthenticated actors.
        if inject_authority_markers {
            if let Some(c) = self.client_user_clause.as_mut() {
                c.with.push(authority_marker(zpl::KATTR_USER_AUTHORITY));
            }
            if let Some(c) = self.client_device_clause.as_mut() {
                c.with.push(authority_marker(zpl::KATTR_DEVICE_AUTHORITY));
            }
            // A written RHS device spec (`... to access <service> ON <device>`)
            // asserts a live device authentication on the SERVER side. Its
            // attributes were folded into the service clause by
            // parse_allow_service_clause, so the marker goes there too; the
            // key's `device.` prefix keeps it in the device domain.
            if self.service_on_device_clause_written {
                if let Some(c) = self.service_clause.as_mut() {
                    c.with.push(authority_marker(zpl::KATTR_DEVICE_AUTHORITY));
                }
            }
        }

        let mut client_user_clause = self.client_user_clause.take().unwrap_or(Clause::new(
            ClassFlavor::User,
            zpl::DEF_CLASS_USER_NAME,
            self.root_tok.clone(),
        ));

        let mut client_device_clause = self.client_device_clause.take().unwrap_or(Clause::new(
            ClassFlavor::Device,
            zpl::DEF_CLASS_DEVICE_NAME,
            self.root_tok.clone(),
        ));

        // For now keep service as none if it is not yet defined.
        let mut opt_client_service_clause = self.client_service_clause.take();

        // Move any non device attributes from the device clause into the correct one.
        let mut keep_attrs = Vec::new();
        for attr in client_device_clause.with {
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
        client_device_clause.with = keep_attrs;

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
                &AttrDomain::Device => client_device_clause.with.push(attr),
                _ => keep_attrs.push(attr),
            }
        }
        client_user_clause.with = keep_attrs;

        let mut client_clauses = Vec::new();
        client_clauses.push(client_user_clause);
        client_clauses.push(client_device_clause);
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
            link: self.link_clause.take(),
            signal: self.signal_clause.take(),
        }
    }
}

/// Build a `has <key>.authority` presence marker (issue #144).
///
/// A single-valued attribute with no value writes as `AttrOp::Has`, and the
/// `user.` / `device.` key prefix resolves the domain, so no schema change is
/// involved. The key constants are well-formed, so construction cannot fail.
fn authority_marker(key: &str) -> Attribute {
    Attribute::tuple(key)
        .single()
        .build()
        .expect("authority marker key must carry a valid domain prefix")
}

/// First token is an ALLOW which is checked by caller.
///
/// Format of the allow statement is:
///
/// allow (<user-clause>|<service-clause>) on <device-clause> to access <service-clause>
///
/// If there are both device and user/service clauses they are separated by 'on'.
/// You can omit either user or device clauses:
///
/// allow <user-clause> to access <service-clause>
/// allow <service-clause> to access <service-clause>
/// allow <device-clause> to access <service-clause>
///
/// The service clause may be followed by an OVER clause that constrains the links
/// of the communication path (RFC 15), and finally by a SIGNAL clause:
///
/// allow <user-clause> to access <service-clause> over <link-clause>
/// allow <user-clause> to access <service-clause> over <link-clause> and signal ...
///
/// `classes_idx` maps class names and AKA names to their canonical names (eg, "services" -> "service").
/// `classs_map` maps class canonical name to [Class] struct.
pub fn parse_allow(
    allow_statement: &[Token],
    statement_id: usize,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<AllowClause, CompilationError> {
    parse_allow_impl(
        allow_statement,
        statement_id,
        classes_idx,
        classes_map,
        true,
    )
}

/// Like [parse_allow], but lets the caller suppress the authority presence
/// markers. `never allow` statements (see [crate::never::parse_never]) must
/// not carry them: a marker would NARROW the deny, so a bare
/// `never allow users ...` would stop denying unauthenticated actors.
pub fn parse_allow_impl(
    allow_statement: &[Token],
    statement_id: usize,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
    inject_authority_markers: bool,
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

            // If we hit a TO then we expect one to have parsed an device, user or even service clause.
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
                        ClassFlavor::Device => {
                            let dc = ps.to_clause(ClassFlavor::Device)?;
                            parse_state.client_device_clause = Some(dc);
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
                    // Hit ON which means we must have parsed a user clause, and we expect an device clause to follow.
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
    // If it's a ON then we expect an device clause next.
    // If it's a TO then we expect a RHS service clause next.
    let tok = tokens.next().unwrap();
    match tok.tt {
        TokenType::On => {
            if parse_state.client_clauses_is_none() {
                panic!("assertion fails - no client clauses on LHS");
            }
            if parse_state.client_device_clause.is_some() {
                return Err(CompilationError::AllowStmtParseError(
                    format!("device clause on RHS preceeds ON"),
                    parse_state.root_tok.line,
                    parse_state.root_tok.col,
                ));
            }
            // Ok, now parse an DEVICE clause, returns having found but not parsed 'TO'.
            if !try_parse_allow_device_clause(
                &mut parse_state,
                &mut tokens,
                classes_idx,
                classes_map,
            )? {
                // Hmm, a non error failure?
                return Err(CompilationError::AllowStmtParseError(
                    "expected an device clause to follow ON".to_string(),
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

    // The remaining tokens should start with "access ..." which we pass to the service class
    // parser. It stops at an OVER or a SIGNAL, leaving those clauses in the queue for us.
    let mut last_tok =
        parse_allow_service_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?;

    // An optional OVER clause constrains the links of the communication path.
    if let Some(tok) = tokens.peek() {
        if tok.tt == TokenType::Over {
            last_tok =
                parse_allow_over_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?;
        }
    }

    // An optional SIGNAL clause, which must come last.
    if tokens.peek().is_some() {
        last_tok =
            parse_allow_signal_clause(&mut parse_state, &mut tokens, classes_idx, classes_map)?;
    }

    let mut ac = parse_state.to_allow_clause(statement_id, last_tok, inject_authority_markers);

    // Set any UNSPECIFIED (lacking domain) attributes to the domain of the clause they are in.

    for client_clause in &mut ac.client {
        for attr in &mut client_clause.with {
            if attr.is_unspecified_domain() {
                let flavor = classes_map.get(&client_clause.class).unwrap().flavor;
                attr.set_domain(flavor.into());
            }
        }
    }
    for server_clause in &mut ac.server {
        for attr in &mut server_clause.with {
            if attr.is_unspecified_domain() {
                let flavor = classes_map.get(&server_clause.class).unwrap().flavor;
                attr.set_domain(flavor.into());
            }
        }
    }
    // Attributes in the OVER clause always live in the link domain.
    if let Some(link_clause) = &mut ac.link {
        for attr in &mut link_clause.with {
            if attr.is_unspecified_domain() {
                attr.set_domain(AttrDomain::Link);
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
            ClassFlavor::Device => usr_ep_svc.1 += 1,
            ClassFlavor::Service => usr_ep_svc.2 += 1,
            _ => (),
        }
    }
    if let Some(err_msg) = match usr_ep_svc {
        (a, _, _) if a > 1 => Some(format!("too many user clauses {explain}")),
        (_, b, _) if b > 1 => Some(format!("too may device clauses {explain}")),
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

/// Parse from <device-clause> up to the 'TO' (of 'TO ACCESS')
/// If this succeeds, it sets the device clause in the [ParseAllowState].
fn try_parse_allow_device_clause<'a, I>(
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
        "device clause",
    )?;

    // This is a good parse if we actually got a device flavor class.
    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor == ClassFlavor::Device {
        let ec = ps.to_clause(ClassFlavor::Device)?;
        pa_state.client_device_clause = Some(ec);
        Ok(true)
    } else {
        Ok(false) // not an device clause
    }
}

/// Parse service clause.
/// The passed tokens MUST start with "ACCESS". There may be a "SIGNAL"
/// token after the "ACCESS" tokens
///
/// The service clause may have a trailing ON <device-clause>.
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
    let popts = ParseOpts::stop_at_any(&[
        TokenType::On,
        TokenType::Eos,
        TokenType::Signal,
        TokenType::Over,
    ]);
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

    // If there are tokens remaining, the valid possibilities are: an ON clause, an
    // OVER clause, a SIGNAL clause, or an ON followed by an OVER and/or a SIGNAL.
    // In the ON case the queue will match the first branch of the match, then exit
    // the function with the OVER/SIGNAL still in the queue for the caller.
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
                    &ParseOpts::stop_at_any(&[TokenType::Eos, TokenType::Signal, TokenType::Over]),
                    "service device clause",
                )?;

                // This is a good parse if we actually got a device or signal flavor class.
                let cn = nested_ps.class_name.as_ref().unwrap();
                if classes_map.get(cn).unwrap().flavor == ClassFlavor::Device {
                    // Record that the author wrote a server-side device spec so
                    // to_allow_clause can inject the device authority marker
                    // (issue #144) -- the clause itself is folded into
                    // service_clause.with below and loses its identity.
                    pa_state.service_on_device_clause_written = true;
                    let service_ec = nested_ps.to_clause(ClassFlavor::Device)?;

                    // Since ZPL could use a defined class in the on clause we need to walk the tree and
                    // gather any attributes.
                    let mut all_device_attrs =
                        collect_all_attributes(&service_ec.class, classes_map);
                    all_device_attrs.extend(service_ec.with);

                    for ec_attr in &all_device_attrs {
                        let mut domained_attr = ec_attr.clone();
                        if domained_attr.is_unspecified_domain() {
                            domained_attr.set_domain(AttrDomain::Device);
                        } else if !domained_attr.is_domain(AttrDomain::Device) {
                            // This is not permitted. You can only talk about devices in the ON clause.
                            return Err(CompilationError::AllowStmtParseError(
                                format!(
                                    "illegal non-device attribute in service ON clause: '{}'",
                                    domained_attr.to_instance_string()
                                ),
                                pa_state.root_tok.line,
                                pa_state.root_tok.col,
                            ));
                        }
                        service_clause.with.push(domained_attr); // TODO: Are these already in device domain?
                    }
                } else {
                    return Err(CompilationError::AllowStmtParseError(
                        format!(
                            "expected an device class in service ON clause, got: '{}'",
                            cn
                        ),
                        pa_state.root_tok.line,
                        pa_state.root_tok.col,
                    ));
                }
            }
            TokenType::Signal => { // Want to fall through
            }
            TokenType::Over => { // Want to fall through
            }
            _ => {
                return Err(CompilationError::AllowStmtParseError(
                    format!("Expected 'on', 'over' or 'signal' not {:?}", tok.tt),
                    pa_state.root_tok.line,
                    pa_state.root_tok.col,
                ));
            }
        }
    }

    pa_state.service_clause = Some(service_clause);
    Ok(last_token)
}

/// Parse the OVER clause of an allow statement, which constrains the links of the
/// communication path. The passed tokens MUST start with "OVER".
///
/// Grammar: `over <link-clause>`, where the link clause names the built-in `link`
/// (or `links`) class along with zero or more attribute expressions, exactly like
/// the other clause specs. Per RFC 15:
///
/// ```text
/// Allow sales employees to access customer databases over secure links.
/// Allow finance users to access payroll-services over location:usa links.
/// ```
///
/// A SIGNAL clause may follow, so parsing stops at (without consuming) a SIGNAL.
///
/// On a successful parse this returns the last token parsed and sets the link
/// clause in the [ParseAllowState].
fn parse_allow_over_clause<'a, I>(
    pa_state: &mut ParseAllowState,
    tokens: &mut Peekable<I>,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<Token, CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    // Pop off the "OVER" token...
    let over_tok = putil::require_tt(
        &pa_state.root_tok,
        tokens.next(),
        "OVER",
        "allow",
        TokenType::Over,
    )?;

    // Only one OVER clause is permitted per statement.
    if pa_state.link_clause.is_some() {
        return Err(CompilationError::AllowStmtParseError(
            "only one OVER clause is permitted per statement".to_string(),
            over_tok.line,
            over_tok.col,
        ));
    }

    let mut ps = PState::new(&pa_state.root_tok);
    let last_token = ps.parse_tags_attrs_and_classname(
        tokens,
        classes_idx,
        &ParseOpts::stop_at_any(&[TokenType::Eos, TokenType::Signal]),
        "link (OVER) clause",
    )?;

    // The class named in an OVER clause must be the link class.
    let cn = ps.class_name.as_ref().unwrap();
    if classes_map.get(cn).unwrap().flavor != ClassFlavor::Link {
        return Err(CompilationError::AllowStmtParseError(
            format!("expected a link class in OVER clause, got: '{}'", cn),
            over_tok.line,
            over_tok.col,
        ));
    }

    let link_clause = ps.to_clause(ClassFlavor::Link)?;

    // Only link attributes may be constrained by an OVER clause. An attribute that
    // was explicitly qualified with another domain (eg "user.foo") is an error;
    // unqualified ones are defaulted to the link domain by the caller.
    for attr in &link_clause.with {
        if !attr.is_unspecified_domain() && !attr.is_domain(AttrDomain::Link) {
            return Err(CompilationError::AllowStmtParseError(
                format!(
                    "illegal non-link attribute in OVER clause: '{}'",
                    attr.to_instance_string()
                ),
                over_tok.line,
                over_tok.col,
            ));
        }
    }

    pa_state.link_clause = Some(link_clause);
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
    classes_idx: &HashMap<String, String>,
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
            target = if let Some(service_class) = classes_idx
                .get(&service_name.to_lowercase())
                .and_then(|cn| classes_map.get(cn))
            {
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
                    if let Some(class) = classes.get(&s.to_lowercase()) {
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

    /// Build the default class registry and the canonical-name index (including AKAs).
    fn default_classes() -> (HashMap<String, String>, HashMap<String, Class>) {
        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            for n in class.iterate_all_names() {
                class_index.insert(n.to_lowercase(), name.clone());
            }
        }
        (class_index, classes)
    }

    #[test]
    fn test_parses_valid_on_clause() {
        let valids = vec![
            "allow blue users to access services on level:seven devices",
            "allow blue users to access services on orange devices",
            "allow blue users to access services on orange, level:seven devices",
            "allow blue users on green devices to access services",
            "allow blue users to access services and signal \"blue\" to service",
            "allow blue users on green devices to access services and signal \"blue\" to service",
            "allow blue users to access services on level:seven devices and signal \"blue\" to service",
        ];

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            for n in class.iterate_all_names() {
                class_index.insert(n.to_lowercase(), name.clone());
            }
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

    // --- OVER clause (link constraints, RFC 15) ---

    #[test]
    fn test_parses_valid_over_clause() {
        // The first two are the literal examples from RFC 15; the rest cover the
        // interaction with the other optional clauses.
        let valids = vec![
            "allow sales users to access customer services over secure links",
            "allow finance users to access payroll services over location:usa links",
            "allow blue users on green devices to access services over secure links",
            "allow blue users to access services on level:seven devices over secure links",
            "allow blue users to access services over secure links and signal \"blue\" to service",
            "allow blue users to access services over link",
            "allow blue users to access services over secure, location:usa links",
        ];

        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();

        for statement in &valids {
            let tz = tokenize_str(statement, &cctx).unwrap();
            let clause = parse_allow(&tz.tokens, 1, &class_index, &classes).unwrap_or_else(|e| {
                panic!("valid statement failed to parse: '{statement}': {e:?}")
            });
            let link = clause
                .link
                .unwrap_or_else(|| panic!("no link clause captured for: '{statement}'"));
            assert_eq!(link.flavor, ClassFlavor::Link);
            assert_eq!(link.class, "link");
        }
    }

    #[test]
    fn test_over_clause_attributes_land_in_link_domain() {
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(
            "allow finance users to access payroll services over secure, location:usa links",
            &cctx,
        )
        .unwrap();
        let clause = parse_allow(&tz.tokens, 1, &class_index, &classes).unwrap();

        let link = clause.link.expect("expected a link clause");
        assert_eq!(link.with.len(), 2, "expected both link attributes");
        for attr in &link.with {
            assert!(
                attr.is_domain(AttrDomain::Link),
                "attribute '{}' should be in the link domain",
                attr.to_instance_string()
            );
        }
    }

    #[test]
    fn test_no_over_clause_leaves_link_none() {
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str("allow blue users to access services", &cctx).unwrap();
        let clause = parse_allow(&tz.tokens, 1, &class_index, &classes).unwrap();
        assert!(clause.link.is_none());
    }

    #[test]
    fn test_fails_on_invalid_over_clause() {
        let invalids = vec![
            // OVER must name the link class, not some other flavor.
            "allow blue users to access services over green devices",
            "allow blue users to access services over other services",
            // No class named at all.
            "allow blue users to access services over secure",
            // Empty over clause.
            "allow blue users to access services over",
            // Only one over clause per statement.
            "allow blue users to access services over secure links over fast links",
            // The signal clause must be last.
            "allow blue users to access services and signal \"blue\" to service over secure links",
            // Attributes explicitly in another domain are not link constraints.
            "allow blue users to access services over user.secure links",
        ];

        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();

        for statement in &invalids {
            // Some of these fail at tokenization, the rest at parse time; either
            // is acceptable, what matters is that none of them is accepted.
            let Ok(tz) = tokenize_str(statement, &cctx) else {
                continue;
            };
            assert!(
                parse_allow(&tz.tokens, 1, &class_index, &classes).is_err(),
                "invalid statement unexpectedly parsed: '{statement}'"
            );
        }
    }

    #[test]
    fn test_over_clause_accepts_singular_and_plural_and_casing() {
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        for statement in [
            "allow blue users to access services over secure link",
            "allow blue users to access services over secure links",
            "allow blue users to access services OVER secure links",
            "allow blue users to access services Over secure links",
        ] {
            let tz = tokenize_str(statement, &cctx).unwrap();
            let clause = parse_allow(&tz.tokens, 1, &class_index, &classes)
                .unwrap_or_else(|e| panic!("'{statement}' should parse: {e:?}"));
            assert!(
                clause.link.is_some(),
                "'{statement}' should set link clause"
            );
        }
    }

    #[test]
    fn test_fails_on_invalid_on_clause() {
        let invalids = vec![
            "allow blue users to access services on",
            "allow blue users to access services on level:seven on devices",
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
            for n in class.iterate_all_names() {
                class_index.insert(n.to_lowercase(), name.clone());
            }
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
        let statement = "allow blue users to access services on level:seven devices";

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            for n in class.iterate_all_names() {
                class_index.insert(n.to_lowercase(), name.clone());
            }
        }

        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let tokens = tz.tokens;
        let clause = parse_allow(&tokens, 1, &class_index, &classes).unwrap();

        // Blue tag goes on user.

        assert_eq!(2, clause.client.len(), "{:?}", clause.client); // user & device
        let mut matched = false;
        for lhs_clause in &clause.client {
            if lhs_clause.flavor == ClassFlavor::User {
                matched = true;
                lhs_clause
                    .with
                    .iter()
                    .find(|a| a.to_instance_string() == "#user.blue")
                    .expect("blue tag missing from user clause");
            }
        }
        assert!(matched, "failed to find a user clause");
        matched = false;

        // level:seven attr goes in as an device domain attribute on the service.
        assert_eq!(1, clause.server.len(), "{:?}", clause.server); // service only
        for rhs_clause in &clause.server {
            if rhs_clause.flavor == ClassFlavor::Service {
                matched = true;
                rhs_clause
                    .with
                    .iter()
                    .find(|a| a.to_instance_string() == "device.level:seven")
                    .expect("level:seven tag missing from service clause");
            }
        }
        assert!(matched, "failed to find device class in RHS");
    }

    #[test]
    fn test_sets_attrs_correctly_user_on() {
        let statement = "allow blue users on level:seven devices to access services";

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            for n in class.iterate_all_names() {
                class_index.insert(n.to_lowercase(), name.clone());
            }
        }

        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let tokens = tz.tokens;
        let clause = parse_allow(&tokens, 1, &class_index, &classes).unwrap();

        assert_eq!(2, clause.client.len()); // users, devices
        let mut matched_user = false;
        let mut matched_device = false;
        for lhs_clause in clause.client {
            // Blue tag goes on user.
            if lhs_clause.flavor == ClassFlavor::User {
                matched_user = true;
                lhs_clause
                    .with
                    .iter()
                    .find(|a| a.to_instance_string() == "#user.blue")
                    .expect("blue tag missing from user clause");
            } else if lhs_clause.flavor == ClassFlavor::Device {
                // level:seven attr goes in as an device attribute
                matched_device = true;
                lhs_clause
                    .with
                    .iter()
                    .find(|a| a.to_instance_string() == "device.level:seven")
                    .expect("level:seven tag missing from device clause");
            }
        }
        assert!(matched_user, "failed to locate user clause in LHS");
        assert!(matched_device, "failed to locate device clause in LHS");
    }

    #[test]
    fn test_sets_attrs_correctly_two_on() {
        let statement =
            "allow blue users on level:seven devices to access services on level:eight devices";

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            for n in class.iterate_all_names() {
                class_index.insert(n.to_lowercase(), name.clone());
            }
        }

        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let tokens = tz.tokens;
        let clause = parse_allow(&tokens, 1, &class_index, &classes).unwrap();

        assert_eq!(2, clause.client.len()); // users, devices
        assert_eq!(1, clause.server.len()); // services

        let mut matched_user = false;
        let mut matched_device = false;
        let mut matched_service = false;

        for lhs_clause in clause.client {
            match lhs_clause.flavor {
                ClassFlavor::User => {
                    // Blue tag goes on user.
                    matched_user = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_instance_string() == "#user.blue")
                        .expect("blue tag missing from user clause");
                }
                ClassFlavor::Device => {
                    // level:seven attr goes in as an device attribute
                    matched_device = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_instance_string() == "device.level:seven")
                        .expect("level:seven tag missing from device clause");
                }
                _ => (),
            }
        }
        assert!(matched_user, "failed to locate user clause in LHS");
        assert!(matched_device, "failed to locate device clause in LHS");

        for rhs_clause in clause.server {
            match rhs_clause.flavor {
                ClassFlavor::Service => {
                    matched_service = true;
                    rhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_instance_string() == "device.level:eight")
                        .expect("level:eight tag missing from service clause");
                }
                _ => (),
            }
        }
        assert!(matched_service, "failed to locate service clause in RHS");
    }

    #[test]
    fn test_sets_service_attrs_lhs() {
        let statement =
            "allow blue services on level:seven devices to access services on level:eight devices";

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            for n in class.iterate_all_names() {
                class_index.insert(n.to_lowercase(), name.clone());
            }
        }

        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let tokens = tz.tokens;
        let clause = parse_allow(&tokens, 1, &class_index, &classes).unwrap();

        assert_eq!(3, clause.client.len()); // services, users, devices
        assert_eq!(1, clause.server.len()); // services

        let mut matched_user = false;
        let mut matched_device = false;
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
                        .find(|a| a.to_instance_string() == "#service.blue")
                        .expect(
                            format!("blue tag missing from service clause: {:?}", lhs_clause)
                                .as_str(),
                        );
                }
                ClassFlavor::Device => {
                    // level:seven attr goes in as an device attribute
                    matched_device = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_instance_string() == "device.level:seven")
                        .expect("level:seven tag missing from device clause");
                }
                _ => (),
            }
        }
        assert!(matched_user, "failed to locate user clause in LHS");
        assert!(matched_device, "failed to locate device clause in LHS");
        assert!(matched_service, "failed to locate service clause in LHS");

        for rhs_clause in clause.server {
            match rhs_clause.flavor {
                ClassFlavor::Service => {
                    matched_service = true;
                    rhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_instance_string() == "device.level:eight")
                        .expect("level:eight tag missing from service clause");
                }
                _ => (),
            }
        }
        assert!(matched_service, "failed to locate service clause in RHS");
    }

    #[test]
    fn test_multi_value_attrs() {
        let statement = "allow colors:{blue, red} users on levels:{1, 2} devices to access services on levels:{9, 10} devices";

        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            for n in class.iterate_all_names() {
                class_index.insert(n.to_lowercase(), name.clone());
            }
        }

        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let tokens = tz.tokens;
        let clause = parse_allow(&tokens, 1, &class_index, &classes).unwrap();

        assert_eq!(2, clause.client.len()); // users, devices
        assert_eq!(1, clause.server.len()); // services

        let mut matched_user = false;
        let mut matched_device = false;
        let mut matched_service = false;

        for lhs_clause in clause.client {
            match lhs_clause.flavor {
                ClassFlavor::User => {
                    matched_user = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_instance_string() == "user.colors:{blue, red}")
                        .expect("colors{blue,red} missing from user clause");
                }
                ClassFlavor::Device => {
                    matched_device = true;
                    lhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_instance_string() == "device.levels:{1, 2}")
                        .expect("levels{1,2} missing from device clause");
                }
                _ => (),
            }
        }
        assert!(matched_user, "failed to locate user clause in LHS");
        assert!(matched_device, "failed to locate device clause in LHS");

        for rhs_clause in clause.server {
            match rhs_clause.flavor {
                ClassFlavor::Service => {
                    matched_service = true;
                    rhs_clause
                        .with
                        .iter()
                        .find(|a| a.to_instance_string() == "device.levels:{9, 10}")
                        .expect("levels{9,10} missing from service clause");
                }
                _ => (),
            }
        }
        assert!(matched_service, "failed to locate service clause in RHS");
    }

    // Pointing a signal clause at a non-service class (e.g. the built-in "user")
    // must fail because signals can only target services.
    #[test]
    fn test_signal_non_service_target() {
        let statement = r#"allow users to access services and signal "x" to user"#;
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        match parse_allow(&tz.tokens, 1, &class_index, &classes) {
            Ok(c) => panic!("should have failed: signal target is not a service: {c:?}"),
            Err(e) => assert!(
                e.to_string().contains("not a service"),
                "unexpected error: {e}"
            ),
        }
    }

    // Pointing a signal clause at a class name that does not exist at all must
    // fail with an "Invalid service name" error.
    #[test]
    fn test_signal_unknown_service() {
        let statement = r#"allow users to access services and signal "x" to nosuchclass"#;
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        match parse_allow(&tz.tokens, 1, &class_index, &classes) {
            Ok(c) => panic!("should have failed: unknown signal target: {c:?}"),
            Err(e) => assert!(
                e.to_string().contains("Invalid service name"),
                "unexpected error: {e}"
            ),
        }
    }

    // A signal clause that has no message payload (the literal between "signal"
    // and "to") must fail with an informative error.
    #[test]
    fn test_signal_missing_message() {
        // "to" immediately follows "signal" — no string literal for the message
        let statement = "allow users to access services and signal to service";
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        match parse_allow(&tz.tokens, 1, &class_index, &classes) {
            Ok(c) => panic!("should have failed: signal has no message: {c:?}"),
            Err(e) => assert!(e.to_string().contains("Literal"), "unexpected error: {e}"),
        }
    }

    // A signal clause that has a message but no "to" keyword before the service
    // name must fail because "to" is required syntax.
    #[test]
    fn test_signal_missing_to() {
        let statement = r#"allow users to access services and signal "x" service"#;
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        match parse_allow(&tz.tokens, 1, &class_index, &classes) {
            Ok(c) => panic!("should have failed: signal missing TO: {c:?}"),
            Err(e) => assert!(
                e.to_string().contains("TO") || e.to_string().contains("expected"),
                "unexpected error: {e}"
            ),
        }
    }

    // A signal clause that ends after "to" with no service name must fail
    // because the target service is required.
    #[test]
    fn test_signal_missing_service() {
        let statement = r#"allow users to access services and signal "x" to"#;
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        match parse_allow(&tz.tokens, 1, &class_index, &classes) {
            Ok(c) => panic!("should have failed: signal missing service name: {c:?}"),
            Err(e) => assert!(e.to_string().contains("service"), "unexpected error: {e}"),
        }
    }

    // Extra tokens after the signal clause (which must be the last clause) must
    // be rejected because the grammar does not allow anything after the signal.
    #[test]
    fn test_signal_trailing_tokens() {
        let statement = r#"allow users to access services and signal "x" to service extra"#;
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        match parse_allow(&tz.tokens, 1, &class_index, &classes) {
            Ok(c) => panic!("should have failed: tokens after signal clause: {c:?}"),
            Err(e) => assert!(e.to_string().contains("signal"), "unexpected error: {e}"),
        }
    }

    // Using a non-device class (e.g. "users") in the ON clause on the RHS of
    // an allow statement (after the service) must fail because only device
    // classes are valid there.
    #[test]
    fn test_service_on_non_device_class() {
        let statement = "allow blue users to access services on users";
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        match parse_allow(&tz.tokens, 1, &class_index, &classes) {
            Ok(c) => panic!("should have failed: ON clause class is not an device: {c:?}"),
            Err(e) => assert!(e.to_string().contains("device"), "unexpected error: {e}"),
        }
    }

    // ---- Authority presence markers (issue #144) ----

    /// Parse a statement and return, per flavor, the list of zplc keys in the
    /// matching client clause (empty list when the clause has no attributes).
    fn client_keys_by_flavor(statement: &str) -> HashMap<ClassFlavor, Vec<String>> {
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let clause = parse_allow(&tz.tokens, 1, &class_index, &classes)
            .unwrap_or_else(|e| panic!("'{statement}' should parse: {e:?}"));
        let mut out = HashMap::new();
        for c in &clause.client {
            let mut keys: Vec<String> = c.with.iter().map(|a| a.zplc_key()).collect();
            keys.sort();
            out.insert(c.flavor, keys);
        }
        out
    }

    // A bare written `users` spec must emit `has user.authority` and nothing
    // else; the synthesized device clause must stay empty.
    #[test]
    fn test_authority_marker_bare_users() {
        let keys = client_keys_by_flavor("allow users to access services");
        assert_eq!(keys[&ClassFlavor::User], vec!["user.authority"]);
        assert!(keys[&ClassFlavor::Device].is_empty());
    }

    // A bare written `devices` spec: `has device.authority` only, user clause empty.
    #[test]
    fn test_authority_marker_bare_devices() {
        let keys = client_keys_by_flavor("allow devices to access services");
        assert_eq!(keys[&ClassFlavor::Device], vec!["device.authority"]);
        assert!(keys[&ClassFlavor::User].is_empty());
    }

    // An LHS service spec gets neither marker: libeval matching is already
    // service-centric, and no user/device clause was written.
    #[test]
    fn test_authority_marker_bare_services_lhs() {
        let keys = client_keys_by_flavor("allow services to access services");
        assert!(keys[&ClassFlavor::User].is_empty());
        assert!(keys[&ClassFlavor::Device].is_empty());
        // The written service clause gets no authority marker either.
        assert!(
            !keys[&ClassFlavor::Service]
                .iter()
                .any(|k| k.contains("authority")),
            "service clause must not carry an authority marker: {:?}",
            keys[&ClassFlavor::Service]
        );
    }

    // `users on devices`: both actor clauses were written, so both markers.
    #[test]
    fn test_authority_marker_users_on_devices() {
        let keys = client_keys_by_flavor("allow users on devices to access services");
        assert_eq!(keys[&ClassFlavor::User], vec!["user.authority"]);
        assert_eq!(keys[&ClassFlavor::Device], vec!["device.authority"]);
    }

    // A constrained user spec keeps its written attribute AND gains the marker.
    #[test]
    fn test_authority_marker_with_written_attribute() {
        let keys = client_keys_by_flavor("allow domain:example users to access services");
        assert_eq!(
            keys[&ClassFlavor::User],
            vec!["user.authority", "user.domain"]
        );
    }

    // An authored valued form of the marker key parses alongside the injected
    // valueless marker; squash_attributes later collapses the pair to the
    // valued one (asserted end-to-end in the compilation tests).
    #[test]
    fn test_authority_marker_authored_value_coexists_at_parse() {
        let keys = client_keys_by_flavor("allow user.authority:google users to access services");
        assert_eq!(
            keys[&ClassFlavor::User],
            vec!["user.authority", "user.authority"]
        );
    }

    /// Parse a statement and return the sorted zplc keys of the server-side
    /// service clause's attributes.
    fn server_keys(statement: &str) -> Vec<String> {
        let (class_index, classes) = default_classes();
        let cctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &cctx).unwrap();
        let clause = parse_allow(&tz.tokens, 1, &class_index, &classes)
            .unwrap_or_else(|e| panic!("'{statement}' should parse: {e:?}"));
        let sc = clause.get_server_service_clause().expect("server clause");
        let mut keys: Vec<String> = sc.with.iter().map(|a| a.zplc_key()).collect();
        keys.sort();
        keys
    }

    // A written RHS device spec (`... on devices`) must emit the device
    // authority marker into the server-side service clause (issue #144).
    #[test]
    fn test_authority_marker_rhs_devices() {
        assert_eq!(
            server_keys("allow users to access services on devices"),
            vec!["device.authority"]
        );
    }

    // No RHS device spec written -> no marker in the service clause.
    #[test]
    fn test_authority_marker_no_rhs_devices() {
        assert!(server_keys("allow users to access services").is_empty());
    }

    // A constrained RHS device spec keeps its written attribute AND gains
    // the marker.
    #[test]
    fn test_authority_marker_rhs_devices_with_attribute() {
        assert_eq!(
            server_keys("allow users to access services on color:blue devices"),
            vec!["device.authority", "device.color"]
        );
    }
}
