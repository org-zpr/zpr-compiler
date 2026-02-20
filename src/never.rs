use crate::allow::parse_allow;
use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{AllowClause, Class};
use std::collections::HashMap;

/// A "never" statement is just an allow statement preceeded by the token
/// "never".  Caller must ensure first token is "never".
pub fn parse_never(
    never_statement: &[Token],
    statement_id: usize,
    classes_idx: &HashMap<String, String>,
    classes_map: &HashMap<String, Class>,
) -> Result<AllowClause, CompilationError> {
    if never_statement.is_empty() {
        panic!("parse_never called with empty statement");
    }
    if never_statement[0].tt != TokenType::Never {
        panic!("parse_never called with non-NEVER statement");
    }
    if never_statement.len() < 3 {
        return Err(CompilationError::NeverStmtParseError(
            "incomplete never statement".to_string(),
            never_statement[0].line,
            never_statement[0].col,
        ));
    }
    if never_statement[1].tt != TokenType::Allow {
        return Err(CompilationError::NeverStmtParseError(
            "expected 'allow' after 'never'".to_string(),
            never_statement[1].line,
            never_statement[1].col,
        ));
    }
    let mut allow_clause = parse_allow(
        &never_statement[1..],
        statement_id,
        classes_idx,
        classes_map,
    )?;
    // Since we started with never, we update the span.
    allow_clause.span.0 = never_statement[0].clone().into();
    Ok(allow_clause)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::{context::CompilationCtx, lex::tokenize_str};

    /// Build the default class registry (user, service, endpoint, VisaService)
    /// plus a corresponding name→canonical-name index that includes AKA entries.
    fn make_classes() -> (HashMap<String, String>, HashMap<String, Class>) {
        let mut classes: HashMap<String, Class> = HashMap::new();
        for defclass in Class::defaults() {
            classes.insert(defclass.name.clone(), defclass);
        }
        let mut class_index: HashMap<String, String> = HashMap::new();
        for (name, class) in classes.iter() {
            class_index.insert(name.clone(), name.clone());
            class_index.insert(class.aka.clone(), name.clone());
        }
        (class_index, classes)
    }

    // A lone "never" token (len < 3) must fail with "incomplete never statement".
    #[test]
    fn test_bare_never_fails() {
        let ctx = CompilationCtx::default();
        let tz = tokenize_str("never", &ctx).unwrap();
        let (class_index, classes) = make_classes();
        let err = parse_never(&tz.tokens, 1, &class_index, &classes)
            .expect_err("expected error for bare 'never'");
        assert!(
            err.to_string().contains("incomplete"),
            "unexpected error: {err}"
        );
    }

    // "never" not followed by the "allow" keyword must fail with a message
    // referencing "allow" so the user knows what is expected.
    #[test]
    fn test_never_without_allow_fails() {
        let ctx = CompilationCtx::default();
        let tz = tokenize_str("never users to access services", &ctx).unwrap();
        let (class_index, classes) = make_classes();
        let err = parse_never(&tz.tokens, 1, &class_index, &classes)
            .expect_err("expected error for 'never' without 'allow'");
        assert!(
            err.to_string().contains("allow"),
            "unexpected error: {err}"
        );
    }

    // A well-formed "never allow ..." statement must parse without error and
    // produce a non-empty client and server clause list.
    #[test]
    fn test_valid_never_parses() {
        let ctx = CompilationCtx::default();
        let tz = tokenize_str("never allow blue users to access services", &ctx).unwrap();
        let (class_index, classes) = make_classes();
        let clause = parse_never(&tz.tokens, 1, &class_index, &classes)
            .expect("valid never statement should parse");
        assert!(!clause.client.is_empty());
        assert!(!clause.server.is_empty());
    }

    // parse_never must overwrite span.0 with the "never" token's position so
    // that source locations in error messages point at "never", not "allow".
    #[test]
    fn test_never_span_starts_at_never_token() {
        let ctx = CompilationCtx::default();
        // "never" is at col 1; "allow" follows at col 7.
        let tz = tokenize_str("never allow users to access services", &ctx).unwrap();
        let never_tok = &tz.tokens[0];
        assert_eq!(never_tok.col, 1, "never token should start at col 1");

        let (class_index, classes) = make_classes();
        let clause = parse_never(&tz.tokens, 1, &class_index, &classes).unwrap();

        // The span must be anchored to the "never" token, not the inner "allow".
        assert_eq!(clause.span.0.line, never_tok.line);
        assert_eq!(clause.span.0.col, never_tok.col);
    }
}
