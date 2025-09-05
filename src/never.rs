use crate::allow::parse_allow;
use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{AllowClause, Class};
use std::collections::HashMap;

/// A "never" statement is just an allow statement preceeded by the token
/// "never".
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
        panic!("parse_never called with non-ALLOW statement");
    }
    if never_statement.len() < 3 {
        return Err(CompilationError::NeverStmtParseError(
            "incomplete never statement".to_string(),
            never_statement[0].line,
            never_statement[0].col,
        ));
    }
    parse_allow(
        &never_statement[1..],
        statement_id,
        classes_idx,
        classes_map,
    )
}
