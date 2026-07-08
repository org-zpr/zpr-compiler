use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};

// Given the next token in the list, we error out if that token is not of the expected type.
pub fn require_tt(
    parent_tok: &Token,
    next_tok: Option<&Token>,
    expect: &str,
    statement_type: &str,
    expect_tt: TokenType,
) -> Result<Token, CompilationError> {
    match next_tok {
        Some(tok) => {
            if tok.tt == expect_tt {
                Ok(tok.clone())
            } else {
                Err(CompilationError::ParseError(
                    format!("expected {expect}, found {:?}", tok.tt),
                    tok.line,
                    tok.col,
                ))
            }
        }
        None => Err(CompilationError::ParseError(
            format!("malformed {} (expected {})", statement_type, expect),
            parent_tok.line,
            parent_tok.col,
        )),
    }
}

// Expect the next token in the list to be a literal, and if so we return a copy of the value.
pub fn return_literal(
    parent_tok: &Token,
    next_tok: Option<&Token>,
    expect_desc: &str,
    statement_type: &str,
) -> Result<String, CompilationError> {
    let value = match next_tok {
        Some(tok) => match &tok.tt {
            TokenType::Literal(s) => s,
            _ => {
                return Err(CompilationError::ParseError(
                    format!("expected {} to follow {}", expect_desc, statement_type),
                    tok.line,
                    tok.col,
                ));
            }
        },
        None => {
            return Err(CompilationError::ParseError(
                format!("malformed {}", statement_type),
                parent_tok.line,
                parent_tok.col,
            ));
        }
    };
    Ok(value.clone())
}

// Pluralize a string by adding an "s" or "es" to the end. Does not handle complex pluralization rules, but handles the most common cases.
pub fn pluralize(s: &str) -> String {
    let ls = s.to_lowercase();
    let possible_es = ["s", "sh", "ch", "x", "z"];
    let consonants = "bcdfghjklmnpqrstvwxyz";
    let word_with_consonant_o = ls.ends_with("o")
        && ls
            .chars()
            .rev()
            .nth(1)
            .is_some_and(|c| consonants.contains(c));
    let needs_es = word_with_consonant_o || possible_es.iter().any(|&ending| ls.ends_with(ending));
    let suffix = if needs_es { "es" } else { "s" };
    if s.chars().last().is_some_and(char::is_uppercase) {
        format!("{s}{}", suffix.to_uppercase())
    } else {
        format!("{s}{suffix}")
    }
}

#[test]
fn test_pluralize() {
    assert_eq!(pluralize("mobile-phone"), "mobile-phones");
    assert_eq!(pluralize("box"), "boxes");
    assert_eq!(pluralize("bus"), "buses");
    assert_eq!(pluralize("match"), "matches");
    assert_eq!(pluralize("dish"), "dishes");
    assert_eq!(pluralize("potato"), "potatoes");
    assert_eq!(pluralize("radio"), "radios");
    assert_eq!(pluralize("VisaService"), "VisaServices");
    assert_eq!(pluralize("BOX"), "BOXES");
    assert_eq!(pluralize("POTATO"), "POTATOES");
    assert_eq!(pluralize("o"), "os");
    assert_eq!(pluralize(""), "s");
}
