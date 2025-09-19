use std::fs;
use std::path::Path;

use crate::context::CompilationCtx;
use crate::errors::CompilationError;
use crate::zplstr::{ZPLStr, ZPLStrBuilder};

#[derive(Debug, PartialEq, Clone)]
pub enum TokenType {
    Undefined, // default value, never parsed
    Never,
    Allow,
    Define,
    With,
    Without,
    To,     // to must preceed access
    Access, // access must be preceeded by to
    And,    // "," is AND as is "and" as is ", and"
    Comma,
    As,
    AkA,
    From,
    Tag,
    Tags,
    On, // starts an endpoint clause
    Optional,
    Multiple,
    Literal(String),
    Tuple((String, String)),
    Period,
    Eos, // means "end of statement" but is never actually created
    Signal,
}

#[allow(dead_code)]
pub fn tuple_from_strs(name: &str, value: &str) -> TokenType {
    TokenType::Tuple((String::from(name), String::from(value)))
}

#[derive(Debug, PartialEq, Clone)]
pub struct Token {
    pub tt: TokenType,
    pub line: usize,
    pub col: usize,
}

impl Token {
    pub fn new_from_str(s: &ZPLStr, line: usize, col: usize) -> Token {
        if s.is_tuple() {
            return Token::new(TokenType::Tuple(s.as_tuple()), line, col);
        }
        let ls = s.as_atom().to_lowercase();
        let tok = match ls.as_str() {
            "never" => TokenType::Never,
            "allow" => TokenType::Allow,
            "define" => TokenType::Define,
            "with" => TokenType::With,
            "without" => TokenType::Without,
            "to" => TokenType::To,
            "access" => TokenType::Access,
            "and" => TokenType::And,
            "," => TokenType::Comma,
            "as" => TokenType::As,
            "aka" => TokenType::AkA,
            "from" => TokenType::From,
            "tag" => TokenType::Tag,
            "tags" => TokenType::Tags,
            "on" => TokenType::On,
            "optional" => TokenType::Optional,
            "multiple" => TokenType::Multiple,
            "." => TokenType::Period,
            "signal" => TokenType::Signal,
            _ => TokenType::Literal(s.as_atom()),
        };
        Token::new(tok, line, col)
    }

    pub fn new(tt: TokenType, line: usize, col: usize) -> Token {
        Token { tt, line, col }
    }
}

impl Default for Token {
    fn default() -> Self {
        Token {
            tt: TokenType::Undefined,
            line: 0,
            col: 0,
        }
    }
}

#[derive(Debug)]
pub struct Tokenization {
    pub tokens: Vec<Token>,
}

pub fn tokenize(zpl_in: &Path, ctx: &CompilationCtx) -> Result<Tokenization, CompilationError> {
    let zpl = fs::read_to_string(zpl_in).map_err(|e| {
        CompilationError::FileError(format!("failed to read ZPL file {:?}: {}", zpl_in, e))
    })?;
    tokenize_str(&zpl, ctx)
}

enum QuotingType {
    None,
    Single,
    Double,
}

impl QuotingType {
    fn is_quoting(&self) -> bool {
        match self {
            QuotingType::None => false,
            _ => true,
        }
    }

    /// Panics if not called with a valid quote character.
    fn set_quoting(&mut self, c: char) {
        match c {
            '\'' | '`' => *self = QuotingType::Single,
            '\"' => *self = QuotingType::Double,
            _ => panic!("call to set_quoting with invalid char: '{c}'"),
        }
    }

    fn is_match(&self, c: char) -> bool {
        match self {
            QuotingType::None => false,
            QuotingType::Single => c == '\'' || c == '`',
            QuotingType::Double => c == '\"',
        }
    }
}

pub fn tokenize_str(zpl: &str, ctx: &CompilationCtx) -> Result<Tokenization, CompilationError> {
    let mut tokens = Vec::new();
    let mut line = 1;
    let mut col = 1;
    let mut chars = zpl.chars().peekable();

    let mut current_word = ZPLStrBuilder::new();
    let mut current_start = (line, col);
    let mut quoting = QuotingType::None;

    while let Some(c) = chars.next() {
        match c {
            '\n' => {
                if quoting.is_quoting() {
                    // quoted strings should not span lines.
                    return Err(CompilationError::UnterminatedQuote(
                        current_start.0,
                        current_start.1,
                    ));
                }
                if current_word.len() > 0 {
                    if !current_word.is_sugar() {
                        tokens.push(Token::new_from_str(
                            &current_word.build(),
                            current_start.0,
                            current_start.1,
                        ));
                    }
                    current_word.clear();
                }
                line += 1;
                col = 1;
            }
            '\t' => {
                // tab?
                if current_word.len() > 0 {
                    // Then treat as a delimiter
                    if !current_word.is_sugar() {
                        tokens.push(Token::new_from_str(
                            &current_word.build(),
                            current_start.0,
                            current_start.1,
                        ));
                    }
                    current_word.clear();
                }
                col += 1;
            }
            ' ' => {
                // if we are quoting the literal, keep space, otherwise this is a delimiter
                if current_word.len() > 0 {
                    if quoting.is_quoting() {
                        current_word.push(c, true, line, col)?;
                    } else {
                        if !current_word.is_sugar() {
                            tokens.push(Token::new_from_str(
                                &current_word.build(),
                                current_start.0,
                                current_start.1,
                            ));
                        }
                        current_word.clear();
                    }
                }
                col += 1;
            }
            ',' => {
                // if we are quoting the literal, keep comma, otherwise this is new COMMA token (should this be AND?)
                if current_word.len() > 0 {
                    if quoting.is_quoting() {
                        current_word.push(c, true, line, col)?;
                    } else {
                        if !current_word.is_sugar() {
                            tokens.push(Token::new_from_str(
                                &current_word.build(),
                                current_start.0,
                                current_start.1,
                            ));
                        }
                        current_word.clear();
                        tokens.push(Token::new(TokenType::Comma, line, col));
                    }
                } else {
                    tokens.push(Token::new(TokenType::Comma, line, col));
                }
                col += 1;
            }
            '.' => {
                let followed_by_whitespace = if let Some(&next) = chars.peek() {
                    next.is_whitespace()
                } else {
                    true // none (end of input)
                };
                if current_word.len() > 0 && quoting.is_quoting() {
                    current_word.push(c, true, line, col)?;
                } else if current_word.len() > 0 {
                    // We have a word going, we are not quoting. A period followed by whitespace ends the statement.
                    // Otherwise it is assumed to be part of the word.
                    if followed_by_whitespace {
                        if !current_word.is_sugar() {
                            tokens.push(Token::new_from_str(
                                &current_word.build(),
                                current_start.0,
                                current_start.1,
                            ));
                        }
                        current_word.clear();
                        tokens.push(Token::new(TokenType::Period, line, col));
                    } else {
                        current_word.push(c, quoting.is_quoting(), line, col)?;
                        // Special case: if we see that there is another period following this one we warn the user.
                        if let Some(&next) = chars.peek() {
                            if next == '.' {
                                ctx.warn(&format!(
                                    "multiple unquoted periods at line: {}, col: {}",
                                    line, col,
                                ))?;
                            }
                        }
                    }
                } else if followed_by_whitespace {
                    tokens.push(Token::new(TokenType::Period, line, col));
                } else {
                    current_word.push(c, quoting.is_quoting(), line, col)?; // I guess it is allowed to start a "word" with a period?
                }
                col += 1;
            }
            '#' | '/' => {
                if quoting.is_quoting() {
                    current_word.push(c, true, line, col)?;
                } else {
                    let comment = match c {
                        '#' => true,
                        '/' => {
                            if let Some(&next) = chars.peek() {
                                if next == '/' {
                                    // Detected '//' which is start of comment.
                                    true
                                } else {
                                    // Not a comment start, must be something else.
                                    false
                                }
                            } else {
                                // no more chars?
                                false
                            }
                        }
                        _ => panic!("character at this point must be '#' or '/'"),
                    };
                    if !comment {
                        current_word.push(c, quoting.is_quoting(), line, col)?;
                        col += 1;
                    } else {
                        // This is a comment, consume the rest of the line.
                        for c in chars.by_ref() {
                            if c == '\n' {
                                break;
                            }
                        }
                        // We may have parsed a word prior to the comment.
                        if current_word.len() > 0 {
                            tokens.push(Token::new_from_str(
                                &current_word.build(),
                                current_start.0,
                                current_start.1,
                            ));
                            current_word.clear();
                        }
                        line += 1;
                        col = 1;
                    }
                }
            }
            ':' => {
                // If we are quoting, then this is just a normal colon.
                // If proceeded by "note" or "comment" this indicates rest of line is a comment.
                // Otherwise we treat this as an attribute signifier.
                if current_word.len() == 0 {
                    return Err(CompilationError::IllegalColon(line, col));
                }
                if quoting.is_quoting() {
                    current_word.push(c, true, line, col)?;
                } else if !current_word.accept_value() {
                    return Err(CompilationError::IllegalColon(line, col));
                }

                col += 1;
            }
            '\'' | '`' | '\"' => {
                // A single or double quote alone can start a quoted string.
                // We do not differentiate between the types of single quotes. But
                // if a single quote starts a quoted string a single quote must end it
                // and same for double quotes.
                //
                // Within a quoted string a leading backslash can be used to escape
                // a quote character or a backslash itself.
                if current_word.len() == 0 {
                    if !quoting.is_quoting() {
                        quoting.set_quoting(c);
                        current_start = (line, col);
                    } else {
                        // No word in buffer is either empty string or invalud.
                        if quoting.is_match(c) {
                            // take empty string
                            tokens.push(Token::new_from_str(
                                &ZPLStr::default(),
                                current_start.0,
                                current_start.1,
                            ));
                            current_word.clear();
                            quoting = QuotingType::None;
                        } else {
                            return Err(CompilationError::IllegalQuote(line, col));
                        }
                    }
                } else {
                    // We have a word in buffer
                    if quoting.is_quoting() {
                        if !quoting.is_match(c) {
                            // We got a quote char, but it is not the one that started our quoting run,
                            // so we keep it.
                            current_word.push(c, true, line, col)?;
                        } else {
                            // We are at the end of the quoted literal.
                            // If next char is a colon, then we continue to parse attr value.
                            if let Some(&next) = chars.peek() {
                                if next == ':' {
                                    quoting = QuotingType::None;
                                    col += 1;
                                    continue;
                                }
                            }
                            // Otherwise consume the current word.
                            if !current_word.is_sugar() {
                                tokens.push(Token::new_from_str(
                                    &current_word.build(),
                                    current_start.0,
                                    current_start.1,
                                ));
                            }
                            current_word.clear();
                            quoting = QuotingType::None;
                        }
                    } else {
                        // We have a word in buffer but are not quoting and we just read a quote char?
                        // Only allowed if this is starting to quote a tuple value.
                        if current_word.is_tuple() && current_word.value_len() == 0 {
                            quoting.set_quoting(c); // turn on tuple value quoting
                        } else {
                            return Err(CompilationError::IllegalQuote(line, col));
                        }
                    }
                }
                col += 1;
            }
            '\\' => {
                // Backslash.  Within a quoted string, backslash is used to escape a the next
                // caracter. Am considering it a valid char if not in quoted context.
                if quoting.is_quoting() {
                    // If we are quoting, we need to escape (ie, accept) the next character.
                    if let Some(&next) = chars.peek() {
                        col += 1;
                        let _ = chars.next(); // consume the next char
                        current_word.push(next, true, line, col)?;
                    } else {
                        // trailing backslash while quoting?
                        // Don't care -- we will get an error due to EOL while quoting.
                    }
                } else {
                    // If we are not quoting, we treat the backslash as a regular character.
                    current_word.push(c, false, line, col)?;
                }
                col += 1;
            }
            _ => {
                if current_word.len() == 0 && !quoting.is_quoting() {
                    current_start = (line, col);
                }
                current_word.push(c, quoting.is_quoting(), line, col)?;
                col += 1;
            }
        }
    }
    if quoting.is_quoting() {
        return Err(CompilationError::UnterminatedQuote(
            current_start.0,
            current_start.1,
        ));
    }
    if current_word.len() > 0 && !current_word.is_sugar() {
        tokens.push(Token::new_from_str(
            &current_word.build(),
            current_start.0,
            current_start.1,
        ));
    }

    let tz = Tokenization { tokens };
    Ok(tz)
}

#[cfg(test)]
mod test {
    use crate::context::CompilationCtx;

    #[test]
    fn test_tuple_literal() {
        let zpl = "define foo as user with color:purple, `role`:`manager`, office:`fris:co`, and tag `foo bar`";
        let tz = super::tokenize_str(zpl, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        println!("{:?}", tokens);
        assert_eq!(tokens.len(), 14);
        let colorpurple = &tokens[5];
        assert_eq!(colorpurple.tt, super::tuple_from_strs("color", "purple"));
        let rolemanager = &tokens[7];
        assert_eq!(rolemanager.tt, super::tuple_from_strs("role", "manager"));
        let officefrisco = &tokens[9];
        assert_eq!(officefrisco.tt, super::tuple_from_strs("office", "fris:co"));
    }

    #[test]
    fn test_multiple_periods() {
        let zpl = "define alien as user with color green. . . allow aliens to access services";
        let tz = super::tokenize_str(zpl, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        println!("{:?}", tokens);
        assert_eq!(tokens.len(), 15);
    }

    #[test]
    fn test_successive_periods() {
        {
            // TODO: Should this fail since it does not end in period?
            let zpl = "define alien as user with color:green. allow aliens to access services";
            let tz = super::tokenize_str(zpl, &CompilationCtx::default()).unwrap();
            let tokens = tz.tokens;
            assert_eq!(tokens.len(), 12);
        }

        {
            // This will fail since a period is not allowed on an unquoted string
            let zpl = "define alien as user with color:green.. allow aliens to access services";
            let res = super::tokenize_str(zpl, &CompilationCtx::default());
            assert!(res.is_err());
            let err = res.unwrap_err();
            match err {
                super::CompilationError::IllegalStringLiteralChar(c, _line, _col) => {
                    assert_eq!(c, '.');
                }
                _ => panic!("unexpected error: {:?}", err),
            }
        }
    }

    #[test]
    fn test_quoted_period_in_attr_value() {
        let zpl = "Define alien as user with color:'green.'.";
        let tz = super::tokenize_str(zpl, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        assert_eq!(tokens.len(), 7);
        assert_eq!(tokens[6].tt, super::TokenType::Period);
        assert_eq!(
            tokens[5].tt,
            super::TokenType::Tuple(("color".to_string(), "green.".to_string()))
        );
    }

    #[test]
    fn test_comment_hash() {
        let zpl = "Define alien as user with color:'green.'. # comment here";
        let tz = super::tokenize_str(zpl, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        assert_eq!(tokens.len(), 7);
        assert_eq!(tokens[6].tt, super::TokenType::Period);
        assert_eq!(
            tokens[5].tt,
            super::TokenType::Tuple(("color".to_string(), "green.".to_string()))
        );
    }

    #[test]
    fn test_comment_slash() {
        let zpl = "Define alien as user with color:'green.'. // comment here";
        let tz = super::tokenize_str(zpl, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        assert_eq!(tokens.len(), 7);
        assert_eq!(tokens[6].tt, super::TokenType::Period);
        assert_eq!(
            tokens[5].tt,
            super::TokenType::Tuple(("color".to_string(), "green.".to_string()))
        );
    }

    #[test]
    fn test_quote_aka() {
        let zpl = "Define alien aka 'green monsters' as user with color:green.";
        let tz = super::tokenize_str(zpl, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        assert_eq!(tokens.len(), 9);
        assert_eq!(
            tokens[3].tt,
            super::TokenType::Literal("green monsters".to_string())
        );
    }

    #[test]
    fn test_quoting() {
        let zpls = vec![
            ("`foo`", "foo"),
            ("`foo'", "foo"),
            ("'foo`", "foo"),
            ("\"foo\"", "foo"),
            (r"`fo\`o`", "fo`o"),
            (r#""foo\\bar""#, r"foo\bar"),
            (r#""""#, ""),
            (r"''", ""),
            (r"'`", ""),
        ];

        for (zpl, expect) in zpls {
            match super::tokenize_str(zpl, &CompilationCtx::default()) {
                Ok(tz) => {
                    let tokens = tz.tokens;
                    assert_eq!(tokens.len(), 1);
                    assert_eq!(tokens[0].tt, super::TokenType::Literal(expect.to_string()));
                }
                Err(err) => {
                    panic!("failed to tokenize string: [{zpl}]   error={err}");
                }
            }
        }
    }

    #[test]
    fn test_invalid_quoting() {
        let zpls = vec!["`foo\"", "\"foo'", "foo'bar "];

        for zpl in zpls {
            match super::tokenize_str(zpl, &CompilationCtx::default()) {
                Ok(tz) => {
                    let tokens = tz.tokens;
                    panic!("should have failed to tokenize string: [{zpl}]   produced={tokens:?}");
                }
                Err(_err) => {}
            }
        }
    }

    #[test]
    fn test_keyword_on() {
        let zpl = "allow users on green endpoints to access services on red endpoints";
        let tz = super::tokenize_str(zpl, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        println!("{:?}", tokens);
        assert_eq!(tokens.len(), 11);
        let ontok = &tokens[2];
        assert_eq!(ontok.tt, super::TokenType::On);
        let ontok = &tokens[8];
        assert_eq!(ontok.tt, super::TokenType::On);
    }

    #[test]
    fn test_keyword_never() {
        let zpl = "never allow users on green endpoints to access services";
        let tz = super::tokenize_str(zpl, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        println!("{:?}", tokens);
        assert_eq!(tokens.len(), 9);
        let nevtok = &tokens[0];
        assert_eq!(nevtok.tt, super::TokenType::Never);
    }
}
