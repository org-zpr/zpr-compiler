//! define.rs - parser for define statements

use std::collections::HashMap;
use std::iter::Peekable;

use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::ptypes::{Class, ClassFlavor};
use crate::putil;
use crate::zpl;
use zpr::policy_types::Attribute;

// First token exists and is a DEFINE which is checked by the caller.
// `statement_num` must be unique for each statement.
pub fn parse_define(
    define_statement: &[Token],
    statement_num: usize,
) -> Result<Class, CompilationError> {
    if define_statement.is_empty() {
        panic!("parse_define called with empty statement");
    }
    if define_statement[0].tt != TokenType::Define {
        panic!("parse_define called with non-DEFINE statement");
    }

    let mut tokens = define_statement.iter().peekable();
    let _define = tokens.next().unwrap();

    let root_tok = &define_statement[0];

    // define class_name
    //        ^^^^^^^^^^
    let class_name = putil::return_literal(root_tok, tokens.next(), "class name", "define")?;

    // define class_name AKA plural
    //                   ^^^ ^^^^^^
    let aka_name: String;

    if let Some(next_tok) = tokens.peek() {
        match next_tok.tt {
            TokenType::AkA => {
                let aka = tokens.next().unwrap(); // consume the AKA
                aka_name = putil::return_literal(aka, tokens.next(), "aka name", "aka")?;
            }
            _ => {
                // No AKA, so aka_name is just plural.
                aka_name = putil::pluralize(&class_name);
            }
        }
    } else {
        aka_name = putil::pluralize(&class_name);
    }

    // define class_name [ aka foo ] as a parent-class-name with
    //                               ^^
    // 'a' will have been discarded by the lex step.
    putil::require_tt(root_tok, tokens.next(), "AS", "define", TokenType::As)?;

    // define class_name [ aka foo ] as a parent-class-name with
    //                                    ^^^^^^^^^^^^^^^^^
    //
    // baked in classes are: user, service, endpoint (was called device) (and their plurals)
    let mut parent_class_name =
        putil::return_literal(root_tok, tokens.next(), "parent class name", "as")?;

    // The flavor of the parent class really cannot be figured out until all
    // the classes are defined. To give meaning full error may need to track
    // the define token or something.
    let flavor = match parent_class_name.as_str() {
        zpl::DEF_CLASS_USER_NAME | zpl::DEF_CLASS_USER_AKA => {
            parent_class_name = String::from(zpl::DEF_CLASS_USER_NAME);
            ClassFlavor::User
        }
        zpl::DEF_CLASS_SERVICE_NAME | zpl::DEF_CLASS_SERVICE_AKA => {
            parent_class_name = String::from(zpl::DEF_CLASS_SERVICE_NAME);
            ClassFlavor::Service
        }
        zpl::DEF_CLASS_ENDPOINT_NAME | zpl::DEF_CLASS_ENDPOINT_AKA => {
            parent_class_name = String::from(zpl::DEF_CLASS_ENDPOINT_NAME);
            ClassFlavor::Endpoint
        }
        _ => ClassFlavor::Undefined,
    };

    // The "with" clause is optional.
    let mut class = Class {
        flavor,
        parent: parent_class_name.clone(),
        name: class_name.clone(),
        aka: aka_name.clone(),
        pos: root_tok.into(),
        with_attrs: Vec::new(),
        extensible: true,
        class_id: statement_num,
    };

    match tokens.peek() {
        Some(tok) => {
            if tok.tt == TokenType::With {
                // consume the WITH token
                tokens.next();
                parse_attributes(&mut class, &mut tokens)?;
            } else {
                return Err(CompilationError::DefineStmtParseError(
                    "expected WITH clause".to_string(),
                    tok.line,
                    tok.col,
                ));
            }
        }
        None => {
            // No WITH clause, so we are done.
        }
    }
    Ok(class)
}

// Parse attributes (tail end of the define). Each token is some attribute for the class.
// If we get a TAGS token, then everything after that is a tag until we hit an AND WITH.
// The MULTIPLE keyword just applies to the next attribute (cannot be a tag).
//
// This consumes all the remaining tokens (or errors out) and updates `class` in place.
fn parse_attributes<'a, I>(
    class: &mut Class,
    tokens: &mut Peekable<I>,
) -> Result<(), CompilationError>
where
    I: Iterator<Item = &'a Token>,
{
    let mut multiple = false;
    let mut tags = false;
    let mut tag = false;
    let mut optional: bool = false;
    let mut and = false;

    for tok in tokens {
        match &tok.tt {
            TokenType::Tags => {
                if tags {
                    return Err(CompilationError::DefineStmtParseError(
                        "multiple TAGS statements".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                if tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "TAGS following TAG".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                tags = true;
            }
            TokenType::Tag => {
                // tag is the non-greedy version of tags. Next token is the tag name.
                if tags {
                    return Err(CompilationError::DefineStmtParseError(
                        "TAG following TAGS".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                tag = true;
            }
            TokenType::Optional => {
                if tags || tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "OPTIONAL not allowed after tag/tags".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                if optional {
                    return Err(CompilationError::DefineStmtParseError(
                        "multiple OPTIONAL statements".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                optional = true;
            }
            TokenType::Multiple => {
                if tags || tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "MULTIPLE not allowed after tag/tags".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                if multiple {
                    return Err(CompilationError::DefineStmtParseError(
                        "multiple MULTIPLE statements".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                multiple = true;
            }
            TokenType::And => {
                if and {
                    return Err(CompilationError::DefineStmtParseError(
                        "multiple AND statements".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                if tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "TAG requires a tag name, not AND".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                and = true;
            }
            TokenType::With => {
                // Only valid after an and.
                if !and {
                    return Err(CompilationError::DefineStmtParseError(
                        "WITH must follow AND".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                // Got AND WITH so that turns off modifier flags.
                tags = false;
                tag = false;
                optional = false;
                multiple = false;
                and = false;
            }
            TokenType::Comma => {}
            TokenType::Tuple((name, value)) => {
                if tags || tag {
                    return Err(CompilationError::DefineStmtParseError(
                        "attributes not allowed in tag/tags".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                let attr = if multiple || value.len() > 1 {
                    Attribute::tuple(name)
                        .multi()
                        .values(value.to_vec())
                        .optional(optional)
                        .domain_hint(class.flavor.into())
                        .build()?
                } else {
                    Attribute::tuple(name)
                        .single()
                        .values(value.to_vec())
                        .optional(optional)
                        .domain_hint(class.flavor.into())
                        .build()?
                };
                class.with_attrs.push(attr);
                multiple = false;
                and = false;
            }
            TokenType::Literal(s) => {
                if (tag || tags) && multiple {
                    return Err(CompilationError::DefineStmtParseError(
                        "MULTIPLE not allowed with tag/tags".to_string(),
                        tok.line,
                        tok.col,
                    ));
                }
                let attr = if tag || tags {
                    Attribute::tag(s)
                        .domain_hint(class.flavor.into())
                        .optional(optional)
                        .build()?
                } else {
                    Attribute::tuple(s)
                        .optional(optional)
                        .domain_hint(class.flavor.into())
                        .multi_if(multiple)
                        .build()?
                };
                class.with_attrs.push(attr);
                multiple = false;
                and = false;
                tag = false; // not greedy
            }
            _ => {
                return Err(CompilationError::DefineStmtParseError(
                    format!("syntax error ({:?})", tok.tt),
                    tok.line,
                    tok.col,
                ));
            }
        }
    }
    Ok(())
}

// Fill in any classes with undefined flavor by walking backwards to their parent classes.
pub fn resolve_class_flavors(classes: &mut HashMap<String, Class>) -> Result<(), CompilationError> {
    let mut undef_count = 0;
    for class in (*classes).values() {
        if class.flavor == ClassFlavor::Undefined {
            undef_count += 1;
        }
    }
    while undef_count > 0 {
        let prev_undef_count = undef_count;
        let mut needs_parent = Vec::new();
        for (name, class) in classes.iter_mut() {
            if class.flavor == ClassFlavor::Undefined {
                needs_parent.push(name.clone());
            }
        }
        for name in needs_parent {
            let parentless_ref = classes.get(&name).unwrap();
            let parent_flavor = match classes.get(parentless_ref.parent.as_str()) {
                Some(parent) => {
                    // Ensure parent allows subclassing.
                    if !parent.extensible {
                        return Err(CompilationError::DefineStmtParseError(
                            format!(
                                "class {} extends {} which is not extensible",
                                name, parent.name,
                            ),
                            parentless_ref.pos.line,
                            parentless_ref.pos.col,
                        ));
                    }
                    parent.flavor.clone()
                }
                None => {
                    // This is an error, the parent class does not exist.
                    return Err(CompilationError::DefineStmtParseError(
                        format!(
                            "parent class {} of {} does not exist",
                            parentless_ref.parent, name
                        ),
                        parentless_ref.pos.line,
                        parentless_ref.pos.col,
                    ));
                }
            };
            if parent_flavor != ClassFlavor::Undefined {
                let parentless = classes.get_mut(&name).unwrap();
                parentless.flavor = parent_flavor;
                undef_count -= 1;
            }
        }
        if undef_count > 0 && prev_undef_count == undef_count {
            // We did not make any progress, so we have an impass.
            let mut undefined = Vec::new();
            for (name, class) in classes.iter_mut() {
                if class.flavor == ClassFlavor::Undefined {
                    undefined.push(name.clone());
                }
            }
            return Err(CompilationError::DefineStmtParseError(
                format!("could not resolve classes: {:?}", undefined),
                0,
                0,
            ));
        }
    }
    Ok(())
}

#[cfg(test)]
mod test {

    use super::*;
    use crate::{context::CompilationCtx, lex::tokenize_str};

    #[test]
    fn test_required_tag() {
        let statement = "define marketing-emp as a user with tag full-time";
        let tz = tokenize_str(statement, &CompilationCtx::default()).unwrap();
        let tokens = tz.tokens;
        let class = parse_define(&tokens, 1).unwrap();
        assert_eq!(class.name, "marketing-emp");
    }

    // Test stuff that passes tokenizer but should fail parser.
    #[test]
    fn test_reject_nonesense() {
        let invalids = vec![
            "define marketing-emp as a user with tag multiple foo",
            "define marketing-emp as a user with tags multiple foo",
            "define marketing-emp as a user with tag and foo",
        ];
        let ctx = CompilationCtx::default();
        for statement in invalids {
            let tz = tokenize_str(statement, &ctx).unwrap();
            let tokens = tz.tokens;
            match parse_define(&tokens, 1) {
                Ok(_) => panic!("should have failed on: '{}'", statement),
                Err(_) => {}
            }
        }
    }

    // Using "tags" a second time (after names have already been consumed under the
    // first "tags") must fail because there can only be one tags-section per attribute list.
    #[test]
    fn test_double_tags_errors() {
        let statement = "define foo as a user with tags bar tags baz";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: duplicate 'tags'"),
            Err(e) => assert!(
                e.to_string().contains("TAGS"),
                "unexpected error: {e}"
            ),
        }
    }

    // "tags" immediately following "tag" (before the tag name is consumed) must
    // fail because you cannot mix the two forms without a name in between.
    #[test]
    fn test_tags_after_tag_errors() {
        let statement = "define foo as a user with tag tags bar";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: 'tags' following 'tag'"),
            Err(e) => assert!(
                e.to_string().contains("TAGS"),
                "unexpected error: {e}"
            ),
        }
    }

    // "tag" immediately following "tags" must fail — "tags" is the greedy variant
    // and "tag" inside it is nonsensical.
    #[test]
    fn test_tag_after_tags_errors() {
        let statement = "define foo as a user with tags tag bar";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: 'tag' following 'tags'"),
            Err(e) => assert!(
                e.to_string().contains("TAG"),
                "unexpected error: {e}"
            ),
        }
    }

    // "optional" is not a valid modifier inside a tags clause; it must appear
    // before "tags"/"tag", not after.
    #[test]
    fn test_optional_after_tags_errors() {
        let statement = "define foo as a user with tags optional bar";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: 'optional' after 'tags'"),
            Err(e) => assert!(
                e.to_string().contains("OPTIONAL"),
                "unexpected error: {e}"
            ),
        }
    }

    // Two consecutive "optional" keywords without an attribute name between them
    // must fail because "optional" is a one-shot modifier.
    #[test]
    fn test_double_optional_errors() {
        let statement = "define foo as a user with optional optional id";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: duplicate 'optional'"),
            Err(e) => assert!(
                e.to_string().contains("OPTIONAL"),
                "unexpected error: {e}"
            ),
        }
    }

    // "multiple" is not allowed inside a tags clause and must be rejected.
    #[test]
    fn test_multiple_after_tags_errors() {
        let statement = "define foo as a user with tags multiple bar";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: 'multiple' after 'tags'"),
            Err(e) => assert!(
                e.to_string().contains("MULTIPLE"),
                "unexpected error: {e}"
            ),
        }
    }

    // Two consecutive "multiple" keywords without an attribute name between them
    // must fail because "multiple" is a one-shot modifier.
    #[test]
    fn test_double_multiple_errors() {
        let statement = "define foo as a user with multiple multiple id";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: duplicate 'multiple'"),
            Err(e) => assert!(
                e.to_string().contains("MULTIPLE"),
                "unexpected error: {e}"
            ),
        }
    }

    // "multiple" set before "tags", then a literal name, must fail because the
    // literal sees both (tags=true, multiple=true) simultaneously.
    #[test]
    fn test_multiple_combined_with_tags_errors() {
        let statement = "define foo as a user with multiple tags foo";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: 'multiple' combined with 'tags'"),
            Err(e) => assert!(
                e.to_string().contains("MULTIPLE"),
                "unexpected error: {e}"
            ),
        }
    }

    // Two consecutive "and" keywords must fail — "and" is reset only when a
    // literal or "with" consumes it.
    #[test]
    fn test_double_and_errors() {
        let statement = "define foo as a user with bar and and baz";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: duplicate 'and'"),
            Err(e) => assert!(
                e.to_string().contains("AND"),
                "unexpected error: {e}"
            ),
        }
    }

    // "and" immediately after "tag" (before the tag name) must fail because
    // "tag" requires a name token next, not a conjunction.
    #[test]
    fn test_and_after_tag_errors() {
        let statement = "define foo as a user with tag and bar";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: 'and' immediately after 'tag'"),
            Err(e) => assert!(
                e.to_string().contains("AND"),
                "unexpected error: {e}"
            ),
        }
    }

    // "with" not preceded by "and" must fail — "and with" is the valid
    // two-token form that opens an additional attribute group; bare "with" is not.
    #[test]
    fn test_with_without_and_errors() {
        let statement = "define foo as a user with bar with baz";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: 'with' without preceding 'and'"),
            Err(e) => assert!(
                e.to_string().contains("WITH"),
                "unexpected error: {e}"
            ),
        }
    }

    // A key:value tuple attribute inside a "tags" clause must fail because
    // tags only accept plain names, not structured attributes.
    #[test]
    fn test_tuple_attr_in_tags_errors() {
        let statement = "define foo as a user with tags color:purple";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        match parse_define(&tz.tokens, 1) {
            Ok(_) => panic!("should have failed: tuple attribute inside 'tags'"),
            Err(e) => assert!(
                e.to_string().contains("tag"),
                "unexpected error: {e}"
            ),
        }
    }

    // The AKA clause must be captured in class.aka; without it, the parser
    // auto-pluralises, so an explicit AKA must override that default.
    #[test]
    fn test_aka_is_set() {
        let statement = "define mouse AKA mice as a user with device-id";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        let class = parse_define(&tz.tokens, 1).unwrap();
        assert_eq!(class.name, "mouse");
        assert_eq!(class.aka, "mice");
    }

    // The "optional" modifier must set attr.optional = true on the resulting
    // attribute; that flag is separate from multi-valued and must be checked
    // independently.
    #[test]
    fn test_optional_attr_flag() {
        let statement = "define employee as a user with optional nickname";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        let class = parse_define(&tz.tokens, 1).unwrap();
        assert_eq!(class.with_attrs.len(), 1);
        assert!(
            class.with_attrs[0].optional,
            "attribute should be marked optional"
        );
    }

    // The "multiple" modifier must produce a multi-valued attribute; that flag
    // is distinct from optional and must be independently asserted.
    #[test]
    fn test_multiple_attr_flag() {
        let statement = "define employee as a user with multiple roles";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        let class = parse_define(&tz.tokens, 1).unwrap();
        assert_eq!(class.with_attrs.len(), 1);
        assert!(
            class.with_attrs[0].is_multi_valued(),
            "attribute should be marked multi-valued"
        );
    }

    // A define statement with no "with" clause is valid — the clause is optional.
    // The resulting class must have an empty attribute list.
    #[test]
    fn test_no_with_clause() {
        let statement = "define alien as a user";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(statement, &ctx).unwrap();
        let class = parse_define(&tz.tokens, 1).unwrap();
        assert_eq!(class.name, "alien");
        assert!(class.with_attrs.is_empty(), "expected no attributes");
    }
}
