use std::collections::HashMap;

use crate::allow::parse_allow;
use crate::context::CompilationCtx;
use crate::define::{parse_define, resolve_class_flavors};
use crate::errors::CompilationError;
use crate::lex::{Token, TokenType};
use crate::never::parse_never;
use crate::ptypes::{Class, Policy};

#[derive(Default)]
pub struct ParsingResult {
    pub policy: Policy,
}

pub fn parse(tokens: Vec<Token>, ctx: &CompilationCtx) -> Result<ParsingResult, CompilationError> {
    let mut result = ParsingResult::default();
    let mut statements = Vec::new();
    let mut current_statement = Vec::new();

    // Convert the tokens into statements, which are just sub-lists of the tokens.
    // Currently the compiler only accepts ALLOW statements and DEFINE statements.
    // Periods are still optional, but if you use them incorrectly they parser will
    // complain.
    let mut in_statement = false;
    let mut in_never: bool = false;
    for tok in tokens {
        match tok.tt {
            TokenType::Period => {
                if !current_statement.is_empty() {
                    statements.push(current_statement);
                    current_statement = Vec::new();
                }
                in_statement = false;
                in_never = false;
            }
            TokenType::Allow if in_never => {
                current_statement.push(tok);
            }
            TokenType::Allow | TokenType::Define | TokenType::Never => {
                if !current_statement.is_empty() {
                    statements.push(current_statement);
                    current_statement = Vec::new();
                }
                in_never = tok.tt == TokenType::Never;
                current_statement.push(tok);
                in_statement = true;
            }
            _ if in_statement => {
                current_statement.push(tok);
            }
            _ => {
                return Err(CompilationError::ParseError(
                    "unexpected token".to_string(),
                    tok.line,
                    tok.col,
                ));
            }
        }
    }
    if !current_statement.is_empty() {
        statements.push(current_statement);
    }

    if statements.is_empty() {
        ctx.warn("empty policy")?;
    }

    let mut policy = Policy::default();

    let mut classes: HashMap<String, Class> = HashMap::new();

    // Add default classes:
    for defclass in Class::defaults() {
        classes.insert(defclass.name.clone(), defclass);
    }

    // Construct an index that adds entries for all the AKAs.
    let mut class_index: HashMap<String, String> = HashMap::new();
    for (name, class) in classes.iter() {
        class_index.insert(name.clone(), name.clone());
        class_index.insert(class.aka.clone(), name.clone());
    }

    // Define statements create classes.
    for (i, statement) in statements.iter().enumerate() {
        if statement[0].tt == TokenType::Define {
            let class = parse_define(statement, i + 1)?;

            // It is an error to redefine a class.
            if classes.contains_key(&class.name) || class_index.contains_key(&class.name) {
                return Err(CompilationError::Redefinition(
                    class.name,
                    statement[0].line,
                    statement[0].col,
                ));
            }
            let cname = class.name.clone();
            class_index.insert(cname.clone(), cname.clone());
            class_index.insert(class.aka.clone(), cname.clone());
            classes.insert(cname, class);
        }
    }

    // Take a pass over the defines to resolve all the child/parent relationships and
    // compute the correct flavors.
    resolve_class_flavors(&mut classes)?;

    // Now make sure all attributes have a domain.
    for (_, class) in classes.iter_mut() {
        for attr in class.with_attrs.iter_mut() {
            if attr.is_unspecified_domain() {
                attr.set_domain(class.flavor.into());
            }
            if attr.is_unspecified_domain() {
                return Err(CompilationError::ParseError(
                    format!("attribute {} has no domain", attr.zpl_key()),
                    class.pos.line,
                    class.pos.col,
                ));
            }
        }
    }

    // Next parse all the nevers.
    for (i, statement) in statements.iter().enumerate() {
        if statement[0].tt == TokenType::Never {
            let never = parse_never(statement, i + 1, &class_index, &classes)?;
            if ctx.verbose {
                println!("{}", never.to_string_never());
            }
            policy.nevers.push(never);
        }
    }

    // Next parse all the allows.
    for (i, statement) in statements.iter().enumerate() {
        if statement[0].tt == TokenType::Allow {
            let allow = parse_allow(statement, i + 1, &class_index, &classes)?;
            if ctx.verbose {
                println!("{}", allow);
            }
            policy.allows.push(allow);
        }
    }

    if ctx.verbose {
        println!()
    }

    // move all the classes in the policy
    for (_, class) in classes.into_iter() {
        // Not sure i need the built in ones?
        if class.is_builtin() {
            continue;
        }
        if ctx.verbose {
            println!("defined class: {} (is a {:?})", class.name, class.flavor);
            for attr in &class.with_attrs {
                println!("  with: {}", attr.to_instance_string());
            }
        }
        policy.defines.push(class);
    }

    result.policy = policy;
    Ok(result)
}

#[cfg(test)]
mod test {
    use super::*;
    use crate::lex::{Tokenization, tokenize_str};
    use crate::ptypes::ClassFlavor;

    #[test]
    fn test_parse_define() {
        let valids = vec![
            "define employee as a user with an id",
            "define employee as a user with an id \n define marketing-emp as an employee with rule:marketing and tag full-time",
            "define employee as a user with an ID-number, multiple roles and optional tags full-time, part-time, and intern",
            "define employee as a user with an `ID number`, multiple roles and optional tags full-time, part-time, and intern and with color:purple, size:`extra:large`",
            "define gateway as a service with an external-network-connection",
            "define gateway as a service with an external-network-connection \n define internet-gateway as a gateway with external-network-connection:public-internet",
            "define peripheral as a user with function \n define mouse AKA mice as a peripheral with function:pointing",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tz: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tz.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_short_policy() {
        let pp = r#"
define employee as a user with an ID-number, multiple roles and
optional tags full-time, part-time, and intern

define marketing-emp as an employee with rule:marketing and tag full-time

allow marketing-emps to access role:marketing services
"#;
        let ctx = CompilationCtx::default();
        let tz: Result<Tokenization, CompilationError> = tokenize_str(pp, &ctx).or_else(|e| {
            panic!("failed to tokenize '{}': {:?}", pp, e);
        });
        let pol = match parse(tz.unwrap().tokens, &ctx) {
            Ok(pr) => pr.policy,
            Err(e) => {
                panic!("failed to parse '{}': {:?}", pp, e);
            }
        };
        assert_eq!(pol.defines.len(), 2);
        assert_eq!(pol.allows.len(), 1);

        let emp = match pol.defines[0].name.as_str() {
            "employee" => &pol.defines[0],
            "marketing-emp" => &pol.defines[1],
            _ => panic!("unexpected class name: {}", pol.defines[0].name),
        };
        assert_eq!(emp.name, "employee");
        assert_eq!(emp.flavor, ClassFlavor::User);
        assert_eq!(emp.with_attrs.len(), 5);
        for attr in &emp.with_attrs {
            match attr.zpl_key().as_str() {
                "user.ID-number" => {
                    assert_eq!(attr.is_multi_valued(), false);
                    assert_eq!(attr.is_tag(), false);
                    assert_eq!(attr.optional, false);
                }
                "user.roles" => {
                    assert_eq!(attr.is_multi_valued(), true);
                    assert_eq!(attr.is_tag(), false);
                    assert_eq!(attr.optional, false);
                }
                "user.zpr.tag" if attr.zpl_value() == "user.full-time" => {
                    assert_eq!(attr.is_multi_valued(), false);
                    assert_eq!(attr.is_tag(), true);
                    assert_eq!(attr.optional, true);
                }
                "user.zpr.tag" if attr.zpl_value() == "user.part-time" => {
                    assert_eq!(attr.is_multi_valued(), false);
                    assert_eq!(attr.is_tag(), true);
                    assert_eq!(attr.optional, true);
                }
                "user.zpr.tag" if attr.zpl_value() == "user.intern" => {
                    assert_eq!(attr.is_multi_valued(), false);
                    assert_eq!(attr.is_tag(), true);
                    assert_eq!(attr.optional, true);
                }
                "user.zpr.tag" => {
                    panic!("unexpected tag: {}", attr.zpl_value());
                }
                _ => panic!("unexpected attribute name: {}", attr.zpl_key()),
            }
        }
    }

    #[test]
    fn test_base_allow() {
        let valids = vec!["allow color:green users to access services"];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let toks = tokens.unwrap().tokens;
            assert_eq!(6, toks.len());
            let _pol = match parse(toks, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_postifx_attr_prohibited() {
        let valids = vec![
            "allow endpoints with users with loc:italy to access services",
            "allow endpoints with users to access services with color:green",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let toks = tokens.unwrap().tokens;
            let _pol = match parse(toks, &ctx) {
                Ok(_) => panic!("should not have parsed postfix notation: {}", valid),
                Err(e) => {
                    assert!(
                        e.to_string().contains("postfix"),
                        "unexpected error: {:?}",
                        e
                    );
                }
            };
        }
    }

    #[test]
    fn test_omit_device() {
        let valids = vec![
            "allow color:red users to access services",
            "allow managed users to access services",
            "allow color:red users to access services",
            "allow managed, color:red users to access services",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_omit_user() {
        let valids = vec![
            "allow managed endpoints to access services",
            "allow color:red endpoints to access services",
            "allow managed, color:red endpoints to access services",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    #[test]
    fn test_verbose_device() {
        let valids = vec![
            "allow managed, color:red users on color:green endpoints to access green services",
            "allow color:red, managed users on color:green endpoints to access color:blue services",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    // Test splitting statements with a period. Will work anyway since we
    // use Allow and Define as our statement delimiters.
    #[test]
    fn test_use_periods() {
        let valids = vec![
            "Define Alien as a user with color:green. Allow Aliens to access services.",
            ".",
        ];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
        }
    }

    // Put periods in where they don't belong. Should fail.
    #[test]
    fn test_use_periods_in_error() {
        let invalids = vec![
            "Define Alien. as a user with color:green. Allow Aliens to. access services",
            "Define alien as a user. with color:green.",
        ];
        let ctx = CompilationCtx::default();
        for valid in invalids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(_policy) => {
                    panic!("should not have parsed '{}'", valid);
                }
                Err(_e) => (),
            };
        }
    }

    #[test]
    fn test_cannot_subclass_visa_service() {
        let invalids = vec!["Define MyVs as a VisaService with endpoint.color:green"];
        let ctx = CompilationCtx::default();
        for valid in invalids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let _pol = match parse(tokens.unwrap().tokens, &ctx) {
                Ok(_policy) => {
                    panic!("should not have parsed '{}'", valid);
                }
                Err(e) => {
                    assert!(
                        e.to_string().contains("is not extensible"),
                        "unexpected error: {:?}",
                        e
                    );
                }
            };
        }
    }

    // A custom class defined with "define" must be usable as the subject class
    // in an allow statement by its canonical name.  This exercises the class
    // registry lookup path in parse_allow.
    #[test]
    fn test_custom_class_in_allow() {
        let input = "define employee as a user with id\nallow employees to access services";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.defines.len(), 1);
        assert_eq!(pr.policy.allows.len(), 1);

        // The user clause on the LHS must name the custom class, not the base "user".
        let allow = &pr.policy.allows[0];
        let user_clause = allow
            .client
            .iter()
            .find(|c| c.flavor == ClassFlavor::User)
            .expect("user clause missing from LHS");
        assert_eq!(user_clause.class, "employee");
    }

    // The AKA name of a custom class must be accepted wherever the canonical
    // name is accepted in an allow statement and must resolve to the canonical name.
    #[test]
    fn test_aka_name_in_allow() {
        // "mice" is the AKA for "mouse"; the allow statement uses the AKA.
        let input =
            "define mouse AKA mice as a user with device-id\nallow mice to access services";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.allows.len(), 1);

        let allow = &pr.policy.allows[0];
        let user_clause = allow
            .client
            .iter()
            .find(|c| c.flavor == ClassFlavor::User)
            .expect("user clause missing from LHS");
        // The AKA "mice" must resolve to the canonical class name "mouse".
        assert_eq!(user_clause.class, "mouse");
    }

    // resolve_class_flavors must iterate until all classes are resolved, even
    // when the inheritance chain is more than two levels deep.  This tests a
    // three-level chain: engineer → employee → worker → user (built-in).
    #[test]
    fn test_multi_level_inheritance() {
        let input = "\
            define worker as a user with id\n\
            define employee as a worker with role\n\
            define engineer as an employee with specialty";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.defines.len(), 3);

        // After multi-pass flavor resolution every class must end up as User.
        for class in &pr.policy.defines {
            assert_eq!(
                class.flavor,
                ClassFlavor::User,
                "class '{}' should have User flavor but got {:?}",
                class.name,
                class.flavor
            );
        }
    }

    // Defining the same class name twice in one policy must fail with a
    // Redefinition error, not silently overwrite the first definition.
    #[test]
    fn test_redefinition_error() {
        let input =
            "define employee as a user with id \n define employee as a user with id";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        match parse(tz.tokens, &ctx) {
            Ok(_) => panic!("should have failed: class defined twice"),
            Err(e) => assert!(
                matches!(e, CompilationError::Redefinition(_, _, _)),
                "unexpected error: {e:?}"
            ),
        }
    }

    // A literal token that appears before any statement keyword (allow/define/never)
    // has no valid enclosing statement and must be rejected immediately.
    #[test]
    fn test_token_before_keyword_fails() {
        let input = "foo allow users to access services";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        match parse(tz.tokens, &ctx) {
            Ok(_) => panic!("should have failed: literal before any keyword"),
            Err(e) => assert!(
                matches!(e, CompilationError::ParseError(_, _, _)),
                "unexpected error: {e:?}"
            ),
        }
    }

    // A "never" statement not followed by "allow" must produce a NeverStmtParseError
    // at the top-level parse stage (the error propagates up from parse_never).
    #[test]
    fn test_never_without_allow_at_parser_level() {
        let input = "never users to access services";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        match parse(tz.tokens, &ctx) {
            Ok(_) => panic!("should have failed: never without allow"),
            Err(e) => assert!(
                matches!(e, CompilationError::NeverStmtParseError(_, _, _)),
                "unexpected error: {e:?}"
            ),
        }
    }

    #[test]
    fn test_base_never() {
        let valids = vec!["never allow color:green users to access services"];
        let ctx = CompilationCtx::default();
        for valid in valids {
            let tokens: Result<Tokenization, CompilationError> =
                tokenize_str(valid, &ctx).or_else(|e| {
                    panic!("failed to tokenize '{}': {:?}", valid, e);
                });
            let toks = tokens.unwrap().tokens;
            assert_eq!(7, toks.len());
            let pol = match parse(toks, &ctx) {
                Ok(policy) => policy,
                Err(e) => {
                    panic!("failed to parse '{}': {:?}", valid, e);
                }
            };
            assert_eq!(pol.policy.nevers.len(), 1);
            assert_eq!(pol.policy.allows.len(), 0);
        }
    }

    // DEFINE statements are collected in a first pass before any ALLOW or NEVER
    // statements are processed, so a class reference in an allow that appears
    // before its define in the source file must still resolve correctly.
    #[test]
    fn test_forward_reference_in_allow() {
        let input = "allow employees to access services\ndefine employee as a user with id";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("forward reference should resolve");
        assert_eq!(pr.policy.allows.len(), 1);
        assert_eq!(pr.policy.defines.len(), 1);
    }

    // A signal clause must survive the full parse() pipeline intact and be
    // accessible on the resulting AllowClause with the correct message and target.
    #[test]
    fn test_signal_clause_through_full_parse() {
        let input = r#"allow users to access services and signal "hello" to service"#;
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.allows.len(), 1);

        let signal = pr.policy.allows[0]
            .signal
            .as_ref()
            .expect("signal clause should be present on the allow");
        assert_eq!(signal.message, "hello");
        assert_eq!(signal.service_class_name, "service");
    }

    // A policy containing multiple allows and a never must produce the correct
    // counts in each respective vector of the Policy struct.
    #[test]
    fn test_multi_statement_counts() {
        let input = "\
            allow users to access services\n\
            allow color:green users to access services\n\
            never allow color:red users to access services";
        let ctx = CompilationCtx::default();
        let tz = tokenize_str(input, &ctx).unwrap();
        let pr = parse(tz.tokens, &ctx).expect("should parse");
        assert_eq!(pr.policy.allows.len(), 2, "expected 2 allow clauses");
        assert_eq!(pr.policy.nevers.len(), 1, "expected 1 never clause");
    }
}
