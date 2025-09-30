//! The ZPLStr type can hold either a plain string (atom) or a ZPL tuple.
//! A tuple has a value that may be empty, or a single string, or a list
//! of strings.
//!
//! Examples:
//! - Atom: "classified"
//! - Tuple with empty value: "name:"
//! - Tuple with single string value: "name:John"
//! - Tuple with list value: "roles:{role1, role2, role3}"
//!
//! This has functionality that is specifically helpful to the lexer step.

use std::fmt;

use crate::errors::CompilationError;

pub struct ZPLStr {
    name: String,
    value: Option<Vec<String>>,
    tuple: bool,
}

impl ZPLStr {
    pub fn new_atom(name: String) -> ZPLStr {
        ZPLStr {
            name,
            value: None,
            tuple: false,
        }
    }

    pub fn new_tuple_vec(name: String, value: Vec<String>) -> ZPLStr {
        ZPLStr {
            name,
            value: Some(value),
            tuple: true,
        }
    }

    #[allow(dead_code)]
    pub fn new_tuple_empty(name: &str) -> ZPLStr {
        ZPLStr {
            name: name.to_string(),
            value: None,
            tuple: true,
        }
    }

    pub fn is_tuple(&self) -> bool {
        self.tuple
    }

    /// Note that returned `value` may be empty vector.
    pub fn as_tuple(&self) -> (String, Vec<String>) {
        if !self.tuple {
            panic!("not a tuple");
        }
        match self.value {
            Some(ref v) => (self.name.clone(), v.clone()),
            None => (self.name.clone(), Vec::new()),
        }
    }

    pub fn as_atom(&self) -> String {
        if self.tuple {
            panic!("not an atom");
        }
        self.name.clone()
    }

    /// Get the length of the string representation.
    pub fn rendered_len(&self) -> usize {
        let str_form = format!("{}", self);
        str_form.len()
    }
}

impl Default for ZPLStr {
    fn default() -> Self {
        ZPLStr::new_atom("".into())
    }
}

impl fmt::Display for ZPLStr {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        if self.tuple {
            let (k, v) = self.as_tuple();
            if v.len() == 0 {
                write!(f, "{k}:")
            } else if v.len() == 1 {
                write!(f, "{k}:{}", v[0])
            } else {
                write!(f, "{k}:{{{}}}", v.join(", "))
            }
        } else {
            write!(f, "{}", self.name)
        }
    }
}

pub struct ZPLStrBuilder {
    name: String,
    current_value: String,
    prev_values: Vec<String>,
    tuple: bool,
    input_to_value: bool,
}

impl ZPLStrBuilder {
    pub fn new() -> Self {
        ZPLStrBuilder {
            name: String::new(),
            current_value: String::new(),
            prev_values: Vec::new(),
            tuple: false,
            input_to_value: false,
        }
    }

    pub fn is_empty(&self) -> bool {
        self.name.is_empty() && self.current_value.is_empty() && self.prev_values.is_empty()
    }

    /// Push supplied character onto the name or value depending on mode.
    /// TODO: Currently only accepts ASCII alphanumerics, '-', '_', and '.' (for names).
    pub fn push(
        &mut self,
        c: char,
        quoted: bool,
        line: usize,
        col: usize,
    ) -> Result<(), CompilationError> {
        if self.input_to_value {
            if !quoted && !c.is_ascii_alphanumeric() && !matches!(c, '-' | '_') {
                return Err(CompilationError::IllegalStringLiteralChar(c, line, col));
            }
            self.current_value.push(c);
        } else {
            // The name part of a tuple is allowed to contain periods wihout needing quotes.
            if !quoted && !c.is_ascii_alphanumeric() && !matches!(c, '.' | '-' | '_') {
                return Err(CompilationError::IllegalNameLiteralChar(c, line, col));
            }
            self.name.push(c);
        }
        Ok(())
    }

    /// Switch to value mode ... all further pushes go to the tuple value. Implies that this is a tuple
    /// meaning that it has a key part and a value part.  The value part may be an atom type string or
    /// a list of atoms.
    ///
    /// Returns false if we are already in value mode.
    pub fn accept_value(&mut self) -> bool {
        if self.input_to_value {
            return false;
        }
        self.input_to_value = true;
        self.tuple = true;
        true
    }

    /// Start accepting the next value in a tuple list.
    pub fn next_value(&mut self) {
        if !self.input_to_value {
            panic!("not in value mode");
        }
        if !self.current_value.is_empty() {
            self.prev_values.push(self.current_value.clone());
            self.current_value.clear();
        }
    }

    /// Get the length of the current value string.
    pub fn value_is_empty(&self) -> bool {
        self.current_value.is_empty()
    }

    pub fn is_tuple(&self) -> bool {
        self.tuple
    }

    pub fn is_sugar(&self) -> bool {
        if self.tuple {
            return false;
        }
        self.name.eq_ignore_ascii_case("a") || self.name.eq_ignore_ascii_case("an")
    }

    pub fn build(self) -> ZPLStr {
        if self.tuple {
            let mut vals = self.prev_values;
            if !self.current_value.is_empty() {
                vals.push(self.current_value);
            }
            return ZPLStr::new_tuple_vec(self.name, vals);
        }
        ZPLStr::new_atom(self.name)
    }
}

#[cfg(test)]
mod test {
    use super::*;

    #[test]
    fn test_atom() {
        let mut b = ZPLStrBuilder::new();
        assert!(b.is_empty());
        assert!(!b.is_tuple());
        assert!(!b.is_sugar());
        for (i, c) in "classified".chars().enumerate() {
            b.push(c, false, 1, i + 1).unwrap();
        }
        assert!(!b.is_empty());
        assert!(!b.is_tuple());
        assert!(!b.is_sugar());
        let s = b.build();
        assert_eq!(s.is_tuple(), false);
        assert_eq!(s.as_atom(), "classified");
        assert_eq!(format!("{}", s), "classified");
    }

    #[test]
    fn test_tuple_empty() {
        let mut b = ZPLStrBuilder::new();
        assert!(b.is_empty());
        assert!(!b.is_tuple());
        assert!(!b.is_sugar());
        for (i, c) in "name".chars().enumerate() {
            b.push(c, false, 1, i + 1).unwrap();
        }
        assert!(!b.is_empty());
        assert!(!b.is_tuple());
        assert!(!b.is_sugar());
        assert!(b.accept_value());
        assert!(!b.accept_value()); // second time should return false
        assert!(b.is_tuple());
        let s = b.build();
        assert_eq!(s.is_tuple(), true);
        let (k, v) = s.as_tuple();
        assert_eq!(k, "name");
        assert_eq!(v.len(), 0);
        assert_eq!(format!("{}", s), "name:");
    }

    #[test]
    fn test_tuple_single() {
        let mut b = ZPLStrBuilder::new();
        assert!(b.is_empty());
        assert!(!b.is_tuple());
        assert!(!b.is_sugar());
        for (i, c) in "name".chars().enumerate() {
            b.push(c, false, 1, i + 1).unwrap();
        }
        assert!(!b.is_empty());
        assert!(!b.is_tuple());
        assert!(!b.is_sugar());
        assert!(b.accept_value());
        assert!(!b.accept_value()); // second time should return false
        assert!(b.is_tuple());
        for (i, c) in "John".chars().enumerate() {
            b.push(c, false, 1, i + 1).unwrap();
        }
        let s = b.build();
        assert_eq!(s.is_tuple(), true);
        let (k, v) = s.as_tuple();
        assert_eq!(k, "name");
        assert_eq!(v.len(), 1);
        assert_eq!(v[0], "John");
        assert_eq!(format!("{}", s), "name:John");
    }

    #[test]
    fn test_tuple_list() {
        let mut b = ZPLStrBuilder::new();
        assert!(b.is_empty());
        assert!(!b.is_tuple());
        assert!(!b.is_sugar());
        for (i, c) in "roles".chars().enumerate() {
            b.push(c, false, 1, i + 1).unwrap();
        }
        assert!(!b.is_empty());
        assert!(!b.is_tuple());
        assert!(!b.is_sugar());
        assert!(b.accept_value());
        assert!(!b.accept_value()); // second time should return false
        assert!(b.is_tuple());
        for (i, c) in "role1".chars().enumerate() {
            b.push(c, false, 1, i + 1).unwrap();
        }
        b.next_value();
        for (i, c) in "role2".chars().enumerate() {
            b.push(c, false, 1, i + 1).unwrap();
        }
        b.next_value();
        for (i, c) in "role3".chars().enumerate() {
            b.push(c, false, 1, i + 1).unwrap();
        }
        let s = b.build();
        assert_eq!(s.is_tuple(), true);
        let (k, v) = s.as_tuple();
        assert_eq!(k, "roles");
        assert_eq!(v.len(), 3);
        assert_eq!(v[0], "role1");
        assert_eq!(v[1], "role2");
        assert_eq!(v[2], "role3");
        assert_eq!(format!("{}", s), "roles:{role1, role2, role3}");
    }
}
