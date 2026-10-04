// Copyright (c) Microsoft Corporation.
// Licensed under the MIT License.

//! Kernel symbol tables in `/proc/kallsyms` or `System.map` format.

use std::collections::HashMap;

/// A kernel symbol.
#[derive(Debug, Clone, PartialEq, Eq)]
pub struct Symbol {
    /// The symbol's virtual address.
    pub addr: u64,
    /// The `nm`-style type letter.
    pub kind: char,
    /// The symbol name.
    pub name: String,
}

/// A table of kernel symbols, sorted by address.
#[derive(Debug, Default, Clone)]
pub struct SymbolTable {
    symbols: Vec<Symbol>,
    by_name: HashMap<String, usize>,
}

impl SymbolTable {
    /// Parses `addr type name [module]` lines, as produced by
    /// `/proc/kallsyms` and `System.map`.
    ///
    /// Module symbols, zero addresses (from a restricted `/proc/kallsyms`),
    /// and malformed lines are skipped.
    pub fn parse(text: &str) -> Self {
        let mut symbols = Vec::new();
        for line in text.lines() {
            let mut fields = line.split_whitespace();
            let (Some(addr), Some(kind), Some(name)) =
                (fields.next(), fields.next(), fields.next())
            else {
                continue;
            };
            if fields.next().is_some() {
                continue;
            }
            let Ok(addr) = u64::from_str_radix(addr, 16) else {
                continue;
            };
            let mut kind_chars = kind.chars();
            let (Some(kind), None) = (kind_chars.next(), kind_chars.next()) else {
                continue;
            };
            if addr == 0 {
                continue;
            }
            symbols.push(Symbol {
                addr,
                kind,
                name: name.to_owned(),
            });
        }
        Self::from_symbols(symbols)
    }

    /// Builds a table from a list of symbols.
    pub fn from_symbols(mut symbols: Vec<Symbol>) -> Self {
        symbols.sort_by_key(|s| s.addr);
        let mut by_name = HashMap::new();
        for (i, s) in symbols.iter().enumerate() {
            by_name.entry(s.name.clone()).or_insert(i);
        }
        Self { symbols, by_name }
    }

    /// Returns the number of symbols.
    pub fn len(&self) -> usize {
        self.symbols.len()
    }

    /// Returns true if the table is empty.
    pub fn is_empty(&self) -> bool {
        self.symbols.is_empty()
    }

    /// Looks up a symbol's address by name.
    pub fn addr(&self, name: &str) -> Option<u64> {
        self.by_name.get(name).map(|&i| self.symbols[i].addr)
    }

    /// Returns the address of the first symbol strictly above `name`'s
    /// address.
    pub fn next_addr_after(&self, name: &str) -> Option<u64> {
        let addr = self.addr(name)?;
        let i = self.symbols.partition_point(|s| s.addr <= addr);
        self.symbols.get(i).map(|s| s.addr)
    }

    /// Returns the symbol containing `addr` and the offset into it.
    pub fn lookup(&self, addr: u64) -> Option<(&Symbol, u64)> {
        let i = self.symbols.partition_point(|s| s.addr <= addr);
        let s = self.symbols.get(i.checked_sub(1)?)?;
        Some((s, addr - s.addr))
    }

    /// Formats `addr` as `symbol+offset`, or as a hex address if unknown.
    pub fn describe(&self, addr: u64) -> String {
        match self.lookup(addr) {
            Some((s, 0)) => s.name.clone(),
            Some((s, off)) => format!("{}+{:#x}", s.name, off),
            None => format!("{addr:#x}"),
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn parse_and_lookup() {
        let table = SymbolTable::parse(
            "ffffffc008000000 T _text\r\n\
             ffffffc008010000 T _stext\n\
             ffffffc008010100 t helper\n\
             0000000000000000 T restricted\n\
             ffffffc009000000 D modsym\t[somemod]\n\
             garbage\n\
             ffffffc008800000 T _etext\n",
        );
        assert_eq!(table.len(), 4);
        assert_eq!(table.addr("_stext"), Some(0xffffffc008010000));
        assert_eq!(table.addr("restricted"), None);
        assert_eq!(table.describe(0xffffffc008010104), "helper+0x4");
        assert_eq!(table.describe(0xffffffc008010000), "_stext");
        assert_eq!(table.describe(0x1000), "0x1000");
        assert_eq!(table.next_addr_after("_stext"), Some(0xffffffc008010100));
    }
}
