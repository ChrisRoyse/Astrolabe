// grammar_stubs.c — NULL-returning tree-sitter grammar factories for the
// grammar-subset build (#283).
//
// This translation unit is compiled ONLY in a `CBM_GRAMMAR_SET=core` build
// (see patches/cbm/Makefile.cbm). In that build the Makefile drops every
// non-core grammar_<lang>.c shim from GRAMMAR_SRCS, so the tree_sitter_<lang>()
// symbols those shims defined would otherwise be UNDEFINED at link time —
// lang_specs.c references each grammar factory by direct extern symbol. This
// file supplies each dropped symbol as a NULL-returning stub so the archive
// links intact, WITHOUT the real ~1.19 GiB of parser tables.
//
// Fail-closed contract: a stubbed factory returns NULL (never a bogus
// TSLanguage). cbm.c's parse path detects "spec->ts_factory != NULL yet
// ts_factory() == NULL" and raises a labeled CBM_GRAMMAR_STUBBED error naming
// the CBM_GRAMMAR_SET knob — a stubbed language is a hard, named skip, never a
// silent parse miss.
//
// Duplicate-symbol safety: every stub below is guarded by `#ifndef CBM_CORE_<lang>`.
// The Makefile passes `-DCBM_CORE_<lang>` for exactly the core languages whose
// real grammar_<lang>.c IS still compiled, so this file emits a stub for a
// language if and only if its real parser was dropped — the two are mutually
// exclusive, so no symbol is ever defined twice.
//
// Default builds (`CBM_GRAMMAR_SET=full`) do NOT compile this file at all (it is
// filtered out of the full-set wildcard); the whole body is additionally
// wrapped in `#ifdef CBM_GRAMMAR_SET_CORE` as belt-and-suspenders so it is inert
// if ever compiled outside a core build.
//
// This file is generated to mirror the full extern grammar-factory list in
// lang_specs.c. If a grammar is added/removed there, update this list too (the
// core build will fail to link on any missing symbol — fail closed).

#include "tree_sitter/api.h" // TSLanguage

#ifdef CBM_GRAMMAR_SET_CORE

#ifndef CBM_CORE_ada
const TSLanguage *tree_sitter_ada(void) { return NULL; }
#endif
#ifndef CBM_CORE_agda
const TSLanguage *tree_sitter_agda(void) { return NULL; }
#endif
#ifndef CBM_CORE_apex
const TSLanguage *tree_sitter_apex(void) { return NULL; }
#endif
#ifndef CBM_CORE_asm
const TSLanguage *tree_sitter_asm(void) { return NULL; }
#endif
#ifndef CBM_CORE_astro
const TSLanguage *tree_sitter_astro(void) { return NULL; }
#endif
#ifndef CBM_CORE_awk
const TSLanguage *tree_sitter_awk(void) { return NULL; }
#endif
#ifndef CBM_CORE_bash
const TSLanguage *tree_sitter_bash(void) { return NULL; }
#endif
#ifndef CBM_CORE_beancount
const TSLanguage *tree_sitter_beancount(void) { return NULL; }
#endif
#ifndef CBM_CORE_bibtex
const TSLanguage *tree_sitter_bibtex(void) { return NULL; }
#endif
#ifndef CBM_CORE_bicep
const TSLanguage *tree_sitter_bicep(void) { return NULL; }
#endif
#ifndef CBM_CORE_bitbake
const TSLanguage *tree_sitter_bitbake(void) { return NULL; }
#endif
#ifndef CBM_CORE_blade
const TSLanguage *tree_sitter_blade(void) { return NULL; }
#endif
#ifndef CBM_CORE_c
const TSLanguage *tree_sitter_c(void) { return NULL; }
#endif
#ifndef CBM_CORE_c_sharp
const TSLanguage *tree_sitter_c_sharp(void) { return NULL; }
#endif
#ifndef CBM_CORE_cairo
const TSLanguage *tree_sitter_cairo(void) { return NULL; }
#endif
#ifndef CBM_CORE_capnp
const TSLanguage *tree_sitter_capnp(void) { return NULL; }
#endif
#ifndef CBM_CORE_cfml
const TSLanguage *tree_sitter_cfml(void) { return NULL; }
#endif
#ifndef CBM_CORE_cfscript
const TSLanguage *tree_sitter_cfscript(void) { return NULL; }
#endif
#ifndef CBM_CORE_clojure
const TSLanguage *tree_sitter_clojure(void) { return NULL; }
#endif
#ifndef CBM_CORE_cmake
const TSLanguage *tree_sitter_cmake(void) { return NULL; }
#endif
#ifndef CBM_CORE_COBOL
const TSLanguage *tree_sitter_COBOL(void) { return NULL; }
#endif
#ifndef CBM_CORE_commonlisp
const TSLanguage *tree_sitter_commonlisp(void) { return NULL; }
#endif
#ifndef CBM_CORE_cpp
const TSLanguage *tree_sitter_cpp(void) { return NULL; }
#endif
#ifndef CBM_CORE_crystal
const TSLanguage *tree_sitter_crystal(void) { return NULL; }
#endif
#ifndef CBM_CORE_css
const TSLanguage *tree_sitter_css(void) { return NULL; }
#endif
#ifndef CBM_CORE_csv
const TSLanguage *tree_sitter_csv(void) { return NULL; }
#endif
#ifndef CBM_CORE_cuda
const TSLanguage *tree_sitter_cuda(void) { return NULL; }
#endif
#ifndef CBM_CORE_d
const TSLanguage *tree_sitter_d(void) { return NULL; }
#endif
#ifndef CBM_CORE_dart
const TSLanguage *tree_sitter_dart(void) { return NULL; }
#endif
#ifndef CBM_CORE_devicetree
const TSLanguage *tree_sitter_devicetree(void) { return NULL; }
#endif
#ifndef CBM_CORE_diff
const TSLanguage *tree_sitter_diff(void) { return NULL; }
#endif
#ifndef CBM_CORE_dockerfile
const TSLanguage *tree_sitter_dockerfile(void) { return NULL; }
#endif
#ifndef CBM_CORE_dotenv
const TSLanguage *tree_sitter_dotenv(void) { return NULL; }
#endif
#ifndef CBM_CORE_elisp
const TSLanguage *tree_sitter_elisp(void) { return NULL; }
#endif
#ifndef CBM_CORE_elixir
const TSLanguage *tree_sitter_elixir(void) { return NULL; }
#endif
#ifndef CBM_CORE_elm
const TSLanguage *tree_sitter_elm(void) { return NULL; }
#endif
#ifndef CBM_CORE_erlang
const TSLanguage *tree_sitter_erlang(void) { return NULL; }
#endif
#ifndef CBM_CORE_fennel
const TSLanguage *tree_sitter_fennel(void) { return NULL; }
#endif
#ifndef CBM_CORE_fish
const TSLanguage *tree_sitter_fish(void) { return NULL; }
#endif
#ifndef CBM_CORE_form
const TSLanguage *tree_sitter_form(void) { return NULL; }
#endif
#ifndef CBM_CORE_fortran
const TSLanguage *tree_sitter_fortran(void) { return NULL; }
#endif
#ifndef CBM_CORE_fsharp
const TSLanguage *tree_sitter_fsharp(void) { return NULL; }
#endif
#ifndef CBM_CORE_func
const TSLanguage *tree_sitter_func(void) { return NULL; }
#endif
#ifndef CBM_CORE_gdscript
const TSLanguage *tree_sitter_gdscript(void) { return NULL; }
#endif
#ifndef CBM_CORE_gitattributes
const TSLanguage *tree_sitter_gitattributes(void) { return NULL; }
#endif
#ifndef CBM_CORE_gitignore
const TSLanguage *tree_sitter_gitignore(void) { return NULL; }
#endif
#ifndef CBM_CORE_gleam
const TSLanguage *tree_sitter_gleam(void) { return NULL; }
#endif
#ifndef CBM_CORE_glsl
const TSLanguage *tree_sitter_glsl(void) { return NULL; }
#endif
#ifndef CBM_CORE_gn
const TSLanguage *tree_sitter_gn(void) { return NULL; }
#endif
#ifndef CBM_CORE_go
const TSLanguage *tree_sitter_go(void) { return NULL; }
#endif
#ifndef CBM_CORE_gomod
const TSLanguage *tree_sitter_gomod(void) { return NULL; }
#endif
#ifndef CBM_CORE_gotmpl
const TSLanguage *tree_sitter_gotmpl(void) { return NULL; }
#endif
#ifndef CBM_CORE_graphql
const TSLanguage *tree_sitter_graphql(void) { return NULL; }
#endif
#ifndef CBM_CORE_groovy
const TSLanguage *tree_sitter_groovy(void) { return NULL; }
#endif
#ifndef CBM_CORE_hare
const TSLanguage *tree_sitter_hare(void) { return NULL; }
#endif
#ifndef CBM_CORE_haskell
const TSLanguage *tree_sitter_haskell(void) { return NULL; }
#endif
#ifndef CBM_CORE_hcl
const TSLanguage *tree_sitter_hcl(void) { return NULL; }
#endif
#ifndef CBM_CORE_hlsl
const TSLanguage *tree_sitter_hlsl(void) { return NULL; }
#endif
#ifndef CBM_CORE_html
const TSLanguage *tree_sitter_html(void) { return NULL; }
#endif
#ifndef CBM_CORE_hyprlang
const TSLanguage *tree_sitter_hyprlang(void) { return NULL; }
#endif
#ifndef CBM_CORE_ini
const TSLanguage *tree_sitter_ini(void) { return NULL; }
#endif
#ifndef CBM_CORE_ispc
const TSLanguage *tree_sitter_ispc(void) { return NULL; }
#endif
#ifndef CBM_CORE_janet_simple
const TSLanguage *tree_sitter_janet_simple(void) { return NULL; }
#endif
#ifndef CBM_CORE_java
const TSLanguage *tree_sitter_java(void) { return NULL; }
#endif
#ifndef CBM_CORE_javascript
const TSLanguage *tree_sitter_javascript(void) { return NULL; }
#endif
#ifndef CBM_CORE_jinja2
const TSLanguage *tree_sitter_jinja2(void) { return NULL; }
#endif
#ifndef CBM_CORE_jsdoc
const TSLanguage *tree_sitter_jsdoc(void) { return NULL; }
#endif
#ifndef CBM_CORE_json
const TSLanguage *tree_sitter_json(void) { return NULL; }
#endif
#ifndef CBM_CORE_json5
const TSLanguage *tree_sitter_json5(void) { return NULL; }
#endif
#ifndef CBM_CORE_jsonnet
const TSLanguage *tree_sitter_jsonnet(void) { return NULL; }
#endif
#ifndef CBM_CORE_julia
const TSLanguage *tree_sitter_julia(void) { return NULL; }
#endif
#ifndef CBM_CORE_just
const TSLanguage *tree_sitter_just(void) { return NULL; }
#endif
#ifndef CBM_CORE_kconfig
const TSLanguage *tree_sitter_kconfig(void) { return NULL; }
#endif
#ifndef CBM_CORE_kdl
const TSLanguage *tree_sitter_kdl(void) { return NULL; }
#endif
#ifndef CBM_CORE_kotlin
const TSLanguage *tree_sitter_kotlin(void) { return NULL; }
#endif
#ifndef CBM_CORE_lean
const TSLanguage *tree_sitter_lean(void) { return NULL; }
#endif
#ifndef CBM_CORE_linkerscript
const TSLanguage *tree_sitter_linkerscript(void) { return NULL; }
#endif
#ifndef CBM_CORE_liquid
const TSLanguage *tree_sitter_liquid(void) { return NULL; }
#endif
#ifndef CBM_CORE_llvm
const TSLanguage *tree_sitter_llvm(void) { return NULL; }
#endif
#ifndef CBM_CORE_lua
const TSLanguage *tree_sitter_lua(void) { return NULL; }
#endif
#ifndef CBM_CORE_luau
const TSLanguage *tree_sitter_luau(void) { return NULL; }
#endif
#ifndef CBM_CORE_magma
const TSLanguage *tree_sitter_magma(void) { return NULL; }
#endif
#ifndef CBM_CORE_make
const TSLanguage *tree_sitter_make(void) { return NULL; }
#endif
#ifndef CBM_CORE_markdown
const TSLanguage *tree_sitter_markdown(void) { return NULL; }
#endif
#ifndef CBM_CORE_matlab
const TSLanguage *tree_sitter_matlab(void) { return NULL; }
#endif
#ifndef CBM_CORE_mermaid
const TSLanguage *tree_sitter_mermaid(void) { return NULL; }
#endif
#ifndef CBM_CORE_meson
const TSLanguage *tree_sitter_meson(void) { return NULL; }
#endif
#ifndef CBM_CORE_move
const TSLanguage *tree_sitter_move(void) { return NULL; }
#endif
#ifndef CBM_CORE_nasm
const TSLanguage *tree_sitter_nasm(void) { return NULL; }
#endif
#ifndef CBM_CORE_nickel
const TSLanguage *tree_sitter_nickel(void) { return NULL; }
#endif
#ifndef CBM_CORE_nix
const TSLanguage *tree_sitter_nix(void) { return NULL; }
#endif
#ifndef CBM_CORE_objc
const TSLanguage *tree_sitter_objc(void) { return NULL; }
#endif
#ifndef CBM_CORE_ocaml
const TSLanguage *tree_sitter_ocaml(void) { return NULL; }
#endif
#ifndef CBM_CORE_odin
const TSLanguage *tree_sitter_odin(void) { return NULL; }
#endif
#ifndef CBM_CORE_pascal
const TSLanguage *tree_sitter_pascal(void) { return NULL; }
#endif
#ifndef CBM_CORE_perl
const TSLanguage *tree_sitter_perl(void) { return NULL; }
#endif
#ifndef CBM_CORE_php_only
const TSLanguage *tree_sitter_php_only(void) { return NULL; }
#endif
#ifndef CBM_CORE_pine
const TSLanguage *tree_sitter_pine(void) { return NULL; }
#endif
#ifndef CBM_CORE_pkl
const TSLanguage *tree_sitter_pkl(void) { return NULL; }
#endif
#ifndef CBM_CORE_po
const TSLanguage *tree_sitter_po(void) { return NULL; }
#endif
#ifndef CBM_CORE_pony
const TSLanguage *tree_sitter_pony(void) { return NULL; }
#endif
#ifndef CBM_CORE_powershell
const TSLanguage *tree_sitter_powershell(void) { return NULL; }
#endif
#ifndef CBM_CORE_prisma
const TSLanguage *tree_sitter_prisma(void) { return NULL; }
#endif
#ifndef CBM_CORE_properties
const TSLanguage *tree_sitter_properties(void) { return NULL; }
#endif
#ifndef CBM_CORE_proto
const TSLanguage *tree_sitter_proto(void) { return NULL; }
#endif
#ifndef CBM_CORE_puppet
const TSLanguage *tree_sitter_puppet(void) { return NULL; }
#endif
#ifndef CBM_CORE_purescript
const TSLanguage *tree_sitter_purescript(void) { return NULL; }
#endif
#ifndef CBM_CORE_python
const TSLanguage *tree_sitter_python(void) { return NULL; }
#endif
#ifndef CBM_CORE_qmljs
const TSLanguage *tree_sitter_qmljs(void) { return NULL; }
#endif
#ifndef CBM_CORE_r
const TSLanguage *tree_sitter_r(void) { return NULL; }
#endif
#ifndef CBM_CORE_racket
const TSLanguage *tree_sitter_racket(void) { return NULL; }
#endif
#ifndef CBM_CORE_regex
const TSLanguage *tree_sitter_regex(void) { return NULL; }
#endif
#ifndef CBM_CORE_requirements
const TSLanguage *tree_sitter_requirements(void) { return NULL; }
#endif
#ifndef CBM_CORE_rescript
const TSLanguage *tree_sitter_rescript(void) { return NULL; }
#endif
#ifndef CBM_CORE_ron
const TSLanguage *tree_sitter_ron(void) { return NULL; }
#endif
#ifndef CBM_CORE_rst
const TSLanguage *tree_sitter_rst(void) { return NULL; }
#endif
#ifndef CBM_CORE_ruby
const TSLanguage *tree_sitter_ruby(void) { return NULL; }
#endif
#ifndef CBM_CORE_rust
const TSLanguage *tree_sitter_rust(void) { return NULL; }
#endif
#ifndef CBM_CORE_scala
const TSLanguage *tree_sitter_scala(void) { return NULL; }
#endif
#ifndef CBM_CORE_scheme
const TSLanguage *tree_sitter_scheme(void) { return NULL; }
#endif
#ifndef CBM_CORE_scss
const TSLanguage *tree_sitter_scss(void) { return NULL; }
#endif
#ifndef CBM_CORE_slang
const TSLanguage *tree_sitter_slang(void) { return NULL; }
#endif
#ifndef CBM_CORE_smali
const TSLanguage *tree_sitter_smali(void) { return NULL; }
#endif
#ifndef CBM_CORE_smithy
const TSLanguage *tree_sitter_smithy(void) { return NULL; }
#endif
#ifndef CBM_CORE_solidity
const TSLanguage *tree_sitter_solidity(void) { return NULL; }
#endif
#ifndef CBM_CORE_soql
const TSLanguage *tree_sitter_soql(void) { return NULL; }
#endif
#ifndef CBM_CORE_sosl
const TSLanguage *tree_sitter_sosl(void) { return NULL; }
#endif
#ifndef CBM_CORE_sql
const TSLanguage *tree_sitter_sql(void) { return NULL; }
#endif
#ifndef CBM_CORE_squirrel
const TSLanguage *tree_sitter_squirrel(void) { return NULL; }
#endif
#ifndef CBM_CORE_ssh_config
const TSLanguage *tree_sitter_ssh_config(void) { return NULL; }
#endif
#ifndef CBM_CORE_starlark
const TSLanguage *tree_sitter_starlark(void) { return NULL; }
#endif
#ifndef CBM_CORE_svelte
const TSLanguage *tree_sitter_svelte(void) { return NULL; }
#endif
#ifndef CBM_CORE_sway
const TSLanguage *tree_sitter_sway(void) { return NULL; }
#endif
#ifndef CBM_CORE_swift
const TSLanguage *tree_sitter_swift(void) { return NULL; }
#endif
#ifndef CBM_CORE_systemverilog
const TSLanguage *tree_sitter_systemverilog(void) { return NULL; }
#endif
#ifndef CBM_CORE_tablegen
const TSLanguage *tree_sitter_tablegen(void) { return NULL; }
#endif
#ifndef CBM_CORE_tcl
const TSLanguage *tree_sitter_tcl(void) { return NULL; }
#endif
#ifndef CBM_CORE_teal
const TSLanguage *tree_sitter_teal(void) { return NULL; }
#endif
#ifndef CBM_CORE_templ
const TSLanguage *tree_sitter_templ(void) { return NULL; }
#endif
#ifndef CBM_CORE_thrift
const TSLanguage *tree_sitter_thrift(void) { return NULL; }
#endif
#ifndef CBM_CORE_tlaplus
const TSLanguage *tree_sitter_tlaplus(void) { return NULL; }
#endif
#ifndef CBM_CORE_toml
const TSLanguage *tree_sitter_toml(void) { return NULL; }
#endif
#ifndef CBM_CORE_tsx
const TSLanguage *tree_sitter_tsx(void) { return NULL; }
#endif
#ifndef CBM_CORE_typescript
const TSLanguage *tree_sitter_typescript(void) { return NULL; }
#endif
#ifndef CBM_CORE_typst
const TSLanguage *tree_sitter_typst(void) { return NULL; }
#endif
#ifndef CBM_CORE_verilog
const TSLanguage *tree_sitter_verilog(void) { return NULL; }
#endif
#ifndef CBM_CORE_vhdl
const TSLanguage *tree_sitter_vhdl(void) { return NULL; }
#endif
#ifndef CBM_CORE_vim
const TSLanguage *tree_sitter_vim(void) { return NULL; }
#endif
#ifndef CBM_CORE_vue
const TSLanguage *tree_sitter_vue(void) { return NULL; }
#endif
#ifndef CBM_CORE_wgsl
const TSLanguage *tree_sitter_wgsl(void) { return NULL; }
#endif
#ifndef CBM_CORE_wit
const TSLanguage *tree_sitter_wit(void) { return NULL; }
#endif
#ifndef CBM_CORE_wolfram
const TSLanguage *tree_sitter_wolfram(void) { return NULL; }
#endif
#ifndef CBM_CORE_xml
const TSLanguage *tree_sitter_xml(void) { return NULL; }
#endif
#ifndef CBM_CORE_yaml
const TSLanguage *tree_sitter_yaml(void) { return NULL; }
#endif
#ifndef CBM_CORE_zig
const TSLanguage *tree_sitter_zig(void) { return NULL; }
#endif
#ifndef CBM_CORE_zsh
const TSLanguage *tree_sitter_zsh(void) { return NULL; }
#endif

#endif // CBM_GRAMMAR_SET_CORE
