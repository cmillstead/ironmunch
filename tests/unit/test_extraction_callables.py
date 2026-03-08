"""Tests for language-specific extraction callables on LanguageSpec (Task 12).

Verifies that the extract_name and extract_call_target callables on LanguageSpec
produce the same results as the old hardcoded if-blocks in extractor.py.
"""

import pytest
from codesight_mcp.parser.extractor import parse_file
from codesight_mcp.parser.languages import (
    LanguageSpec,
    LANGUAGE_REGISTRY,
    _extract_name_c_cpp,
    _extract_name_dart,
    _extract_name_perl,
)


class TestExtractNameCallables:
    """Verify that extract_name callables are set on the right specs."""

    def test_c_spec_has_extract_name(self):
        assert LANGUAGE_REGISTRY["c"].extract_name is not None

    def test_cpp_spec_has_extract_name(self):
        assert LANGUAGE_REGISTRY["cpp"].extract_name is not None

    def test_dart_spec_has_extract_name(self):
        assert LANGUAGE_REGISTRY["dart"].extract_name is not None

    def test_perl_spec_has_extract_name(self):
        assert LANGUAGE_REGISTRY["perl"].extract_name is not None

    def test_python_spec_has_no_extract_name(self):
        assert LANGUAGE_REGISTRY["python"].extract_name is None

    def test_go_spec_has_no_extract_name(self):
        assert LANGUAGE_REGISTRY["go"].extract_name is None


class TestExtractCallTargetCallables:
    """Verify that extract_call_target callables are set on the right specs."""

    def test_java_spec_has_extract_call_target(self):
        assert LANGUAGE_REGISTRY["java"].extract_call_target is not None

    def test_rust_spec_has_extract_call_target(self):
        assert LANGUAGE_REGISTRY["rust"].extract_call_target is not None

    def test_php_spec_has_extract_call_target(self):
        assert LANGUAGE_REGISTRY["php"].extract_call_target is not None

    def test_csharp_spec_has_extract_call_target(self):
        assert LANGUAGE_REGISTRY["c_sharp"].extract_call_target is not None

    def test_perl_spec_has_extract_call_target(self):
        assert LANGUAGE_REGISTRY["perl"].extract_call_target is not None

    def test_ruby_spec_has_extract_call_target(self):
        assert LANGUAGE_REGISTRY["ruby"].extract_call_target is not None

    def test_python_spec_has_no_extract_call_target(self):
        assert LANGUAGE_REGISTRY["python"].extract_call_target is None

    def test_c_spec_has_no_extract_call_target(self):
        """C uses generic call_expression — no special handler needed."""
        assert LANGUAGE_REGISTRY["c"].extract_call_target is None


class TestCNameExtraction:
    """C function and typedef name extraction via extract_name callable."""

    def test_c_function_name(self):
        code = 'void greet(const char* name) {\n    printf("Hello");\n}\n'
        symbols = parse_file(code, "test.c", "c")
        funcs = [s for s in symbols if s.kind == "function"]
        assert len(funcs) >= 1
        assert funcs[0].name == "greet"

    def test_c_typedef_name(self):
        code = "typedef struct { int x; } Point;\n"
        symbols = parse_file(code, "test.c", "c")
        types = [s for s in symbols if s.kind == "type"]
        assert any(s.name == "Point" for s in types)

    def test_cpp_function_name(self):
        code = "int add(int a, int b) {\n    return a + b;\n}\n"
        symbols = parse_file(code, "test.cpp", "cpp")
        funcs = [s for s in symbols if s.kind == "function"]
        assert any(s.name == "add" for s in funcs)


class TestDartNameExtraction:
    """Dart function/method name extraction via extract_name callable."""

    def test_dart_function_name(self):
        code = "void greet(String name) {\n  print(name);\n}\n"
        symbols = parse_file(code, "test.dart", "dart")
        funcs = [s for s in symbols if s.kind == "function"]
        assert len(funcs) >= 1
        assert funcs[0].name == "greet"

    def test_dart_class_method_name(self):
        code = (
            "class Dog {\n"
            "  void bark() {\n"
            "    print('Woof');\n"
            "  }\n"
            "}\n"
        )
        symbols = parse_file(code, "test.dart", "dart")
        methods = [s for s in symbols if s.kind == "method"]
        assert any(s.name == "bark" for s in methods)


class TestPerlNameExtraction:
    """Perl subroutine and package name extraction via extract_name callable."""

    def test_perl_subroutine_name(self):
        code = "sub greet {\n    print 'Hello';\n}\n"
        symbols = parse_file(code, "test.pl", "perl")
        funcs = [s for s in symbols if s.kind == "function"]
        assert len(funcs) >= 1
        assert funcs[0].name == "greet"

    def test_perl_package_name(self):
        code = "package Animal;\nsub new { bless {}, shift }\n"
        symbols = parse_file(code, "test.pm", "perl")
        types = [s for s in symbols if s.kind == "type"]
        assert any(s.name == "Animal" for s in types)


class TestCallTargetExtraction:
    """Verify call target extraction still works with callable-based dispatch."""

    def test_java_method_invocation(self):
        code = (
            "class Foo {\n"
            "    void bar() {\n"
            "        baz();\n"
            "        obj.quux();\n"
            "    }\n"
            "}\n"
        )
        symbols = parse_file(code, "Test.java", "java")
        methods = [s for s in symbols if s.kind == "method" and s.name == "bar"]
        assert len(methods) == 1
        assert "baz" in methods[0].calls

    def test_rust_macro_invocation(self):
        code = (
            "fn main() {\n"
            "    println!(\"hello\");\n"
            "    helper();\n"
            "}\n"
        )
        symbols = parse_file(code, "main.rs", "rust")
        funcs = [s for s in symbols if s.kind == "function" and s.name == "main"]
        assert len(funcs) == 1
        assert "println" in funcs[0].calls
        assert "helper" in funcs[0].calls

    def test_php_function_call(self):
        code = "<?php\nfunction foo() {\n    bar();\n    $obj->baz();\n}\n"
        symbols = parse_file(code, "test.php", "php")
        funcs = [s for s in symbols if s.kind == "function" and s.name == "foo"]
        assert len(funcs) == 1
        assert "bar" in funcs[0].calls
        assert "baz" in funcs[0].calls

    def test_c_call_expression_generic(self):
        """C uses generic call_expression — no special callable needed."""
        code = "void foo() {\n    bar();\n    baz(1, 2);\n}\n"
        symbols = parse_file(code, "test.c", "c")
        funcs = [s for s in symbols if s.kind == "function"]
        assert "bar" in funcs[0].calls
        assert "baz" in funcs[0].calls

    def test_perl_method_call(self):
        code = (
            "sub process {\n"
            "    my $self = shift;\n"
            "    $self->validate();\n"
            "    helper();\n"
            "}\n"
        )
        symbols = parse_file(code, "test.pl", "perl")
        funcs = [s for s in symbols if s.kind == "function" and s.name == "process"]
        assert len(funcs) == 1
        assert "validate" in funcs[0].calls
        assert "helper" in funcs[0].calls

    def test_ruby_call(self):
        code = (
            "class Dog\n"
            "  def bark\n"
            "    puts 'woof'\n"
            "    wag_tail\n"
            "  end\n"
            "end\n"
        )
        symbols = parse_file(code, "test.rb", "ruby")
        methods = [s for s in symbols if s.kind == "method" and s.name == "bark"]
        # Ruby 'puts' is a call node; 'wag_tail' may or may not be depending on grammar
        assert len(methods) == 1


class TestExtractNameCallableReturnNone:
    """Verify that extract_name returns None for unhandled node types,
    allowing fallback to default name_fields logic."""

    def test_c_extract_name_returns_none_for_struct(self):
        """struct_specifier is handled by name_fields, not extract_name."""
        # _extract_name_c_cpp should return None for non-function/non-typedef
        result = _extract_name_c_cpp(type("Node", (), {"type": "struct_specifier"})(), b"")
        assert result is None

    def test_dart_extract_name_returns_none_for_class(self):
        """class_definition is handled by name_fields, not extract_name."""
        result = _extract_name_dart(type("Node", (), {"type": "class_definition"})(), b"")
        assert result is None

    def test_perl_extract_name_returns_none_for_unknown(self):
        """Unknown node types should return None."""
        result = _extract_name_perl(type("Node", (), {"type": "unknown"})(), b"")
        assert result is None
