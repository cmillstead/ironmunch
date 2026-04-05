"""Tests for batch 3 language support: sql, powershell, hcl, proto, graphql, solidity.

Verifies symbol extraction, extension mapping, and registry completeness
for each new language added in batch 3.
"""

import pytest

from codesight_mcp.parser.extractor import parse_file
from codesight_mcp.parser.languages import LANGUAGE_EXTENSIONS, LANGUAGE_REGISTRY


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------


def _symbol_names(symbols):
    """Extract symbol names as a set for assertion convenience."""
    return {s.name for s in symbols}


def _symbol_by_name(symbols, name):
    """Find a symbol by name."""
    for s in symbols:
        if s.name == name:
            return s
    return None


# ---------------------------------------------------------------------------
# Per-language symbol extraction tests
# ---------------------------------------------------------------------------


class TestSqlSymbols:
    """SQL: CREATE TABLE and CREATE FUNCTION extraction."""

    SOURCE = """\
CREATE TABLE users (
    id INT PRIMARY KEY,
    name VARCHAR(100)
);

CREATE FUNCTION get_user(uid INT) RETURNS TEXT AS $$
BEGIN
    RETURN 'hello';
END;
$$ LANGUAGE plpgsql;
"""

    def test_sql_symbols(self):
        symbols = parse_file(self.SOURCE, "test.sql", "sql")
        names = _symbol_names(symbols)
        assert "users" in names
        assert "get_user" in names

        table = _symbol_by_name(symbols, "users")
        assert table.kind == "class"

        func = _symbol_by_name(symbols, "get_user")
        assert func.kind == "function"


class TestSqlSchemaQualified:
    """SQL: schema-qualified table names preserve full qualification."""

    QUALIFIED_SOURCE = """\
CREATE TABLE public.users (
    id INT
);
"""

    UNQUALIFIED_SOURCE = """\
CREATE TABLE users (
    id INT
);
"""

    def test_sql_schema_qualified(self):
        symbols = parse_file(self.QUALIFIED_SOURCE, "test.sql", "sql")
        names = _symbol_names(symbols)
        assert "public.users" in names

    def test_sql_unqualified(self):
        symbols = parse_file(self.UNQUALIFIED_SOURCE, "test.sql", "sql")
        names = _symbol_names(symbols)
        assert "users" in names


class TestPowershellSymbols:
    """PowerShell: function and class with method."""

    SOURCE = """\
function Get-Greeting {
    param([string]$Name)
    return "Hello $Name"
}

class MyService {
    [string] SayHello() {
        return "hello"
    }
}
"""

    def test_powershell_symbols(self):
        symbols = parse_file(self.SOURCE, "test.ps1", "powershell")
        names = _symbol_names(symbols)
        assert "Get-Greeting" in names
        assert "MyService" in names
        assert "SayHello" in names

        func = _symbol_by_name(symbols, "Get-Greeting")
        assert func.kind == "function"

        cls = _symbol_by_name(symbols, "MyService")
        assert cls.kind == "class"

        method = _symbol_by_name(symbols, "SayHello")
        assert method.kind == "method"
        assert method.parent is not None  # nested inside class


class TestHclSymbols:
    """HCL: resource and variable blocks."""

    SOURCE = """\
resource "aws_instance" "web" {
  ami           = "abc-123"
  instance_type = "t2.micro"
}

variable "region" {
  default = "us-east-1"
}
"""

    def test_hcl_symbols(self):
        symbols = parse_file(self.SOURCE, "test.tf", "hcl")
        names = _symbol_names(symbols)
        assert "aws_instance.web" in names
        assert "region" in names

        resource = _symbol_by_name(symbols, "aws_instance.web")
        assert resource.kind == "class"

        var = _symbol_by_name(symbols, "region")
        assert var.kind == "constant"


class TestHclLocalsSkipped:
    """HCL: locals blocks produce no symbols (Codex finding)."""

    SOURCE = """\
locals {
  x = 1
}
"""

    def test_hcl_locals_skipped(self):
        symbols = parse_file(self.SOURCE, "test.tf", "hcl")
        assert len(symbols) == 0


class TestHclResolveKind:
    """HCL: block type determines symbol kind."""

    SOURCE = """\
resource "aws_s3_bucket" "data" {
  bucket = "my-bucket"
}

variable "env" {
  default = "prod"
}

module "vpc" {
  source = "./modules/vpc"
}
"""

    def test_hcl_resolve_kind(self):
        symbols = parse_file(self.SOURCE, "test.tf", "hcl")
        resource = _symbol_by_name(symbols, "aws_s3_bucket.data")
        assert resource is not None
        assert resource.kind == "class"

        var = _symbol_by_name(symbols, "env")
        assert var is not None
        assert var.kind == "constant"

        mod = _symbol_by_name(symbols, "vpc")
        assert mod is not None
        assert mod.kind == "function"


class TestProtoSymbols:
    """Protobuf: message, service with rpc, and enum."""

    SOURCE = """\
syntax = "proto3";

message User {
  string name = 1;
  int32 age = 2;
}

service UserService {
  rpc GetUser (GetUserRequest) returns (User);
}

enum Status {
  UNKNOWN = 0;
  ACTIVE = 1;
}
"""

    def test_proto_symbols(self):
        symbols = parse_file(self.SOURCE, "test.proto", "proto")
        names = _symbol_names(symbols)
        assert "User" in names
        assert "UserService" in names
        assert "GetUser" in names
        assert "Status" in names

        msg = _symbol_by_name(symbols, "User")
        assert msg.kind == "class"

        svc = _symbol_by_name(symbols, "UserService")
        assert svc.kind == "class"

        rpc = _symbol_by_name(symbols, "GetUser")
        assert rpc.kind == "method"  # nested in service -> function becomes method
        assert rpc.parent is not None

        enum = _symbol_by_name(symbols, "Status")
        assert enum.kind == "class"


class TestGraphqlSymbols:
    """GraphQL: type, interface, and enum definitions."""

    SOURCE = """\
type User {
  id: ID!
  name: String!
}

interface Node {
  id: ID!
}

enum Role {
  ADMIN
  USER
}
"""

    def test_graphql_symbols(self):
        symbols = parse_file(self.SOURCE, "test.graphql", "graphql")
        names = _symbol_names(symbols)
        assert "User" in names
        assert "Node" in names
        assert "Role" in names

        for sym in symbols:
            assert sym.kind == "class"


class TestSoliditySymbols:
    """Solidity: contract with function, event, and modifier."""

    SOURCE = """\
pragma solidity ^0.8.0;

contract Token {
    event Transfer(address from, address to, uint256 value);

    modifier onlyOwner() {
        require(msg.sender == owner);
        _;
    }

    function transfer(address to, uint256 amount) public onlyOwner {
        emit Transfer(msg.sender, to, amount);
    }
}
"""

    def test_solidity_symbols(self):
        symbols = parse_file(self.SOURCE, "test.sol", "solidity")
        names = _symbol_names(symbols)
        assert "Token" in names
        assert "Transfer" in names
        assert "onlyOwner" in names
        assert "transfer" in names

        contract = _symbol_by_name(symbols, "Token")
        assert contract.kind == "class"

        # Nested symbols become methods
        transfer_fn = _symbol_by_name(symbols, "transfer")
        assert transfer_fn.kind == "method"
        assert transfer_fn.parent is not None

        event = _symbol_by_name(symbols, "Transfer")
        assert event.kind == "method"
        assert event.parent is not None

        modifier = _symbol_by_name(symbols, "onlyOwner")
        assert modifier.kind == "method"
        assert modifier.parent is not None


class TestSolidityUnnamedSkipped:
    """Solidity: unnamed constructor/fallback/receive produce no named symbols (Codex finding)."""

    SOURCE = """\
pragma solidity ^0.8.0;

contract Vault {
    constructor() {
    }

    fallback() external {
    }

    receive() external payable {
    }
}
"""

    def test_solidity_unnamed_skipped(self):
        symbols = parse_file(self.SOURCE, "test.sol", "solidity")
        names = _symbol_names(symbols)
        # Only the contract itself should be extracted
        assert "Vault" in names
        # constructor, fallback, receive have no identifier child -> skipped
        assert len(symbols) == 1


# ---------------------------------------------------------------------------
# Extension mapping tests
# ---------------------------------------------------------------------------


@pytest.mark.parametrize("ext,lang", [
    (".sql", "sql"),
    (".ps1", "powershell"),
    (".psm1", "powershell"),
    (".tf", "hcl"),
    (".tfvars", "hcl"),
    (".proto", "proto"),
    (".graphql", "graphql"),
    (".gql", "graphql"),
    (".sol", "solidity"),
])
def test_extension_mapping(ext, lang):
    """Verify all batch 3 file extensions map to the correct language."""
    assert LANGUAGE_EXTENSIONS[ext] == lang


def test_psd1_not_mapped():
    """PowerShell data files (.psd1) must NOT be in the extension mapping."""
    assert ".psd1" not in LANGUAGE_EXTENSIONS


# ---------------------------------------------------------------------------
# Registry completeness test
# ---------------------------------------------------------------------------

BATCH3_LANGUAGES = ["sql", "powershell", "hcl", "proto", "graphql", "solidity"]


def test_batch3_in_registry():
    """All 6 batch 3 languages must be registered in LANGUAGE_REGISTRY."""
    for lang in BATCH3_LANGUAGES:
        assert lang in LANGUAGE_REGISTRY, f"{lang} not in LANGUAGE_REGISTRY"
