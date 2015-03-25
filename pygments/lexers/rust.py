# -*- coding: utf-8 -*-
"""
    pygments.lexers.rust
    ~~~~~~~~~~~~~~~~~~~~

    Lexers for the Rust language.

    :copyright: Copyright 2006-2015 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from pygments.lexer import RegexLexer, include, bygroups, words, default
from pygments.token import Comment, Operator, Keyword, Name, String, \
    Number, Punctuation, Whitespace

__all__ = ['RustLexer']


class RustLexer(RegexLexer):
    """
    Lexer for the Rust programming language (version 0.9).

    .. versionadded:: 1.6
    """
    name = 'Rust'
    filenames = ['*.rs']
    aliases = ['rust']
    mimetypes = ['text/x-rustsrc']

    tokens = {
        'root': [
            # Whitespace and Comments
            (r'\n', Whitespace),
            (r'\s+', Whitespace),
            (r'//[/!](.*?)\n', Comment.Doc),
            (r'//(.*?)\n', Comment.Single),
            (r'/\*', Comment.Multiline, 'comment'),

            # Lifetime
            (r"""'[a-zA-Z_]\w*""", Name.Label),
            # Macro parameters
            (r"""\$([a-zA-Z_]\w*|\(,?|\),?|,?)""", Comment.Preproc),
            # Keywords
            (words((
                'as', 'box', 'break', 'continue', 'do', 'else', 'enum', 'extern',
                'fn', 'for', 'if', 'impl', 'in', 'loop', 'match', 'mut', 'priv',
                'proc', 'pub', 'ref', 'return', 'static', '\'static', 'struct',
                'trait', 'true', 'type', 'unsafe', 'while'), suffix=r'\b'),
             Keyword),
            (words(('alignof', 'be', 'const', 'offsetof', 'pure', 'sizeof',
                    'typeof', 'once', 'unsized', 'yield'), suffix=r'\b'),
             Keyword.Reserved),
            (r'(mod|use)\b', Keyword.Namespace),
            (r'(true|false)\b', Keyword.Constant),
            (r'let\b', Keyword.Declaration),
            (words(('u8', 'u16', 'u32', 'u64', 'i8', 'i16', 'i32', 'i64', 'uint',
                    'int', 'f32', 'f64', 'str', 'bool'), suffix=r'\b'),
             Keyword.Type),
            (r'self\b', Name.Builtin.Pseudo),
            # Prelude
            (words((
                'Freeze', 'Pod', 'Send', 'Sized', 'Add', 'Sub', 'Mul', 'Div', 'Rem', 'Neg', 'Not', 'BitAnd',
                'BitOr', 'BitXor', 'Drop', 'Shl', 'Shr', 'Index', 'Option', 'Some', 'None', 'Result',
                'Ok', 'Err', 'from_str', 'range', 'print', 'println', 'Any', 'AnyOwnExt', 'AnyRefExt',
                'AnyMutRefExt', 'Ascii', 'AsciiCast', 'OnwedAsciiCast', 'AsciiStr',
                'IntoBytes', 'Bool', 'ToCStr', 'Char', 'Clone', 'DeepClone', 'Eq', 'ApproxEq',
                'Ord', 'TotalEq', 'Ordering', 'Less', 'Equal', 'Greater', 'Equiv', 'Container',
                'Mutable', 'Map', 'MutableMap', 'Set', 'MutableSet', 'Default', 'FromStr',
                'Hash', 'FromIterator', 'Extendable', 'Iterator', 'DoubleEndedIterator',
                'RandomAccessIterator', 'CloneableIterator', 'OrdIterator',
                'MutableDoubleEndedIterator', 'ExactSize', 'Times', 'Algebraic',
                'Trigonometric', 'Exponential', 'Hyperbolic', 'Bitwise', 'BitCount',
                'Bounded', 'Integer', 'Fractional', 'Real', 'RealExt', 'Num', 'NumCast',
                'CheckedAdd', 'CheckedSub', 'CheckedMul', 'Orderable', 'Signed',
                'Unsigned', 'Round', 'Primitive', 'Int', 'Float', 'ToStrRadix',
                'ToPrimitive', 'FromPrimitive', 'GenericPath', 'Path', 'PosixPath',
                'WindowsPath', 'RawPtr', 'Buffer', 'Writer', 'Reader', 'Seek',
                'SendStr', 'SendStrOwned', 'SendStrStatic', 'IntoSendStr', 'Str',
                'StrVector', 'StrSlice', 'OwnedStr', 'IterBytes', 'ToStr', 'IntoStr',
                'CopyableTuple', 'ImmutableTuple', 'ImmutableEqVector', 'ImmutableTotalOrdVector',
                'ImmutableCopyableVector', 'OwnedVector', 'OwnedCopyableVector',
                'OwnedEqVector', 'MutableVector', 'MutableTotalOrdVector',
                'Vector', 'VectorVector', 'CopyableVector', 'ImmutableVector',
                'Port', 'Chan', 'SharedChan', 'spawn', 'drop'), suffix=r'\b'),
             Name.Builtin),
            (r'(ImmutableTuple\d+|Tuple\d+)\b', Name.Builtin),
            # Borrowed pointer
            (r'(&)(\'[A-Za-z_]\w*)?', bygroups(Operator, Name)),
            # Labels
            (r'\'[A-Za-z_]\w*:', Name.Label),
            # Character Literal
            (r"""'(\\['"\\nrt]|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}"""
             r"""|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}|.)'""",
             String.Char),
            # Binary Literal
            (r'0b[01_]+', Number.Bin, 'number_lit'),
            # Octal Literal
            (r'0o[0-7_]+', Number.Oct, 'number_lit'),
            # Hexadecimal Literal
            (r'0[xX][0-9a-fA-F_]+', Number.Hex, 'number_lit'),
            # Decimal Literal
            (r'[0-9][0-9_]*(\.[0-9_]+[eE][+\-]?[0-9_]+|'
             r'\.[0-9_]*|[eE][+\-]?[0-9_]+)', Number.Float, 'number_lit'),
            (r'[0-9][0-9_]*', Number.Integer, 'number_lit'),
            # String Literal
            (r'"', String, 'string'),
            (r'r(#*)".*?"\1', String.Raw),

            # Operators and Punctuation
            (r'[{}()\[\],.;]', Punctuation),
            (r'[+\-*/%&|<>^!~@=:?]', Operator),

            # Identifier
            (r'[a-zA-Z_]\w*', Name),

            # Attributes
            (r'#!?\[', Comment.Preproc, 'attribute['),
            # Macros
            (r'([A-Za-z_]\w*)(!)(\s*)([A-Za-z_]\w*)?(\s*)(\{)',
             bygroups(Comment.Preproc, Punctuation, Whitespace, Name,
                      Whitespace, Punctuation), 'macro{'),
            (r'([A-Za-z_]\w*)(!)(\s*)([A-Za-z_]\w*)?(\()',
             bygroups(Comment.Preproc, Punctuation, Whitespace, Name,
                      Punctuation), 'macro('),
        ],
        'comment': [
            (r'[^*/]+', Comment.Multiline),
            (r'/\*', Comment.Multiline, '#push'),
            (r'\*/', Comment.Multiline, '#pop'),
            (r'[*/]', Comment.Multiline),
        ],
        'number_lit': [
            (r'[ui](8|16|32|64)', Keyword, '#pop'),
            (r'f(32|64)', Keyword, '#pop'),
            default('#pop'),
        ],
        'string': [
            (r'"', String, '#pop'),
            (r"""\\['"\\nrt]|\\x[0-9a-fA-F]{2}|\\[0-7]{1,3}"""
             r"""|\\u[0-9a-fA-F]{4}|\\U[0-9a-fA-F]{8}""", String.Escape),
            (r'[^\\"]+', String),
            (r'\\', String),
        ],
        'macro{': [
            (r'\{', Operator, '#push'),
            (r'\}', Operator, '#pop'),
        ],
        'macro(': [
            (r'\(', Operator, '#push'),
            (r'\)', Operator, '#pop'),
        ],
        'attribute_common': [
            (r'"', String, 'string'),
            (r'\[', Comment.Preproc, 'attribute['),
            (r'\(', Comment.Preproc, 'attribute('),
        ],
        'attribute[': [
            include('attribute_common'),
            (r'\];?', Comment.Preproc, '#pop'),
            (r'[^"\]]+', Comment.Preproc),
        ],
        'attribute(': [
            include('attribute_common'),
            (r'\);?', Comment.Preproc, '#pop'),
            (r'[^")]+', Comment.Preproc),
        ],
    }
