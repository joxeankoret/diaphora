# -*- coding: utf-8 -*-
"""
    pygments.lexers.rdf
    ~~~~~~~~~~~~~~~~~~~

    Lexers for semantic web and RDF query languages and markup.

    :copyright: Copyright 2006-2015 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

import re

from pygments.lexer import RegexLexer, bygroups, default
from pygments.token import Keyword, Punctuation, String, Number, Operator, \
    Whitespace, Name, Literal, Comment, Text

__all__ = ['SparqlLexer']


class SparqlLexer(RegexLexer):
    """
    Lexer for `SPARQL <http://www.w3.org/TR/rdf-sparql-query/>`_ query language.

    .. versionadded:: 2.0
    """
    name = 'SPARQL'
    aliases = ['sparql']
    filenames = ['*.rq', '*.sparql']
    mimetypes = ['application/sparql-query']

    flags = re.IGNORECASE

    tokens = {
        'root': [
            (r'\s+', Whitespace),
            (r'(select|construct|describe|ask|where|filter|group\s+by|minus|'
             r'distinct|reduced|from named|from|order\s+by|limit|'
             r'offset|bindings|load|clear|drop|create|add|move|copy|'
             r'insert\s+data|delete\s+data|delete\s+where|delete|insert|'
             r'using named|using|graph|default|named|all|optional|service|'
             r'silent|bind|union|not in|in|as|a)', Keyword),
            (r'(prefix|base)(\s+)([a-z][\w-]*)(\s*)(\:)',
             bygroups(Keyword, Whitespace, Name.Namespace, Whitespace,
                      Punctuation)),
            (r'\?[a-z_]\w*', Name.Variable),
            (r'<[^>]+>', Name.Label),
            (r'([a-z][\w-]*)(\:)([a-z][\w-]*)',
             bygroups(Name.Namespace, Punctuation, Name.Tag)),
            (r'(str|lang|langmatches|datatype|bound|iri|uri|bnode|rand|abs|'
             r'ceil|floor|round|concat|strlen|ucase|lcase|encode_for_uri|'
             r'contains|strstarts|strends|strbefore|strafter|year|month|day|'
             r'hours|minutes|seconds|timezone|tz|now|md5|sha1|sha256|sha384|'
             r'sha512|coalesce|if|strlang|strdt|sameterm|isiri|isuri|isblank|'
             r'isliteral|isnumeric|regex|substr|replace|exists|not exists|'
             r'count|sum|min|max|avg|sample|group_concat|separator)\b',
             Name.Function),
            (r'(true|false)', Literal),
            (r'[+\-]?\d*\.\d+', Number.Float),
            (r'[+\-]?\d*(:?\.\d+)?E[+\-]?\d+', Number.Float),
            (r'[+\-]?\d+', Number.Integer),
            (r'(\|\||&&|=|\*|\-|\+|/)', Operator),
            (r'[(){}.;,:^]', Punctuation),
            (r'#[^\n]+', Comment),
            (r'"""', String, 'triple-double-quoted-string'),
            (r'"', String, 'single-double-quoted-string'),
            (r"'''", String, 'triple-single-quoted-string'),
            (r"'", String, 'single-single-quoted-string'),
        ],
        'triple-double-quoted-string': [
            (r'"""', String, 'end-of-string'),
            (r'[^\\]+', String),
            (r'\\', String, 'string-escape'),
        ],
        'single-double-quoted-string': [
            (r'"', String, 'end-of-string'),
            (r'[^"\\\n]+', String),
            (r'\\', String, 'string-escape'),
        ],
        'triple-single-quoted-string': [
            (r"'''", String, 'end-of-string'),
            (r'[^\\]+', String),
            (r'\\', String, 'string-escape'),
        ],
        'single-single-quoted-string': [
            (r"'", String, 'end-of-string'),
            (r"[^'\\\n]+", String),
            (r'\\', String, 'string-escape'),
        ],
        'string-escape': [
            (r'.', String, '#pop'),
        ],
        'end-of-string': [
            (r'(@)([a-z]+(:?-[a-z0-9]+)*)',
             bygroups(Operator, Name.Function), '#pop:2'),
            (r'\^\^', Operator, '#pop:2'),
            default('#pop:2'),
        ],
    }
