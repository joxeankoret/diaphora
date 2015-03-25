# -*- coding: utf-8 -*-
"""
    pygments.lexers.esoteric
    ~~~~~~~~~~~~~~~~~~~~~~~~

    Lexers for esoteric languages.

    :copyright: Copyright 2006-2015 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

from pygments.lexer import RegexLexer, include
from pygments.token import Text, Comment, Operator, Keyword, Name, String, \
    Number, Punctuation, Error

__all__ = ['BrainfuckLexer', 'BefungeLexer', 'RedcodeLexer']


class BrainfuckLexer(RegexLexer):
    """
    Lexer for the esoteric `BrainFuck <http://www.muppetlabs.com/~breadbox/bf/>`_
    language.
    """

    name = 'Brainfuck'
    aliases = ['brainfuck', 'bf']
    filenames = ['*.bf', '*.b']
    mimetypes = ['application/x-brainfuck']

    tokens = {
        'common': [
            # use different colors for different instruction types
            (r'[.,]+', Name.Tag),
            (r'[+-]+', Name.Builtin),
            (r'[<>]+', Name.Variable),
            (r'[^.,+\-<>\[\]]+', Comment),
        ],
        'root': [
            (r'\[', Keyword, 'loop'),
            (r'\]', Error),
            include('common'),
        ],
        'loop': [
            (r'\[', Keyword, '#push'),
            (r'\]', Keyword, '#pop'),
            include('common'),
        ]
    }


class BefungeLexer(RegexLexer):
    """
    Lexer for the esoteric `Befunge <http://en.wikipedia.org/wiki/Befunge>`_
    language.

    .. versionadded:: 0.7
    """
    name = 'Befunge'
    aliases = ['befunge']
    filenames = ['*.befunge']
    mimetypes = ['application/x-befunge']

    tokens = {
        'root': [
            (r'[0-9a-f]', Number),
            (r'[+*/%!`-]', Operator),             # Traditional math
            (r'[<>^v?\[\]rxjk]', Name.Variable),  # Move, imperatives
            (r'[:\\$.,n]', Name.Builtin),         # Stack ops, imperatives
            (r'[|_mw]', Keyword),
            (r'[{}]', Name.Tag),                  # Befunge-98 stack ops
            (r'".*?"', String.Double),            # Strings don't appear to allow escapes
            (r'\'.', String.Single),              # Single character
            (r'[#;]', Comment),                   # Trampoline... depends on direction hit
            (r'[pg&~=@iotsy]', Keyword),          # Misc
            (r'[()A-Z]', Comment),                # Fingerprints
            (r'\s+', Text),                       # Whitespace doesn't matter
        ],
    }


class RedcodeLexer(RegexLexer):
    """
    A simple Redcode lexer based on ICWS'94.
    Contributed by Adam Blinkinsop <blinks@acm.org>.

    .. versionadded:: 0.8
    """
    name = 'Redcode'
    aliases = ['redcode']
    filenames = ['*.cw']

    opcodes = ('DAT', 'MOV', 'ADD', 'SUB', 'MUL', 'DIV', 'MOD',
               'JMP', 'JMZ', 'JMN', 'DJN', 'CMP', 'SLT', 'SPL',
               'ORG', 'EQU', 'END')
    modifiers = ('A', 'B', 'AB', 'BA', 'F', 'X', 'I')

    tokens = {
        'root': [
            # Whitespace:
            (r'\s+', Text),
            (r';.*$', Comment.Single),
            # Lexemes:
            #  Identifiers
            (r'\b(%s)\b' % '|'.join(opcodes), Name.Function),
            (r'\b(%s)\b' % '|'.join(modifiers), Name.Decorator),
            (r'[A-Za-z_]\w+', Name),
            #  Operators
            (r'[-+*/%]', Operator),
            (r'[#$@<>]', Operator),  # mode
            (r'[.,]', Punctuation),  # mode
            #  Numbers
            (r'[-+]?\d+', Number.Integer),
        ],
    }
