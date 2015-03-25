# -*- coding: utf-8 -*-
"""
    pygments.lexers.dsls
    ~~~~~~~~~~~~~~~~~~~~

    Lexers for various domain-specific languages.

    :copyright: Copyright 2006-2015 by the Pygments team, see AUTHORS.
    :license: BSD, see LICENSE for details.
"""

import re

from pygments.lexer import RegexLexer, bygroups, words, include, default
from pygments.token import Text, Comment, Operator, Keyword, Name, String, \
    Number, Punctuation, Literal

__all__ = ['ProtoBufLexer', 'BroLexer', 'PuppetLexer', 'RslLexer',
           'MscgenLexer', 'VGLLexer', 'AlloyLexer', 'PanLexer']


class ProtoBufLexer(RegexLexer):
    """
    Lexer for `Protocol Buffer <http://code.google.com/p/protobuf/>`_
    definition files.

    .. versionadded:: 1.4
    """

    name = 'Protocol Buffer'
    aliases = ['protobuf', 'proto']
    filenames = ['*.proto']

    tokens = {
        'root': [
            (r'[ \t]+', Text),
            (r'[,;{}\[\]()]', Punctuation),
            (r'/(\\\n)?/(\n|(.|\n)*?[^\\]\n)', Comment.Single),
            (r'/(\\\n)?\*(.|\n)*?\*(\\\n)?/', Comment.Multiline),
            (words((
                'import', 'option', 'optional', 'required', 'repeated', 'default',
                'packed', 'ctype', 'extensions', 'to', 'max', 'rpc', 'returns',
                'oneof'), prefix=r'\b', suffix=r'\b'),
             Keyword),
            (words((
                'int32', 'int64', 'uint32', 'uint64', 'sint32', 'sint64',
                'fixed32', 'fixed64', 'sfixed32', 'sfixed64',
                'float', 'double', 'bool', 'string', 'bytes'), suffix=r'\b'),
             Keyword.Type),
            (r'(true|false)\b', Keyword.Constant),
            (r'(package)(\s+)', bygroups(Keyword.Namespace, Text), 'package'),
            (r'(message|extend)(\s+)',
             bygroups(Keyword.Declaration, Text), 'message'),
            (r'(enum|group|service)(\s+)',
             bygroups(Keyword.Declaration, Text), 'type'),
            (r'\".*?\"', String),
            (r'\'.*?\'', String),
            (r'(\d+\.\d*|\.\d+|\d+)[eE][+-]?\d+[LlUu]*', Number.Float),
            (r'(\d+\.\d*|\.\d+|\d+[fF])[fF]?', Number.Float),
            (r'(\-?(inf|nan))\b', Number.Float),
            (r'0x[0-9a-fA-F]+[LlUu]*', Number.Hex),
            (r'0[0-7]+[LlUu]*', Number.Oct),
            (r'\d+[LlUu]*', Number.Integer),
            (r'[+-=]', Operator),
            (r'([a-zA-Z_][\w.]*)([ \t]*)(=)',
             bygroups(Name.Attribute, Text, Operator)),
            ('[a-zA-Z_][\w.]*', Name),
        ],
        'package': [
            (r'[a-zA-Z_]\w*', Name.Namespace, '#pop'),
            default('#pop'),
        ],
        'message': [
            (r'[a-zA-Z_]\w*', Name.Class, '#pop'),
            default('#pop'),
        ],
        'type': [
            (r'[a-zA-Z_]\w*', Name, '#pop'),
            default('#pop'),
        ],
    }


class BroLexer(RegexLexer):
    """
    For `Bro <http://bro-ids.org/>`_ scripts.

    .. versionadded:: 1.5
    """
    name = 'Bro'
    aliases = ['bro']
    filenames = ['*.bro']

    _hex = r'[0-9a-fA-F_]'
    _float = r'((\d*\.?\d+)|(\d+\.?\d*))([eE][-+]?\d+)?'
    _h = r'[A-Za-z0-9][-A-Za-z0-9]*'

    tokens = {
        'root': [
            # Whitespace
            (r'^@.*?\n', Comment.Preproc),
            (r'#.*?\n', Comment.Single),
            (r'\n', Text),
            (r'\s+', Text),
            (r'\\\n', Text),
            # Keywords
            (r'(add|alarm|break|case|const|continue|delete|do|else|enum|event'
             r'|export|for|function|if|global|hook|local|module|next'
             r'|of|print|redef|return|schedule|switch|type|when|while)\b', Keyword),
            (r'(addr|any|bool|count|counter|double|file|int|interval|net'
             r'|pattern|port|record|set|string|subnet|table|time|timer'
             r'|vector)\b', Keyword.Type),
            (r'(T|F)\b', Keyword.Constant),
            (r'(&)((?:add|delete|expire)_func|attr|(?:create|read|write)_expire'
             r'|default|disable_print_hook|raw_output|encrypt|group|log'
             r'|mergeable|optional|persistent|priority|redef'
             r'|rotate_(?:interval|size)|synchronized)\b',
             bygroups(Punctuation, Keyword)),
            (r'\s+module\b', Keyword.Namespace),
            # Addresses, ports and networks
            (r'\d+/(tcp|udp|icmp|unknown)\b', Number),
            (r'(\d+\.){3}\d+', Number),
            (r'(' + _hex + r'){7}' + _hex, Number),
            (r'0x' + _hex + r'(' + _hex + r'|:)*::(' + _hex + r'|:)*', Number),
            (r'((\d+|:)(' + _hex + r'|:)*)?::(' + _hex + r'|:)*', Number),
            (r'(\d+\.\d+\.|(\d+\.){2}\d+)', Number),
            # Hostnames
            (_h + r'(\.' + _h + r')+', String),
            # Numeric
            (_float + r'\s+(day|hr|min|sec|msec|usec)s?\b', Literal.Date),
            (r'0[xX]' + _hex, Number.Hex),
            (_float, Number.Float),
            (r'\d+', Number.Integer),
            (r'/', String.Regex, 'regex'),
            (r'"', String, 'string'),
            # Operators
            (r'[!%*/+:<=>?~|-]', Operator),
            (r'([-+=&|]{2}|[+=!><-]=)', Operator),
            (r'(in|match)\b', Operator.Word),
            (r'[{}()\[\]$.,;]', Punctuation),
            # Identfier
            (r'([_a-zA-Z]\w*)(::)', bygroups(Name, Name.Namespace)),
            (r'[a-zA-Z_]\w*', Name)
        ],
        'string': [
            (r'"', String, '#pop'),
            (r'\\([\\abfnrtv"\']|x[a-fA-F0-9]{2,4}|[0-7]{1,3})', String.Escape),
            (r'[^\\"\n]+', String),
            (r'\\\n', String),
            (r'\\', String)
        ],
        'regex': [
            (r'/', String.Regex, '#pop'),
            (r'\\[\\nt/]', String.Regex),  # String.Escape is too intense here.
            (r'[^\\/\n]+', String.Regex),
            (r'\\\n', String.Regex),
            (r'\\', String.Regex)
        ]
    }


class PuppetLexer(RegexLexer):
    """
    For `Puppet <http://puppetlabs.com/>`__ configuration DSL.

    .. versionadded:: 1.6
    """
    name = 'Puppet'
    aliases = ['puppet']
    filenames = ['*.pp']

    tokens = {
        'root': [
            include('comments'),
            include('keywords'),
            include('names'),
            include('numbers'),
            include('operators'),
            include('strings'),

            (r'[]{}:(),;[]', Punctuation),
            (r'[^\S\n]+', Text),
        ],

        'comments': [
            (r'\s*#.*$', Comment),
            (r'/(\\\n)?[*](.|\n)*?[*](\\\n)?/', Comment.Multiline),
        ],

        'operators': [
            (r'(=>|\?|<|>|=|\+|-|/|\*|~|!|\|)', Operator),
            (r'(in|and|or|not)\b', Operator.Word),
        ],

        'names': [
            ('[a-zA-Z_]\w*', Name.Attribute),
            (r'(\$\S+)(\[)(\S+)(\])', bygroups(Name.Variable, Punctuation,
                                               String, Punctuation)),
            (r'\$\S+', Name.Variable),
        ],

        'numbers': [
            # Copypasta from the Python lexer
            (r'(\d+\.\d*|\d*\.\d+)([eE][+-]?[0-9]+)?j?', Number.Float),
            (r'\d+[eE][+-]?[0-9]+j?', Number.Float),
            (r'0[0-7]+j?', Number.Oct),
            (r'0[xX][a-fA-F0-9]+', Number.Hex),
            (r'\d+L', Number.Integer.Long),
            (r'\d+j?', Number.Integer)
        ],

        'keywords': [
            # Left out 'group' and 'require'
            # Since they're often used as attributes
            (words((
                'absent', 'alert', 'alias', 'audit', 'augeas', 'before', 'case',
                'check', 'class', 'computer', 'configured', 'contained',
                'create_resources', 'crit', 'cron', 'debug', 'default',
                'define', 'defined', 'directory', 'else', 'elsif', 'emerg',
                'err', 'exec', 'extlookup', 'fail', 'false', 'file',
                'filebucket', 'fqdn_rand', 'generate', 'host', 'if', 'import',
                'include', 'info', 'inherits', 'inline_template', 'installed',
                'interface', 'k5login', 'latest', 'link', 'loglevel',
                'macauthorization', 'mailalias', 'maillist', 'mcx', 'md5',
                'mount', 'mounted', 'nagios_command', 'nagios_contact',
                'nagios_contactgroup', 'nagios_host', 'nagios_hostdependency',
                'nagios_hostescalation', 'nagios_hostextinfo', 'nagios_hostgroup',
                'nagios_service', 'nagios_servicedependency', 'nagios_serviceescalation',
                'nagios_serviceextinfo', 'nagios_servicegroup', 'nagios_timeperiod',
                'node', 'noop', 'notice', 'notify', 'package', 'present', 'purged',
                'realize', 'regsubst', 'resources', 'role', 'router', 'running',
                'schedule', 'scheduled_task', 'search', 'selboolean', 'selmodule',
                'service', 'sha1', 'shellquote', 'split', 'sprintf',
                'ssh_authorized_key', 'sshkey', 'stage', 'stopped', 'subscribe',
                'tag', 'tagged', 'template', 'tidy', 'true', 'undef', 'unmounted',
                'user', 'versioncmp', 'vlan', 'warning', 'yumrepo', 'zfs', 'zone',
                'zpool'), prefix='(?i)', suffix=r'\b'),
             Keyword),
        ],

        'strings': [
            (r'"([^"])*"', String),
            (r"'(\\'|[^'])*'", String),
        ],

    }


class RslLexer(RegexLexer):
    """
    `RSL <http://en.wikipedia.org/wiki/RAISE>`_ is the formal specification
    language used in RAISE (Rigorous Approach to Industrial Software Engineering)
    method.

    .. versionadded:: 2.0
    """
    name = 'RSL'
    aliases = ['rsl']
    filenames = ['*.rsl']
    mimetypes = ['text/rsl']

    flags = re.MULTILINE | re.DOTALL

    tokens = {
        'root': [
            (words((
                'Bool', 'Char', 'Int', 'Nat', 'Real', 'Text', 'Unit', 'abs',
                'all', 'always', 'any', 'as', 'axiom', 'card', 'case', 'channel',
                'chaos', 'class', 'devt_relation', 'dom', 'elems', 'else', 'elif',
                'end', 'exists', 'extend', 'false', 'for', 'hd', 'hide', 'if',
                'in', 'is', 'inds', 'initialise', 'int', 'inter', 'isin', 'len',
                'let', 'local', 'ltl_assertion', 'object', 'of', 'out', 'post',
                'pre', 'read', 'real', 'rng', 'scheme', 'skip', 'stop', 'swap',
                'then', 'theory', 'test_case', 'tl', 'transition_system', 'true',
                'type', 'union', 'until', 'use', 'value', 'variable', 'while',
                'with', 'write', '~isin', '-inflist', '-infset', '-list',
                '-set'), prefix=r'\b', suffix=r'\b'),
             Keyword),
            (r'(variable|value)\b', Keyword.Declaration),
            (r'--.*?\n', Comment),
            (r'<:.*?:>', Comment),
            (r'\{!.*?!\}', Comment),
            (r'/\*.*?\*/', Comment),
            (r'^[ \t]*([\w]+)[ \t]*:[^:]', Name.Function),
            (r'(^[ \t]*)([\w]+)([ \t]*\([\w\s,]*\)[ \t]*)(is|as)',
             bygroups(Text, Name.Function, Text, Keyword)),
            (r'\b[A-Z]\w*\b', Keyword.Type),
            (r'(true|false)\b', Keyword.Constant),
            (r'".*"', String),
            (r'\'.\'', String.Char),
            (r'(><|->|-m->|/\\|<=|<<=|<\.|\|\||\|\^\||-~->|-~m->|\\/|>=|>>|'
             r'\.>|\+\+|-\\|<->|=>|:-|~=|\*\*|<<|>>=|\+>|!!|\|=\||#)',
             Operator),
            (r'[0-9]+\.[0-9]+([eE][0-9]+)?[fd]?', Number.Float),
            (r'0x[0-9a-f]+', Number.Hex),
            (r'[0-9]+', Number.Integer),
            (r'.', Text),
        ],
    }

    def analyse_text(text):
        """
        Check for the most common text in the beginning of a RSL file.
        """
        if re.search(r'scheme\s*.*?=\s*class\s*type', text, re.I) is not None:
            return 1.0


class MscgenLexer(RegexLexer):
    """
    For `Mscgen <http://www.mcternan.me.uk/mscgen/>`_ files.

    .. versionadded:: 1.6
    """
    name = 'Mscgen'
    aliases = ['mscgen', 'msc']
    filenames = ['*.msc']

    _var = r'(\w+|"(?:\\"|[^"])*")'

    tokens = {
        'root': [
            (r'msc\b', Keyword.Type),
            # Options
            (r'(hscale|HSCALE|width|WIDTH|wordwraparcs|WORDWRAPARCS'
             r'|arcgradient|ARCGRADIENT)\b', Name.Property),
            # Operators
            (r'(abox|ABOX|rbox|RBOX|box|BOX|note|NOTE)\b', Operator.Word),
            (r'(\.|-|\|){3}', Keyword),
            (r'(?:-|=|\.|:){2}'
             r'|<<=>>|<->|<=>|<<>>|<:>'
             r'|->|=>>|>>|=>|:>|-x|-X'
             r'|<-|<<=|<<|<=|<:|x-|X-|=', Operator),
            # Names
            (r'\*', Name.Builtin),
            (_var, Name.Variable),
            # Other
            (r'\[', Punctuation, 'attrs'),
            (r'\{|\}|,|;', Punctuation),
            include('comments')
        ],
        'attrs': [
            (r'\]', Punctuation, '#pop'),
            (_var + r'(\s*)(=)(\s*)' + _var,
             bygroups(Name.Attribute, Text.Whitespace, Operator, Text.Whitespace,
                      String)),
            (r',', Punctuation),
            include('comments')
        ],
        'comments': [
            (r'(?://|#).*?\n', Comment.Single),
            (r'/\*(?:.|\n)*?\*/', Comment.Multiline),
            (r'[ \t\r\n]+', Text.Whitespace)
        ]
    }


class VGLLexer(RegexLexer):
    """
    For `SampleManager VGL <http://www.thermoscientific.com/samplemanager>`_
    source code.

    .. versionadded:: 1.6
    """
    name = 'VGL'
    aliases = ['vgl']
    filenames = ['*.rpf']

    flags = re.MULTILINE | re.DOTALL | re.IGNORECASE

    tokens = {
        'root': [
            (r'\{[^}]*\}', Comment.Multiline),
            (r'declare', Keyword.Constant),
            (r'(if|then|else|endif|while|do|endwhile|and|or|prompt|object'
             r'|create|on|line|with|global|routine|value|endroutine|constant'
             r'|global|set|join|library|compile_option|file|exists|create|copy'
             r'|delete|enable|windows|name|notprotected)(?! *[=<>.,()])',
             Keyword),
            (r'(true|false|null|empty|error|locked)', Keyword.Constant),
            (r'[~^*#!%&\[\]()<>|+=:;,./?-]', Operator),
            (r'"[^"]*"', String),
            (r'(\.)([a-z_$][\w$]*)', bygroups(Operator, Name.Attribute)),
            (r'[0-9][0-9]*(\.[0-9]+(e[+\-]?[0-9]+)?)?', Number),
            (r'[a-z_$][\w$]*', Name),
            (r'[\r\n]+', Text),
            (r'\s+', Text)
        ]
    }


class AlloyLexer(RegexLexer):
    """
    For `Alloy <http://alloy.mit.edu>`_ source code.

    .. versionadded:: 2.0
    """

    name = 'Alloy'
    aliases = ['alloy']
    filenames = ['*.als']
    mimetypes = ['text/x-alloy']

    flags = re.MULTILINE | re.DOTALL

    iden_rex = r'[a-zA-Z_][\w\']*'
    text_tuple = (r'[^\S\n]+', Text)

    tokens = {
        'sig': [
            (r'(extends)\b', Keyword, '#pop'),
            (iden_rex, Name),
            text_tuple,
            (r',', Punctuation),
            (r'\{', Operator, '#pop'),
        ],
        'module': [
            text_tuple,
            (iden_rex, Name, '#pop'),
        ],
        'fun': [
            text_tuple,
            (r'\{', Operator, '#pop'),
            (iden_rex, Name, '#pop'),
        ],
        'root': [
            (r'--.*?$', Comment.Single),
            (r'//.*?$', Comment.Single),
            (r'/\*.*?\*/', Comment.Multiline),
            text_tuple,
            (r'(module|open)(\s+)', bygroups(Keyword.Namespace, Text),
                'module'),
            (r'(sig|enum)(\s+)', bygroups(Keyword.Declaration, Text), 'sig'),
            (r'(iden|univ|none)\b', Keyword.Constant),
            (r'(int|Int)\b', Keyword.Type),
            (r'(this|abstract|extends|set|seq|one|lone|let)\b', Keyword),
            (r'(all|some|no|sum|disj|when|else)\b', Keyword),
            (r'(run|check|for|but|exactly|expect|as)\b', Keyword),
            (r'(and|or|implies|iff|in)\b', Operator.Word),
            (r'(fun|pred|fact|assert)(\s+)', bygroups(Keyword, Text), 'fun'),
            (r'!|#|&&|\+\+|<<|>>|>=|<=>|<=|\.|->', Operator),
            (r'[-+/*%=<>&!^|~{}\[\]().]', Operator),
            (iden_rex, Name),
            (r'[:,]', Punctuation),
            (r'[0-9]+', Number.Integer),
            (r'"(\\\\|\\"|[^"])*"', String),
            (r'\n', Text),
        ]
    }


class PanLexer(RegexLexer):
    """
    Lexer for `pan <http://github.com/quattor/pan/>`_ source files.

    Based on tcsh lexer.

    .. versionadded:: 2.0
    """

    name = 'Pan'
    aliases = ['pan']
    filenames = ['*.pan']

    tokens = {
        'root': [
            include('basic'),
            (r'\(', Keyword, 'paren'),
            (r'\{', Keyword, 'curly'),
            include('data'),
        ],
        'basic': [
            (words((
                'if', 'for', 'with', 'else', 'type', 'bind', 'while', 'valid', 'final', 'prefix',
                'unique', 'object', 'foreach', 'include', 'template', 'function', 'variable',
                'structure', 'extensible', 'declaration'), prefix=r'\b', suffix=r'\s*\b'),
             Keyword),
            (words((
                'file_contents', 'format', 'index', 'length', 'match', 'matches', 'replace',
                'splice', 'split', 'substr', 'to_lowercase', 'to_uppercase', 'debug', 'error',
                'traceback', 'deprecated', 'base64_decode', 'base64_encode', 'digest', 'escape',
                'unescape', 'append', 'create', 'first', 'nlist', 'key', 'list', 'merge', 'next',
                'prepend', 'is_boolean', 'is_defined', 'is_double', 'is_list', 'is_long',
                'is_nlist', 'is_null', 'is_number', 'is_property', 'is_resource', 'is_string',
                'to_boolean', 'to_double', 'to_long', 'to_string', 'clone', 'delete', 'exists',
                'path_exists', 'if_exists', 'return', 'value'), prefix=r'\b', suffix=r'\s*\b'),
             Name.Builtin),
            (r'#.*', Comment),
            (r'\\[\w\W]', String.Escape),
            (r'(\b\w+)(\s*)(=)', bygroups(Name.Variable, Text, Operator)),
            (r'[\[\]{}()=]+', Operator),
            (r'<<\s*(\'?)\\?(\w+)[\w\W]+?\2', String),
            (r';', Punctuation),
        ],
        'data': [
            (r'(?s)"(\\\\|\\[0-7]+|\\.|[^"\\])*"', String.Double),
            (r"(?s)'(\\\\|\\[0-7]+|\\.|[^'\\])*'", String.Single),
            (r'\s+', Text),
            (r'[^=\s\[\]{}()$"\'`\\;#]+', Text),
            (r'\d+(?= |\Z)', Number),
        ],
        'curly': [
            (r'\}', Keyword, '#pop'),
            (r':-', Keyword),
            (r'\w+', Name.Variable),
            (r'[^}:"\'`$]+', Punctuation),
            (r':', Punctuation),
            include('root'),
        ],
        'paren': [
            (r'\)', Keyword, '#pop'),
            include('root'),
        ],
    }
