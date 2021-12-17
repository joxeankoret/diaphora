# Diaphora

Diaphora (διαφορά, Greek for 'difference') version 2.0 is the most advanced program diffing tool, working as an IDA plugin, available as of today (2019). It was released first during SyScan 2015 and is actively maintained.

Diaphora supports IDA 6.9 to 7.7, but the main branch has support only for IDA >= 7.4 because the code only runs in Python 3.X. If you are looking for an IDA >= 7.4 port with support for Python 2.X, check [this issue](https://github.com/joxeankoret/diaphora/issues/197).

Support for Ghidra is in development, but it will take very long. Support for Binary Ninja is also planned but will probably come after Ghidra's port. If you are looking for Radare2 support, you can [check this very old fork](https://github.com/radare/diaphora).

For more details, please check the tutorial in the "doc" directory.

NOTE: If you're looking for a tool for diffing or matching functions between binaries and source codes, you might want to take a look to [Pigaios](https://github.com/joxeankoret/pigaios).

## Unique Features

Diaphora has many of the most common program diffing (bindiffing) techniques you might expect, like:

 * Diffing assembler.
 * Diffing control flow graphs.
 * Porting symbol names and comments.
 * Addig manual matches.
 * Similarity ratio calculation.
 * Batch automation.
 * Call graph matching calculation.
 * Dozens of heuristics based on graph theory, assembler, bytes, functions' features, etc...

However, Diaphora has also many features that are unique, not available in any other public tool. The following is a non extensive list of unique features:

 * Parallel diffing.
 * Pseudo-code based heuristics.
 * Pseudo-code patches generation.
 * Ability to port structs, enums and typedefs.
 * Diffing pseudo-codes (with syntax highlighting!).
 * Scripting support (for both the exporting and diffing processes).
 * ...

It's also actively maintained, and the following is a list of the features that are 'in the making':

 * Support for compilation units (finding and diffing compilation units).
 * Direct integration with [Pigaios](https://github.com/joxeankoret/pigaios).
 * 'Machine Learning' based techniques so reverse engineers can teach Diaphora what is a good match or a bad one, and how to search for more.

## Python 2.7 and IDA versions 6.95 to 7.3

TLDR: if you're looking for a version of Diaphora supporting Python 2.X and IDA versions 6.95 to 7.3, [check this release](https://github.com/joxeankoret/diaphora/releases/tag/1.2.4) or [this branch](https://github.com/joxeankoret/diaphora/tree/diaphora-1.2).

Since IDA 7.4, Diaphora will only support Python 3.X. It means that the code in Github will only run in IDA 7.4 and Python 3.X. I've tried to make it compatible but it caused the code to be horrible and unmaintainable. As so, I've decided that it was best to drop support for Python 2.X and IDA versions <= 7.3 and focus in Python 3.X and IDA versions >= 7.4.

## Donations

You can help (or thank) the author of Diaphora by making a donation, if you feel like doing so: [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&amp;hosted_button_id=68Z4H8SE7N64L)

## License

Versions of Diaphora prior to 1.2.4, including version 1.2.4, are licensed under the [GNU GPL version 3](https://www.gnu.org/licenses/gpl-3.0.html). Since version 2.0, Diaphora is now licensed under the [GNU Affero GPL version 3 license](https://www.gnu.org/licenses/agpl-3.0.html). The license has been changed so companies wanting to modify and adapt Diaphora cannot offer web services based on these modified versions without contributing back the changes.

For 99.99% of users, the license change doesn't affect them at all. If your company needs a different licensing model, check the next section...

## Licensing

Commercial licenses of Diaphora are available. Please contact admin@joxeankoret.com for more details.

## Documentation

You can check the tutorial https://github.com/joxeankoret/diaphora/blob/master/doc/diaphora_help.pdf

## Screenshots

This is a screenshot of Diaphora diffing the PEGASUS iOS kernel Vulnerability fixed in iOS 9.3.5:

![Diffing iOS 9.3.5 diff](http://sektioneins.de/images/diaphora1.png)

And this is an old screenshot of Diaphora diffing the [Microsoft bulletin MS15-034](https://technet.microsoft.com/en-us/library/security/ms15-034.aspx):

![Diaphora diffing MS15-034](https://pbs.twimg.com/media/CCnruP_W0AA8ksc.png:large)

These are some screenshots of Diaphora diffing the [Microsoft bulletin MS15-050]( https://technet.microsoft.com/en-us/library/security/ms15-050.aspx), extracted from the blog post [Analyzing MS15-050 With Diaphora](http://www.alex-ionescu.com/?p=271) from Alex Ionescu.

![Diaphora diffing MS15-050, best matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora2.png)
![Diaphora diffing MS15-050, partial matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora3.png)
![Diaphora diffing MS15-050, diffing pseudo-code](http://www.alex-ionescu.com/wp-content/uploads/diaphora1.png)

![Diaphora diffing a LuaBot, matches and pseudo-code](https://1.bp.blogspot.com/-O5UjSOyjCgg/V5byA-ozXVI/AAAAAAAABaY/yRTMDTSD9zI0mSy4AsHN21ZYf_YvctnkwCLcB/s1600/evs-compile.png)


Here is a screenshot of Diaphora diffing [iBoot from iOS 10.3.3 against iOS 11.0](https://blog.matteyeux.com/hacking/2018/04/04/diaphora-diff-and-ida.html):

![Diaphora diffing iBoot from iOS 10.3.3 against iOS 11.0](https://blog.matteyeux.com/images/newgraph.PNG)
