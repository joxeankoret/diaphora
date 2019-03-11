### Welcome!

Diaphora (διαφορά, Greek for 'difference') is a program diffing plugin for IDA Pro and Radare2, similar to Zynamics Bindiff or the FOSS counterparts DarunGrim, TurboDiff, etc... It was released during SyScan 2015.

It works with IDA 6.9 to 7.2. Support for Ghidra is in development. Support for Binary Ninja is also planned but will come after Ghidra's port. If you are looking for Radare2 support you can [check this very old fork](https://github.com/radare/diaphora).

For more details, please check the tutorial in the "doc" directory.

As with any open source project, any form of help for this project is highly appreciated. You can submit your own patches, make feature requests, report bugs or <a href="#donate">donate</a> to support the development of Diaphora.

## Features

Diaphora has support for several unique features not available in other program diffing tools, namely:

 * Exporting and importing structures and enumerations.
 * Exporting and importing pseudo-code comments.
 * Generic matching heuristics based on the pseudo-code and its AST (Abstract Syntax Tree).
 * Visually diffing pseudo-codes.
 * Support for directly matching and diffing from source codes (using the, for now, independent tool [Pigaios](https://github.com/joxeankoret/pigaios) until it's integrated into Diaphora).
 * Parallel diffing.

It also supports all of the most common features that one might expect from a program diffing tool:

 * Support for diffing patches.
 * Support for exporting and import symbols (function names, prototypes, global names, etc...).
 * Support for diffing assembler.
 * Support for diffing control flow graphs.
 * Rudimentary support for matching call graphs.
 * Support for graph based heuristics.
 * Support for constants based heuristics.

...and a long-long number of other features.

## Getting help and asking for features

You can join the [mailing list](https://groups.google.com/forum/?hl=es#!forum/diaphora) to ask for help, new features, report issues, etc... For reporting bugs, however, I recommend using the [issues tracker](https://github.com/joxeankoret/diaphora/issues). You can also check the [Wiki](https://github.com/joxeankoret/diaphora/wiki) that answers some of the most common questions.

Please note that only the last 3 versions of IDA are officially supported. As of today, it means that only IDA 7.0, 7.1 and 7.2 are supported. Versions 6.8, 6.9 and 6.95 do work (with all the last patches that were supplied to *customers*), but no official support is offered for them. However, if you run into any problem with these versions, ping me and I will do my best.

## Documentation

You can take a look to the [tutorial](https://github.com/joxeankoret/diaphora/blob/master/doc/diaphora_help.pdf).

## Screenshots

This is a screenshot of Diaphora diffing the [Microsoft bulletin MS15-034](https://technet.microsoft.com/en-us/library/security/ms15-034.aspx):

![Diaphora diffing MS15-034](https://pbs.twimg.com/media/CCnruP_W0AA8ksc.png:large)

These are some screenshots of Diaphora diffing the [Microsoft bulletin MS15-050]( https://technet.microsoft.com/en-us/library/security/ms15-050.aspx), extracted from the blog post [Analyzing MS15-050 With Diaphora](http://www.alex-ionescu.com/?p=271) from Alex Ionescu.

![Diaphora diffing MS15-050, best matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora2.png)
![Diaphora diffing MS15-050, partial matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora3.png)
![Diaphora diffing MS15-050, diffing pseudo-code](http://www.alex-ionescu.com/wp-content/uploads/diaphora1.png)

There is a screenshot of Diaphora diffing a [LuaBot malware targeting cable modems](https://w00tsec.blogspot.com/2016/09/luabot-malware-targeting-cable-modems.html) against libLua for ARM:

![Diaphora diffing a LuaBot, matches and pseudo-code](https://1.bp.blogspot.com/-O5UjSOyjCgg/V5byA-ozXVI/AAAAAAAABaY/yRTMDTSD9zI0mSy4AsHN21ZYf_YvctnkwCLcB/s1600/evs-compile.png)

Here is a screenshot of Diaphora diffing [iBoot from iOS 10.3.3 against iOS 11.0](http://matteyeux.me/hacking/2018/04/04/diaphora-diff-and-ida.html):

![Diaphora diffing iBoot from iOS 10.3.3 against iOS 11.0](http://matteyeux.me/images/newgraph.PNG)

## Donate

If you like Diaphora, you can make a donation to support the development of this project.

<a href="https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&hosted_button_id=68Z4H8SE7N64L"><img src="https://www.paypalobjects.com/webstatic/en_US/btn/btn_donate_cc_147x47.png"></a>

## List of Diaphora supporters

Below are all the Diaphora supporters who generously made a donation (in no specific order):

 * Quynh Nguyen, author of <a href="http://www.capstone-engine.org">Capstone</a>.
 * Francisco Alonso, <a href="https://twitter.com/revskills">revskills</a>.
 * Denis Laskov, <a href="https://twitter.com/it4sec">it4sec</a>.
 * Pawel Wylecial, <a href="https://twitter.com/h0wlu">h0wlu</a>.
 * Stephen Sims, <a href="https://twitter.com/Steph3nSims">Steph3nSims</a>.
 * Grant Willcox, <a href="https://twitter.com/tekwizz123">tekwizz123</a>.
 * Gi0, <a href="https://twitter.com/sitoiG">sitoiG</a>.
 * Shay Ber.
 * Benedikt Schmotzle, <a href="https://twitter.com/byte_swap">byte_swap</a>.
 * Many people that wish to remain anonymous.

## Contact

You can contact the author, Joxean Koret, by sending an e-mail to admin AT joxeankoret DOT com.
