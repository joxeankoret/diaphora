# Diaphora
Diaphora (διαφορά, Greek for 'difference') is a program diffing plugin for IDA, similar to Zynamics Bindiff or other FOSS counterparts like YaDiff, DarunGrim, TurboDiff, etc... It was released during SyScan 2015.

It works with IDA 6.9 to 7.2. Support for Ghidra is in development. Support for Binary Ninja is also planned but will come after Ghidra's port. If you are looking for Radare2 support you can [check this very old fork](https://github.com/radare/diaphora).

For more details, please check the tutorial in the "doc" directory.

NOTE: If you're looking for a tool for diffing or matching functions between binaries and source codes, you might want to take a look to [Pigaios](https://github.com/joxeankoret/pigaios).

## Getting help and asking for features

You can join the mailing list https://groups.google.com/forum/?hl=es#!forum/diaphora to ask for help, new features, report issues, etc... For reporting bugs, however, I recommend using the issues tracker:  https://github.com/joxeankoret/diaphora/issues

Please note that only the last 3 versions of IDA are officially supported. As of today, it means that only IDA 7.0, 7.1 and 7.2 are supported. Versions 6.8, 6.9 and 6.95 do work (with all the last patches that were supplied to *customers*), but no official support is offered for them. However, if you run into any problem with these versions, ping me and I will do my best.

## Donations

You can help (or thank) the author of Diaphora by making a donation, if you feel like doing so: [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&amp;hosted_button_id=68Z4H8SE7N64L)

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
