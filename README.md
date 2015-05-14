# Diaphora
Diaphora (διαφορά, Greek for 'difference') is a program diffing plugin for IDA Pro, similar to Zynamics Bindiff or the FOSS counterparts DarunGrim, TurboDiff, etc... It was released during SyScan 2015.

At the moment, it works with IDA Pro but support for Radare2 (and maybe Pyew or even Hopper) is also planned.
For more details, please check the tutorial in the "doc" directory.

## Getting help and asking for features

You can join the mailing list https://groups.google.com/forum/?hl=es#!forum/diaphora to ask for help, new features, report issues, etc... For reporting bugs, however, I recommend using the issues tracker:  https://github.com/joxeankoret/diaphora/issues

Please note that only the last 2 versions of IDA will be supported. As of today, it means that only 6.7 and 6.8 are supported. Version 6.6 "should work" (with all the last patches that were supplied to *customers*), but no support is offered for it.

## Documentation

You can check the tutorial https://github.com/joxeankoret/diaphora/blob/master/doc/diaphora_help.pdf

## Screenshots

This is a screenshot of Diaphora diffing the [Microsoft bulletin MS15-034](https://technet.microsoft.com/en-us/library/security/ms15-034.aspx):

![Diaphora diffing MS15-034](https://pbs.twimg.com/media/CCnruP_W0AA8ksc.png:large)

These are some screenshots of Diaphora diffing the [Microsoft bulletin MS15-050]( https://technet.microsoft.com/en-us/library/security/ms15-050.aspx), extracted from the blog post [Analyzing MS15-050 With Diaphora](http://www.alex-ionescu.com/?p=271) from Alex Ionescu.

![Diaphora diffing MS15-050, best matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora2.png)
![Diaphora diffing MS15-050, partial matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora3.png)
![Diaphora diffing MS15-050, diffing pseudo-code](http://www.alex-ionescu.com/wp-content/uploads/diaphora1.png)

