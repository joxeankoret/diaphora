### Welcome!

Diaphora (διαφορά, Greek for 'difference') is a Free and Open Source program diffing tool, that integrates as a plugin for IDA Pro, similar to Zynamics Bindiff or the other FOSS counterparts DarunGrim, TurboDiff, etc... It was released during SyScan 2015.

Diaphora, in its current version, integrates with IDA Pro and exclusively works with this tool (which happens to be the de-facto reverse engineering tool). However support for [Radare2](https://github.com/radare/radare2) will be added in the future. For more details, please check the tutorial in the [doc](https://github.com/joxeankoret/diaphora/tree/master/doc) directory in the [GitHub project page](https://github.com/joxeankoret/diaphora).

As with any open source project, any form of help for this project is highly appreciated. You can submit your own patches, make feature requests, report bugs or <a href="#donate">donate</a> to support the development of Diaphora.

## Getting help and asking for features

You can join the [mailing list](https://groups.google.com/forum/?hl=es#!forum/diaphora) to ask for help, new features, report issues, etc... For reporting bugs, however, I recommend using the [issues tracker](https://github.com/joxeankoret/diaphora/issues).

Please note that, officially, only the last 2 versions of IDA will be supported. As of today, however, both 6.8, 6.9 and 6.95 are supported. Versions 6.6 and 6.7 aren't supported any more and they are known not to work due to recent changes in IDAPython since version 6.9.

## Documentation

You can take a look to the [tutorial](https://github.com/joxeankoret/diaphora/blob/master/doc/diaphora_help.pdf).

## Screenshots

This is a screenshot of Diaphora diffing the [Microsoft bulletin MS15-034](https://technet.microsoft.com/en-us/library/security/ms15-034.aspx):

![Diaphora diffing MS15-034](https://pbs.twimg.com/media/CCnruP_W0AA8ksc.png:large)

These are some screenshots of Diaphora diffing the [Microsoft bulletin MS15-050]( https://technet.microsoft.com/en-us/library/security/ms15-050.aspx), extracted from the blog post [Analyzing MS15-050 With Diaphora](http://www.alex-ionescu.com/?p=271) from Alex Ionescu.

![Diaphora diffing MS15-050, best matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora2.png)
![Diaphora diffing MS15-050, partial matches](http://www.alex-ionescu.com/wp-content/uploads/diaphora3.png)
![Diaphora diffing MS15-050, diffing pseudo-code](http://www.alex-ionescu.com/wp-content/uploads/diaphora1.png)

## Why another program diffing tool?

The reasons to create one more (free and open source) program diffing tool are various, but the following are the main ones:

 * We need an Open Source tool that is updated, actively maintained and easy to modify or adapt.
 * The tool must do much more than what the current ones do. It must offer much more functionality than previously existing ones.
 * The tool should be as deeply integrated in IDA as possible (because 99% of serious researchers use IDA as the main tool).
 * The tool must not be subject to big corporation’s desires (i.e., Google).

The tool I used the most and the one I liked the most, back in the day, was Zynamics BinDiff. However, after Google bought the company, updates to it are either too slow or non existent (you can check [this issue](https://code.google.com/p/zynamics/issues/detail?id=31&can=1&q=bindiff&colspec=ID%20Product%20Type%20Status%20Priority%20Milestone%20Owner%20Summary) and, [my favourite](https://code.google.com/p/zynamics/issues/detail?id=18&can=1&q=bindiff&colspec=ID%20Product%20Type%20Status%20Priority%20Milestone%20Owner%20Summary), this one, where Google people tells to actually patch the binary and that, may be, they can have a real fix for the next week). Also, nobody can be sure Google is not going to finally kill the product making it exclusively a private tool (i.e., only for Google) or simply killing it because they don’t want to support it for a reason (like it killed GoogleCode or other things before).

Some months after Diaphora was released, Zynamics Bindiff was also released "for free" (as in "free beer", freeware software) for Linux and Windows (no support for Mac OSX) but, again, without any kind of support and, also, without any warranty that it will not be killed in the future. Naturally, you're free to use the tool that works better for you, but consider that Zynamics Bindiff doesn't come with any kind of support and it's unlikely they will fix the bugs you encounter or implement that feature you would love to have. Diaphora, on the other hand, is:

 * Actively maintained. Bugs are usually fixed in "short time" (depending on the complexity).
 * Feature requests are accepted and implemented, if interesting.
 * Pull requests are accepted, as long as they are interesting.
 * Open source. Is the tool failing in some specific way for you or do you want to adapt it to your needs? Just clone the GIT repository and do your own changes!

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

## Contact

You can contact the author, Joxean Koret, by sending an e-mail to admin AT joxeankoret DOT com.
