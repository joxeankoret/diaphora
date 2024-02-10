# δiaphora

<p align='center'>
<img src="https://github.com/joxeankoret/diaphora/assets/2945834/3f1e9cf4-98d7-4d9a-b7d3-0a7354053b4e" width="10%">
</p>

Diaphora (διαφορά, Greek for 'difference') version 3.1.2 is the most advanced program diffing tool (working as an IDA plugin) available as of today (2024). It was released first during SyScan 2015 and has been actively maintained ever since: Diaphora has been ported to every single minor version of IDA since 6.8 to 8.4.

Diaphora supports versions of IDA >= 7.4 because the code only runs in Python 3.X (Python 3.11 was the last version being tested).

## Unique Features

Diaphora has many of the most common program diffing (bindiffing) features you might expect, like:

 * Diffing assembler.
 * Diffing control flow graphs.
 * Porting symbol names and comments.
 * Adding manual matches.
 * Similarity ratio calculation.
 * Batch automation.
 * Call graph matching calculation.
 * Dozens of heuristics based on graph theory, assembler, bytes, functions' features, etc...

However, Diaphora has also many features that are unique, not available in any other public tool. The following is a non extensive list of unique features:

 * Ability to port structs, enums, unions and typedefs.
 * Potentially fixed vulnerabilities detection for patch diffing sessions.
 * Support for compilation units (finding and diffing compilation units).
 * Microcode support.
 * Parallel diffing.
 * Pseudo-code based heuristics.
 * Pseudo-code patches generation.
 * Diffing pseudo-codes (with syntax highlighting!).
 * Scripting support (for both the exporting and diffing processes).
 * ...

## Donations

You can help (or thank) the author of Diaphora by making a donation. If you feel like doing so you can use one of the following links:

 * [![Liberapay](https://img.shields.io/liberapay/receives/diaphora.svg?logo=liberapay)](https://liberapay.com/Diaphora/donate)
 * [![Donate](https://img.shields.io/badge/Donate-PayPal-green.svg)](https://www.paypal.com/cgi-bin/webscr?cmd=_s-xclick&amp;hosted_button_id=68Z4H8SE7N64L)

## Support

Feel free to open issues in Github if you have any problem or need help. If you prefer to chat interactivelly, you can use the following Discord channel: https://discord.gg/atg34w2xjV

## Licensing

Versions of Diaphora prior to 1.2.4, including version 1.2.4, were licensed under the [GNU GPL version 3](https://www.gnu.org/licenses/gpl-3.0.html). Since version 2.0, Diaphora is now licensed under the [GNU Affero GPL version 3 license](https://www.gnu.org/licenses/agpl-3.0.html). The license has been changed so companies wanting to modify and adapt Diaphora cannot offer web services based on these modified versions without contributing back the changes.

For 99.99% of users, the license change doesn't affect them at all. If your company needs a different licensing model, check the next section...

## Commercial Support and Consultancy

Commercial support and consultancy is offered for legal companies. If you need support or consultancy for problems you have with your target, to develop products based on Diaphora, to use Diaphora internally interacting with your own tools, for plagiarism detection projects, etc... you can contact me at admin@joxeankoret.com for more details.

## Licensing problems

If your company does not allow using the AGPL license, you can get commercial licenses of Diaphora to use it in your company, or to use it as a particular in any company you work (similar concept as IDA's named licenses). For more details, please contact me at admin@joxeankoret.com.

## Wiki

If you are looking to how to automate the export or diffing process, or you want to speed operations, etc... You might want to take a look to the [wiki](https://github.com/joxeankoret/diaphora/wiki) where such questions are answered.

## Screenshots

Diaphora finding the exact function where a vulnerability was patched in CVE-2020-1350:

![CVE-2020-1350](https://files.mastodon.social/media_attachments/files/110/313/141/968/158/099/original/607189c509ec1cc4.png)

Diaphora, again, finding the exact function where CVE-2023-28231 was fixed:

![CVE-2023-28231](https://files.mastodon.social/media_attachments/files/110/313/148/945/529/051/original/28e032f21be414a3.png)

CVE-2023-28231. As explained in a blog from ZDI, the vulnerability was fixed by checking that the number of relay forward messages in "ProcessRelayForwardMessage()" is not bigger or equal than 32 (0x20), as shown in the following pseudo-code diffing:

![CVE-2023-28231](https://files.mastodon.social/media_attachments/files/110/300/368/934/189/808/original/fe3392db2b8234e9.png)

Diaphora doing Hex-Ray's microcode diffing:

![Diffing microcode in a graph](https://files.mastodon.social/media_attachments/files/110/157/157/910/926/533/original/6c5975e15c378cb5.png)

Diffing assembly, pseudo-code and microcode:

![Assembly, pseudo-code and microcode](https://files.mastodon.social/media_attachments/files/110/102/237/646/074/440/original/4a816df5069691c3.png)

Diffing CVE-2023-21768 with Diaphora 3.0:

![Diffing CVE-2023-21768 with #Diaphora 3.0](https://files.mastodon.social/media_attachments/files/110/066/930/153/215/408/original/86b06ae90d57d5a1.png)

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
