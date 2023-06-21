# Testing suite and debugging scripts

In this directory you will find the software for the Diaphora's testing suite as
well as some scripts that are used to debug some features:

 * check_indices.py: Used to determine which indices are being used and if they are correct.
 * false_positives_checker.py: Used to calculate the FPS ratio for some binaries.
 * tester.py: The actual testing suite.
 * add_sample.py: A helper script to create skeletong .cfg configuration files for testing.

# How to use the testing suite

You will first need to configure it by editing `tester.cfg`. The following is an
example such file:

```
[General]
samples-directory=/shared/samples/
diaphora-script=/shared/diaphora/diaphora.py
cpus=1

[IDA]
path=/shared/ida/ida83/

[Python]
path=/usr/bin/python3.10
```

Basically, you will need to specify your `samples` directory, the path to your
`diaphora.py` script, the path to the IDA's directory (directory, not binary) as
well as the Python binary you want to use. Also, by changing the `cpus` value you
can specify how many processes to run at the same time. This is just for configuring
the tester.

## Adding samples

In the samples directory is where you will have to put your samples and their
corresponding configuration files. Take for example the `ls` and `ls-old` binaries
that are supplied by default: there are 2 accompanying `.cfg` files. Let's take
a look to `ls.cfg`:

```
$ cat ls.cfg 
################################################################################
# Test-case for some Linux ELF x64 'ls' program
################################################################################

[Testcase]
filename=ls
export=ls.sqlite
ida-binary=idat64
decompiler=1
script=

[Export]
total basic blocks=3635
total bblocks instructions=86208
total bblocks relations=15831
total call graph items=1004
total constants=358
total functions bblocks=8562
total functions=318
total instructions=16225
total program items=1
total program data items=43
call graph primes=9.983313005596550880312916944E+365
compilation units=11
named compilation units=2
total microcode basic blocks=4875
total microcode instructions=69983

[Diff]
against=ls-old.sqlite
output=ls-vs-ls-old.db
best=132
partial=101
unreliable=0
multimatches=3
```

In this configuration file we have 3 directives:

 * Testcase: Where we specify the filename, the Diaphora's SQLite database to export, the IDA binary to launch, if we
are going to use the decompiler and some IDAPython script to launch in case we need that.
 * Export: The expected values that Diaphora should export. If they differ at exporting, something changed.
 * Diff: The export Diaphora's SQLite database to diff against, the expected results (best, partial, etc) and where to put diffing results.

Once we have at least one sample and the tester configured, we can just run the
testing suite like this:

```
$ ./tester.py 
[Wed May 21 11:25:36 2023 140405422827072] Launching probe 'export' for test samples/ls.cfg ...
[Wed May 21 11:25:58 2023 140405422827072] Probe 'samples/ls.cfg' completed
[Wed May 21 11:25:58 2023 140405422827072] Launching probe 'export' for test samples/ls-old.cfg ...
[Wed May 21 11:26:15 2023 140405422827072] Probe 'samples/ls-old.cfg' completed
[Wed May 21 11:26:15 2023 140405422827072] Launching probe 'diff' for test samples/ls.cfg ...
[Wed May 21 11:26:19 2023 140405422827072] Probe 'samples/ls.cfg' completed
[Wed May 21 11:26:19 2023 140405422827072] Launching probe 'diff' for test samples/ls-old.cfg ...
[Wed May 21 11:26:23 2023 140405422827072] Probe 'samples/ls-old.cfg' completed
[Wed May 21 11:26:23 2023 140405442479936] Total test-case(s) executed 2. Total of 0 error(s) and 0 warning(s).
[Wed May 21 11:26:23 2023 140405442479936] Done in 0:00:46.717483
```

When executed without arguments, it will first export all the samples and after
exporting, it will diff all the samples that have a `[Diff]` section. If you just
want to, say, launch the export, use this command:

```
$ ./tester.py -el
```

The command line argument `-el` means "export all". If you just want to diff all
the samples, use this command:

```
$ ./tester.py -dl
```

The command line argument `-dl` means "diff all". But please remember that the
samples must be first exported.

If you just one to run a simple test, like `ls.cfg`, do the following:

```
$ ./tester.py ls.cfg
```

The tester will try to search for a file called `ls.cfg` in the `samples-directory`
specified in the `[General]` section in `tester.cfg`.

## Adding new samples

When you want to add new samples to the testing suite, do the following:

 * Copy your binary samples to your `samples-directory`.
 * Run the script `add_sample.py` from within the samples directory. It will create
the stubs for these samples.
 * Run `tester.py -e your-sample.cfg` to get the `[Export]` values and copy-paste
them to the corresponding `sample.cfg`.
 * Add the `[Diff]` section, if required, to your `sample.cfg` file and then run
`tester.py -d your-sample.cfg`. It will show you the values that Diaphora got after
diffing the samples. Copy-paste them and you're ready to go!

