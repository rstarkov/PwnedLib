# PwnedLib
A tiny library for looking up passwords in the Have I Been Pwned database.

## Basic usage

```C#
var checker = new PwnedChecker("hibp.dat");

bool pwned = checker.IsPwned("P@ssword");      // true
int count = checker.GetPwnedCount("P@ssword"); // 5728
```

## Database file

The checker requires a database file to be generated from the official HIBP data file, as the official file is a plain text file not
suitable for fast lookups. To do this:

1. Download the HIBP database [here](https://haveibeenpwned.com/Passwords). Make sure to select the "ordered by hash" version, as the
generator requires that. Or use this direct link to the [torrent file](https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-2.0.txt.7z.torrent).
1. Run the PwnedGen project included in this repository, with two command-line arguments: the path to the (unzipped) HIBP text file, and
the output file path. The output file is overwritten without confirmation.

If the input is the v2 database linked above, the output file will be 9.1 GB. The generator verifies its MD5 hash to confirm correct
generation. The generator can also be run on future versions of the HIBP dump, but it will report a verification failure in this case,
which is safe to ignore.
