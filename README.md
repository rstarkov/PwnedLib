# PwnedLib
A tiny library for looking up passwords in the Have I Been Pwned database.

## Basic usage

```C#
using (var checker = new PwnedChecker("hibp.dat"))
{
    bool pwned = checker.IsPwned("P@ssword");      // true
    int count = checker.GetPwnedCount("P@ssword"); // 5728
}
```

## Database file

The checker requires a database file to be generated from the official HIBP data file, as the official file is a plain text file not
suitable for fast lookups. To do this:

1. Download the HIBP database [here](https://haveibeenpwned.com/Passwords). Make sure to select the "ordered by hash" version, as the
generator requires that. Or use this direct link to the [torrent file](https://downloads.pwnedpasswords.com/passwords/pwned-passwords-ordered-2.0.txt.7z.torrent).
1. Run the PwnedGen project included in this repository, with two command-line arguments: the path to the (unzipped) HIBP text file, and
the output file path. The output file is overwritten without confirmation.

Using the v2 database linked above as input, the output file is 9.1 GB large. The generator verifies its MD5 hash to confirm correct
generation. The generator can also be run on future versions of the HIBP dump, but it will report a verification failure in this case,
which is safe to ignore.

## Performance

This library is optimized for minimal memory usage at the expense of speed. All lookups are performed directly on disk. As a result,
lookup speed is heavily dependent on disk speed and disk workload from other processes. Large amounts of spare RAM will significantly
speed up repeated queries due to OS file caching.

In the worst case, with the database on a heavily-loaded mechanical HDD and with limited RAM / cold start, lookup speed can be as low as
50-100 lookups per second. Running off an SSD and with RAM to spare, this library can perform around 100,000 lookups per second.
