using System;
using System.Globalization;
using System.IO;
using System.Linq;
using System.Security.Cryptography;

namespace PwnedGen
{
    class Program
    {
        static void Main(string[] args)
        {
            generateFile(inputFileName: args[0], outputFileName: args[1]);
            verifyFile(args[1]);
        }

        static void generateFile(string inputFileName, string outputFileName)
        {
            // This file format was designed to allow reasonably efficient lookups with minimal memory usage. The file stores a list of ~500 million entries,
            // where each entry is a SHA-1 + occurrence count pair. The file consists of two parts. The first part is an index containing 256³ 5-byte entries,
            // one for each possible 3-byte SHA-1 prefix. Each 5-byte entry holds a byte position within the file pointing at a small list containing all SHA-1
            // hashes starting with the given 3-byte prefix. This list starts with a 7-bit variable-length integer recording the number of entries in the list (N),
            // followed by N 17-byte SHA-1 suffixes in sorted order, followed by N 7-bit var-length integers encoding the corresponding occurrence counts.
            //
            // This method requires the input to be a text file with one entry per line, sorted by SHA-1 hash, where each line starts with 40 characters for
            // the SHA-1 in hex format, followed by a colon, followed by the occurrence count as a plain text integer.

            using (var output = File.Open(outputFileName, FileMode.Create, FileAccess.Write, FileShare.Read))
            using (var writer = new BinaryWriter2(output))
            {
                int curPrefix = -1;
                var suffixes = new MemoryStream();
                var counts = new MemoryStream();
                var countsW = new BinaryWriter2(counts);
                int entryCount = 0;
                byte[] suffix = new byte[17];

                output.SetLength(256 * 256 * 256 * 5);
                output.Position = output.Length;

                foreach (var line in File.ReadLines(inputFileName).Concat(new[] { "" }))
                {
                    int linePrefix = line.Length == 0 ? -1 : int.Parse(line.Substring(0, 6), NumberStyles.AllowHexSpecifier);
                    if (curPrefix != linePrefix)
                    {
                        if (curPrefix >= 0)
                        {
                            var pos = output.Position;
                            output.Position = curPrefix * 5;
                            if (((ulong) pos & 0xFFFFFF00_00000000) != 0)
                                throw new Exception();
                            writer.Write((uint) pos);
                            writer.Write((byte) (pos >> 32));
                            output.Position = pos;
                            writer.Write7BitEncodedInt(entryCount);
                            writer.Write(suffixes.ToArray());
                            writer.Write(counts.ToArray());
                        }
                        if (linePrefix < 0)
                            break;

                        curPrefix = linePrefix;
                        suffixes.Position = 0;
                        suffixes.SetLength(0);
                        counts.Position = 0;
                        counts.SetLength(0);
                        entryCount = 0;
                        if (curPrefix % 16384 == 0)
                            Console.WriteLine($"Done: {curPrefix:#,0} of {256 * 256 * 256:#,0}");
                    }

                    for (int i = 0; i < suffix.Length; i++)
                        suffix[i] = (byte) ((hexChar(line[6 + (i << 1)]) << 4) + hexChar(line[7 + (i << 1)]));
                    suffixes.Write(suffix, 0, suffix.Length);
                    countsW.Write7BitEncodedInt(int.Parse(line.Substring(41)));
                    entryCount++;
                }
            }
        }

        private static int hexChar(int hexChar) => hexChar - (hexChar < 58 ? 48 : 55);

        private static void verifyFile(string fileName)
        {
            Console.WriteLine("Verifying file...");
            Console.WriteLine("  File length: " + ((new FileInfo(fileName).Length == 9_131_583_903) ? "pass" : "FAIL"));
            Console.Write("  File MD5: ");
            using (var file = File.Open(fileName, FileMode.Open, FileAccess.Read, FileShare.Read))
            {
                var actualMD5 = MD5.Create().ComputeHash(file);
                var expectedMD5 = new byte[] { 0x9a, 0xca, 0xcd, 0x3b, 0x5d, 0xde, 0x27, 0x45, 0x6b, 0xe3, 0x60, 0xf9, 0x83, 0x70, 0x7c, 0x7c };
                Console.WriteLine(actualMD5.SequenceEqual(expectedMD5) ? "pass" : "FAIL");
            }
        }
    }

    class BinaryWriter2 : BinaryWriter
    {
        public BinaryWriter2(Stream output) : base(output) { }
        public new void Write7BitEncodedInt(int value) => base.Write7BitEncodedInt(value);
    }
}