using System;
using PwnedLib;

namespace PwnedGen
{
    // These tests are not meant to be automated as they require a 9GB data file to be present
    class Tests
    {
        public static void Test(string dbFileName)
        {
            assert(true);
            try { assert(false); throw new Exception("Self-test failed"); }
            catch (InvalidOperationException) { }

            var checker = new PwnedChecker(dbFileName);

            var hash1 = new byte[] { 0, 1, 52, 147, 35, 11, 120, 239, 226, 252, 149, 3, 44, 20, 108, 95, 56, 63, 215, 107 };
            assert(checker.IsPwned(hash1));
            assert(checker.GetPwnedCount(hash1) == 194);

            hash1[19]++;
            assert(!checker.IsPwned(hash1));
            assert(checker.GetPwnedCount(hash1) == 0);

            var hash2 = new byte[] { 255, 255, 255, 158, 50, 11, 167, 149, 128, 36, 55, 1, 100, 11, 186, 80, 79, 152, 196, 21 };
            assert(checker.IsPwned(hash2));
            assert(checker.GetPwnedCount(hash2) == 45);
        }

        public static void TestSpeed(string dbFileName, string[] passwords)
        {
            var start = DateTime.UtcNow;
            var checker = new PwnedChecker(dbFileName);
            foreach (string pwd in passwords)
                checker.GetPwnedCount(pwd);
            var time = DateTime.UtcNow - start;
            Console.WriteLine($"Speed: {passwords.Length / time.TotalSeconds:#,0} lookups per second");
        }

        private static void assert(bool condition)
        {
            if (!condition)
                throw new InvalidOperationException("Test failed.");
        }
    }
}
