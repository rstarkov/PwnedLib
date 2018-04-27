using System;
using System.IO;
using System.Security.Cryptography;
using System.Text;

namespace PwnedLib
{
    /// <summary>
    ///     Implements methods to look up passwords in the Have I Been Pwned database. This class is not thread-safe, but
    ///     multiple instances can safely operate in parallel on the same database file.</summary>
    public class PwnedChecker : IDisposable
    {
        private Stream _stream;
        private BinaryReader2 _reader;

        /// <summary>Gets the file name of the HIBP database.</summary>
        public string DbFileName { get; private set; }

        /// <summary>
        ///     Constructor. Ensures that the specified database file exists. The database file remains open until this
        ///     instance is disposed of. Creating instances of this class is cheap, but reusing an instance when performing
        ///     large numbers of lookups will improve performance.</summary>
        /// <param name="dbFileName">
        ///     The name of the HIBP database file. The format of this file is specific to PwnedLib; use PwnedGen to generate
        ///     one. See documentation on the project website.</param>
        public PwnedChecker(string dbFileName)
        {
            DbFileName = dbFileName;
            if (!File.Exists(dbFileName))
                throw new ArgumentException($"The specified file does not exist: \"{dbFileName}\"", "dbFileName");
            _stream = File.Open(DbFileName, FileMode.Open, FileAccess.Read, FileShare.Read);
            _reader = new BinaryReader2(_stream);
        }

        /// <summary>Disposes of this class and closes the database file.</summary>
        public void Dispose()
        {
            _stream?.Dispose();
            _reader?.Dispose();
            _stream = null;
            _reader = null;
        }

        /// <summary>
        ///     Checks whether the specified password is in the HIBP database.</summary>
        /// <param name="hash">
        ///     SHA-1 hash of the password to look up.</param>
        public bool IsPwned(byte[] hash)
        {
            return getPwned(hash, false) != 0;
        }

        /// <summary>
        ///     Checks whether the specified password is in the HIBP database.</summary>
        /// <param name="password">
        ///     The password to look up.</param>
        public bool IsPwned(string password)
        {
            if (password == null)
                throw new ArgumentNullException("password");
            return IsPwned(SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        /// <summary>
        ///     Returns the number of accounts seen in the HIBP database with the specified password. See <see
        ///     cref="IsPwned(byte[])"/> for a marginally faster check.</summary>
        /// <param name="hash">
        ///     SHA-1 hash of the password to look up.</param>
        public int GetPwnedCount(byte[] hash)
        {
            return getPwned(hash, true);
        }

        /// <summary>
        ///     Returns the number of accounts seen in the HIBP database with the specified password. See <see
        ///     cref="IsPwned(string)"/> for a marginally faster check.</summary>
        /// <param name="password">
        ///     The password to look up.</param>
        public int GetPwnedCount(string password)
        {
            if (password == null)
                throw new ArgumentNullException("password");
            return GetPwnedCount(SHA1.Create().ComputeHash(Encoding.UTF8.GetBytes(password)));
        }

        private int getPwned(byte[] hash, bool needCount)
        {
            if (hash == null)
                throw new ArgumentNullException("hash");
            if (hash.Length != 20)
                throw new ArgumentException("The hash is expected to be 20 bytes long.", "hash");
            if (_stream == null || _reader == null)
                throw new ObjectDisposedException(nameof(PwnedChecker));

            int prefix = (hash[0] << 16) + (hash[1] << 8) + hash[2];
            _stream.Position = prefix * 5;
            long pos = _reader.ReadUInt32();
            pos += (long) _reader.ReadByte() << 32;
            if (pos == 0)
                return 0;
            _stream.Position = pos;

            int entryCount = _reader.Read7BitEncodedInt();
            if (entryCount == 0)
                return 0;

            var bytes = _reader.ReadBytes(entryCount * 17);
            int min = 0;
            int max = entryCount - 1;
            int cur = 0;
            while (true)
            {
                cur = (min + max) / 2;
                for (int i = 0; i < 17; i++)
                {
                    int cmp = hash[3 + i] - bytes[cur * 17 + i];
                    if (cmp < 0)
                    {
                        max = cur - 1;
                        goto different;
                    }
                    else if (cmp > 0)
                    {
                        min = cur + 1;
                        goto different;
                    }
                }
                break; // match found; its index is in "cur"
                different:
                if (min > max)
                    return 0;
            }

            if (!needCount)
                return 1;

            for (int i = 0; i < cur; i++)
                _reader.Read7BitEncodedInt();
            return _reader.Read7BitEncodedInt();
        }
    }

    class BinaryReader2 : BinaryReader
    {
        public BinaryReader2(Stream input) : base(input) { }
        public new int Read7BitEncodedInt() => base.Read7BitEncodedInt();
    }
}
