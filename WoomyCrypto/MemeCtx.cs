using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IO;
using System.Linq;
using System.Numerics;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace WoomyCrypto
{
    public class MemeCtx
    {
        private readonly HashAlgorithmName AlgorithmName;

        private readonly byte[] NBytes;
        private readonly byte[] EBytes;
        private readonly byte[] DBytes;

        private readonly int MessageSize;
        private int TotalSize => MessageSize + 8;
        
        private readonly BigInteger D;
        private readonly BigInteger E;
        private readonly BigInteger N;

        public MemeCtx(HashAlgorithmName name, ReadOnlySpan<byte> n, ReadOnlySpan<byte> d, ReadOnlySpan<byte> e, int msgSize)
        {
            AlgorithmName = name;
            MessageSize = msgSize;

            NBytes = n.ToArray();
            DBytes = d.ToArray();
            EBytes = e.ToArray();
            N = BytesToBigInteger(n);
            D = BytesToBigInteger(d);
            E = BytesToBigInteger(e);
        }

        private byte[] GetAesKey(ReadOnlySpan<byte> data)
        {
            using var algo = IncrementalHash.CreateHash(AlgorithmName);
            algo.AppendData(NBytes);
            algo.AppendData(EBytes);
            algo.AppendData(data);

            var hash = algo.GetCurrentHash().AsSpan();
            return hash[..0x10].ToArray();
        }

        private byte[] UnwrapSignature(ReadOnlySpan<byte> data)
        {
            var m = BytesToBigInteger(data.Slice(TotalSize - MessageSize));
            return Exponentiate(m, E);
        }

        private byte[] WrapSignaure(ReadOnlySpan<byte> data)
        {
            var d = BytesToBigInteger(data);
            return Exponentiate(d, D);
        }
        private byte[] Exponentiate(BigInteger value, BigInteger exp)
        {
            return BigIntegerToBytes(BigInteger.ModPow(value, exp, N));
        }

        private byte[] GetMessageHash(ReadOnlySpan<byte> data)
        {
            using var algo = IncrementalHash.CreateHash(AlgorithmName);
            algo.AppendData(data);
            return algo.GetHashAndReset();
        }

        private bool ConstructRecoverableMessage(Span<byte> outs, ReadOnlySpan<byte> ins, uint hashLength)
        {
            if (outs.Length <= hashLength)
                return false;

            /* Calculate offsets. */
            int paddingLength = (int)(ins.Length - outs.Length + hashLength);
            int dataLength = (int)(outs.Length - hashLength);
            var decDataSlice = ins.Slice(paddingLength, dataLength);
            var encHashSlice = outs.Slice(dataLength);

            /* Copy in data. */
            decDataSlice.CopyTo(outs);

            /* Calculate and copy in hash. */
            var hashb = GetMessageHash(ins);
            var hashs = new ReadOnlySpan<byte>(hashb)[..(int)hashLength];
            hashs.CopyTo(encHashSlice);

            return true;
        }

        public bool Sign(Span<byte> enc, ref uint outMessageLength, ReadOnlySpan<byte> dec, uint hashLength)
        {
            if (hashLength >= 0x20)
                return false;

            if (outMessageLength < MessageSize)
                return false;

            var providedOutMessageLength = outMessageLength;
            outMessageLength = (uint)(hashLength + dec.Length);
            if (providedOutMessageLength < outMessageLength)
                return false;

            if (MessageSize - hashLength > dec.Length)
                return false;

            /* Construct message. */
            var msg = new byte[MessageSize];
            if (!ConstructRecoverableMessage(msg, dec, hashLength))
                return false;

            /* Calculate offsets. */
            var payloadSize = dec.Length + hashLength - MessageSize;
            var decPayloadSlice = dec.Slice(0, (int)payloadSize);
            var encPayloadSlice = enc.Slice(0, (int)payloadSize);
            var encSigSlice = enc.Slice((int)payloadSize);

            /* Derive key. */
            var key = GetAesKey(decPayloadSlice);

            var encMsg = AesEncrypt(msg, key);
            encMsg[0] &= 0x7F;

            decPayloadSlice.CopyTo(encPayloadSlice);

            var sig = WrapSignaure(encMsg);
            sig.CopyTo(encSigSlice);

            return true;
        }

        public bool Verify(Span<byte> dec, ref uint outMessageLength, ReadOnlySpan<byte> enc, uint length,
            uint hashLength)
        {
            var messageLength = length - hashLength;

            if (length <= hashLength || hashLength >= 0x20) // TODO: 0x20 -> Hash size of algo??
                return false;
            if (outMessageLength == 0)
            {
                outMessageLength = messageLength;
                return false;
            }

            /* Calculate offsets. */
            var dataOffset = (int)(length - MessageSize);
            var hashOffset = (int)(MessageSize - hashLength);
            var paddingLength = dataOffset;
            outMessageLength = messageLength;

            /* Calculate views into the data. */
            var encData = enc.Slice(dataOffset);
            var encPadding = enc.Slice(0, paddingLength);

            var decData = dec.Slice(dataOffset);
            var decPadding = dec.Slice(0, paddingLength);
            var decMessage = dec.Slice(0, (int)messageLength);

            var sig = UnwrapSignature(enc);
            var key = GetAesKey(encPadding);

            /* Try two decryptions. */
            var l1 = AesDecrypt(sig, key);
            sig[0] |= 0x80;
            var l2 = AesDecrypt(sig, key);

            var l1hash = l1.Slice(hashOffset, (int)hashLength);
            var l2hash = l2.Slice(hashOffset, (int)hashLength);

            var l1data = l1.Slice(0, hashOffset);
            var l2data = l2.Slice(0, hashOffset);

            encPadding.CopyTo(decPadding);
            l1data.CopyTo(decData);

            /* Test first decryption. */
            var hash = GetMessageHash(decMessage).AsSpan().Slice(0, (int)hashLength);

            if (hash.SequenceEqual(l1hash))
            {
                return true;
            }

            /* Test second decryption. */
            l2data.CopyTo(decData);
            hash = GetMessageHash(decMessage).AsSpan().Slice(0, (int)hashLength);

            if (hash.SequenceEqual(l2hash))
            {
                return true;
            }

            return false;
        }


        #region AES-CMC

        /* PKHex's AES-CMC implementation. */
        private Span<byte> AesDecrypt(byte[] input, byte[] key)
        {
            var data = new byte[MessageSize];
            Array.Copy(input, input.Length - MessageSize, data, 0, MessageSize);
            var temp = new byte[0x10];
            var curblock = new byte[0x10];
            var outdata = new byte[data.Length];
            for (var i = 0; i < data.Length / 0x10; i++) // Reverse Phase 2
            {
                var ofs = ((data.Length / 0x10) - 1 - i) * 0x10;
                Array.Copy(data, ofs, curblock, 0, 0x10);
                var temp1 = Xor(temp, curblock);
                temp = AesEcbDecrypt(key, temp1);
                temp.CopyTo(outdata, ofs);
            }

            // At this point we have Phase1(buf) ^ subkey.
            // Subkey is (block first ^ block last) << 1
            // We don't have block first or block last, though?
            // How can we derive subkey?
            // Well, (a ^ a) = 0. so (block first ^ subkey) ^ (block last ^ subkey)
            // = block first ^ block last ;)
            Array.Copy(outdata, ((data.Length / 0x10) - 1) * 0x10, temp, 0, 0x10);
            temp = Xor(temp, outdata.AsSpan(0, 0x10));
            var subkey = GetSubKey(temp);
            for (var i = 0; i < data.Length / 0x10; i++)
            {
                Array.Copy(outdata, 0x10 * i, curblock, 0, 0x10);
                var temp1 = Xor(curblock, subkey);
                Array.Copy(temp1, 0, outdata, 0x10 * i, 0x10);
            }

            // Now we have Phase1Encrypt(buf).
            Array.Clear(temp, 0, 0x10); // Clear to all zero
            for (var i = 0; i < data.Length / 0x10; i++) // Phase 1: CBC Encryption.
            {
                Array.Copy(outdata, i * 0x10, curblock, 0, 0x10);
                var temp1 = AesEcbDecrypt(key, curblock);
                var temp2 = Xor(temp1, temp);
                temp2.CopyTo(outdata, i * 0x10);
                curblock.CopyTo(temp, 0);
            }

            var outbuf = (byte[])input.Clone();
            Array.Copy(outdata, 0, outbuf, outbuf.Length - MessageSize, MessageSize);

            return outbuf;
        }

        private byte[] AesEncrypt(byte[] input, byte[] key)
        {
            var data = new byte[MessageSize];
            Array.Copy(input, input.Length - MessageSize, data, 0, MessageSize);
            var temp = new byte[0x10];
            var curblock = new byte[0x10];
            var outdata = new byte[data.Length];
            for (var i = 0; i < data.Length / 0x10; i++) // Phase 1: CBC Encryption.
            {
                Array.Copy(data, i * 0x10, curblock, 0, 0x10);
                var temp1 = Xor(temp, curblock);
                temp = AesEcbEncrypt(key, temp1);
                temp.CopyTo(outdata, i * 0x10);
            }

            // In between - CMAC stuff
            var inbet = outdata.AsSpan(0, 0x10);
            temp = Xor(temp, inbet);
            var subkey = GetSubKey(temp);

            Array.Clear(temp, 0, temp.Length); // Memcpy from an all-zero buffer
            for (var i = 0; i < data.Length / 0x10; i++)
            {
                var ofs = ((data.Length / 0x10) - 1 - i) * 0x10;
                Array.Copy(outdata, ofs, curblock, 0, 0x10);
                byte[] temp2 = Xor(curblock, subkey);
                byte[] temp3 = AesEcbEncrypt(key, temp2);
                byte[] temp4 = Xor(temp3, temp);
                Array.Copy(temp4, 0, outdata, ofs, 0x10);
                temp = temp2;
            }

            var outbuf = (byte[])input.Clone();
            Array.Copy(outdata, 0, outbuf, outbuf.Length - MessageSize, MessageSize);

            return outbuf;
        }

        private static byte[] Xor(byte[] b1, ReadOnlySpan<byte> b2)
        {
            Debug.Assert(b1.Length == b2.Length);
            var x = new byte[b1.Length];
            for (var i = 0; i < b1.Length; i++)
                x[i] = (byte)(b1[i] ^ b2[i]);
            return x;
        }
        private static byte[] GetSubKey(byte[] temp)
        {
            var subkey = new byte[0x10];
            for (var ofs = 0; ofs < 0x10; ofs += 2) // Imperfect ROL implementation
            {
                byte b1 = temp[ofs + 0], b2 = temp[ofs + 1];
                subkey[ofs + 0] = (byte)((2 * b1) + (b2 >> 7));
                subkey[ofs + 1] = (byte)(2 * b2);
                if (ofs + 2 < temp.Length)
                    subkey[ofs + 1] += (byte)(temp[ofs + 2] >> 7);
            }
            if ((temp[0] & 0x80) != 0)
                subkey[0xF] ^= 0x87;
            return subkey;
        }

        private static readonly byte[] rgbIV = new byte[0x10];

        // Helper Method to perform AES ECB Encryption
        private static byte[] AesEcbEncrypt(byte[] key, byte[] data)
        {
            using var ms = new MemoryStream();
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var cs = new CryptoStream(ms, aes.CreateEncryptor(key, rgbIV), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        // Helper Method to perform AES ECB Decryption
        private static byte[] AesEcbDecrypt(byte[] key, byte[] data)
        {
            using var ms = new MemoryStream();
            using var aes = Aes.Create();
            aes.Mode = CipherMode.ECB;
            aes.Padding = PaddingMode.None;

            using var cs = new CryptoStream(ms, aes.CreateDecryptor(key, rgbIV), CryptoStreamMode.Write);
            cs.Write(data, 0, data.Length);
            cs.FlushFinalBlock();

            return ms.ToArray();
        }

        #endregion


        #region BigInteger Tools

        /* Utilities for converting back and forth with big integers and bytes. */

        const bool IsUnsigned = true;
        const bool IsBigEndian = true;

        private static byte[] BigIntegerToBytes(BigInteger integer)
        {
            return integer.ToByteArray(IsUnsigned, IsBigEndian);
        }

        private static BigInteger BytesToBigInteger(ReadOnlySpan<byte> bytes)
        {
            return new(bytes, IsUnsigned, IsBigEndian);
        }

        #endregion

    }
}
