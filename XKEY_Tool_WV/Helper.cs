using System;
using System.Collections.Generic;
using System.IO;
using System.Linq;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;

namespace XKEY_Tool_WV
{
    public static class Helper
    {
        public static byte[] StringToByteArray(string hex)
        {
            return Enumerable.Range(0, hex.Length)
                             .Where(x => x % 2 == 0)
                             .Select(x => Convert.ToByte(hex.Substring(x, 2), 16))
                             .ToArray();
        }

        public static string ByteArrayToHex(byte[] bytes)        {
            StringBuilder result = new StringBuilder(bytes.Length * 2);
            string hexAlphabet = "0123456789ABCDEF";
            foreach (byte b in bytes)
            {
                result.Append(hexAlphabet[(int)(b >> 4)]);
                result.Append(hexAlphabet[(int)(b & 0xF)]);
            }
            return result.ToString();
        }

        public static string PrintKeyOrIV(KeyValuePair<string, byte[]> pair)
        {
            string name = Encoding.UTF8.GetString(Convert.FromBase64String(pair.Key));
            return ByteArrayToHex(pair.Value) + " " + name;
        }

        public static void ByteSwap4(byte[] data)
        {
            for (int i = 0; i < data.Length / 16; i++)
            {
                int pos = i * 16;
                for (int j = 0; j < 2; j++)
                    for (int k = 0; k < 4; k++)
                    {
                        int posA = pos + j * 4 + k;
                        int posB = pos + (3 - j) * 4 + k;
                        byte b = data[posA];
                        data[posA] = data[posB];
                        data[posB] = b;
                    }
            }
        }

        public static void ByteSwap16(byte[] data)
        {
            for (int i = 0; i < data.Length / 16; i++)
            {
                int pos = i * 16;
                for (int j = 0; j < 8; j++)
                {
                    byte b = data[pos + j];
                    data[pos + j] = data[pos + 15 - j];
                    data[pos + 15 - j] = b;
                }
            }
        }

        public static void FixHeaderChecksums(byte[] data, out byte[] crcHeader, out byte[] crcData)
        {
            Crc32 crc32 = new Crc32();
            byte[] headerNoCRC = new byte[0x40];
            for (int i = 0; i < 0x40; i++)
                if (i < 4 || i > 7)
                    headerNoCRC[i] = data[i];
            crcHeader = crc32.ComputeHash(headerNoCRC);
            crcData = crc32.ComputeHash(data, 0x40, data.Length - 0x40);
            for (int i = 0; i < 4; i++)
            {
                data[i + 4] = crcHeader[i];
                data[i + 0x18] = crcData[i];
            }
        }

        public static Aes GetAes(byte[] key, byte[] iv)
        {
            Aes aes = Aes.Create();
            aes.Mode = CipherMode.CBC;
            aes.KeySize = 128;
            aes.BlockSize = 128;
            aes.FeedbackSize = 128;
            aes.Padding = PaddingMode.None;
            aes.Key = key;
            aes.IV = iv;
            return aes;
        }        
    }
}
