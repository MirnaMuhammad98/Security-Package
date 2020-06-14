using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary.RC4
{
    /// <summary>
    /// If the string starts with 0x.... then it's Hexadecimal not string
    /// </summary>
    public class RC4 : CryptographicTechnique
    {
        public override string Decrypt(string cipherText, string key)
        {
            return crypt(cipherText, key);
        }

        public override  string Encrypt(string plainText, string key)
        {
            return crypt(plainText, key);
        }

        private byte[] GetBytesFromHex(string text)
        {
            return Enumerable.Range(0, text.Length / 2)
                    .Select(x => Convert.ToByte(text.Substring(x * 2, 2), 16))
                    .ToArray();
        }

        public string crypt(string text, string key)
        {

            byte[] S = new byte[256];
            byte[] T = new byte[256];
            byte[] message, keyBytes;

            bool isHex = false;
            if (text.StartsWith("0x"))
            {
                isHex = true;
                text = text.Replace("0x", "");
                message = GetBytesFromHex(text);
                keyBytes = GetBytesFromHex(key.Replace("0x", ""));
            }
            else
            {
                message = Encoding.Default.GetBytes(text);
                keyBytes = Encoding.Default.GetBytes(key);
            }

            int keyLen = keyBytes.Length;
            int i;
            for (i = 0; i < 256; i++)
            {
                S[i] = (byte)i;
                T[i] = keyBytes[i % keyLen];
            }

            int j = 0;
            for (i = 0; i < 256; i++)
            {
                j = (j + S[i] + T[i]) % 256;

                byte temp = S[i];
                S[i] = S[j];
                S[j] = temp;

            }

            i = 0; j = 0;
            int index = 0;
            foreach (byte msgByte in message)
            {
                i = (i + 1) % 256;
                j = (j + S[i]) % 256;

                byte temp = S[i];
                S[i] = S[j];
                S[j] = temp;

                int t = (S[i] + S[j]) % 256;
                message[index] ^= S[t]; 
                index++;
            }

            string cryptedText; 

            if (isHex)
            {
                cryptedText = BitConverter.ToString(message).Replace("-", "");
                return "0x" + cryptedText.ToLower();
            }
            else
            {
                cryptedText = Encoding.Default.GetString(message);
            }
            return cryptedText;
        }
    }
}
