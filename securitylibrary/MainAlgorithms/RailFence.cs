using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class RailFence : ICryptographicTechnique<string, int>
    {
        public int Analyse(string plainText, string cipherText)
        {
            if (plainText.Length != cipherText.Length)
                return -1;
            int key = 1;
            while (true)
            {
                int countChars = 0, idx = 0;
                string resultingCipherText = "";
                for(int prv = 0; ; idx += key)
                {
                    // All characters were used.
                    if (countChars == plainText.Length)
                        break;

                    // An end of a row was reached.
                    // Go to the first character of
                    // the following row.
                    if(idx >= plainText.Length)
                    {
                        idx = prv + 1;
                        prv++;
                    }
                    resultingCipherText += plainText[idx];
                    countChars++;
                }
                if (resultingCipherText.Equals(cipherText, StringComparison.InvariantCultureIgnoreCase))
                    break;
                key++;
                if (key > plainText.Length)
                    return -1;
            }
            return key;
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            double x = (double)cipherText.Length / (double)key;
            int plainTextLength = (int)Math.Round(x);

            for (int plainTextIndex = 0; plainTextIndex < plainTextLength; plainTextIndex++)
            {
                int index = plainTextIndex;
                for (int i = 0; i < key; i++)
                {
                    if (index == cipherText.Length)
                        break;

                    plainText += cipherText[index];
                    index += plainTextLength;
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            List<List<char>> encryptionTable = new List<List<char>>();

            for (int i = 0; i < key; i++)
                encryptionTable.Add(new List<char>());

            int index = 0;
            while(index < plainText.Length)
            {
                int keyIndex = 0;
                while(index < plainText.Length && keyIndex < key)
                {
                    encryptionTable[keyIndex].Add(plainText[index]);
                    keyIndex++;
                    index++;
                }
            }

            string decryptedString = "";
            foreach(List<char> depth in encryptionTable)
            {
                foreach (char c in depth)
                    decryptedString += c;
            }

            return decryptedString;
        }
    }
}
