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
            throw new NotImplementedException();
        }

        public string Decrypt(string cipherText, int key)
        {
            string plainText = "";
            int plainTextLength = cipherText.Length / key;
            int index = 0;
            while(index < cipherText.Length)
            {
                int plainTextIndex = 0;
                while(index < cipherText.Length && plainTextIndex < plainTextLength)
                {
                    plainText += cipherText[index];
                    index++;
                    plainTextIndex++;
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, int key)
        {
            List<List<char>> encryptionTable = new List<List<char>>(key);
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
