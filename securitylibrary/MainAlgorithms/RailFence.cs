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
            if (cipherText.ToLower() == plainText.ToLower())
                return 1;

            int key = 2;
            while (key <= plainText.Length)
            {
                string decryptedText = Decrypt(cipherText, key);
                Console.WriteLine(decryptedText.ToLower(), plainText.ToLower());
                if (decryptedText.ToLower() == plainText.ToLower())
                    break;
                key++;
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
                    if (index >= cipherText.Length)
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
