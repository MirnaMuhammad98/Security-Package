using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class AutokeyVigenere : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";
            plainText = plainText.ToLower();
            for(int i=0; i < plainText.Length; i++)
            {
                int ctCharacter = cipherText[i] - (char.IsUpper(cipherText[i]) ? 'A' : 'a');
                int ptCharacter = plainText[i] - (char.IsUpper(plainText[i]) ? 'A' : 'a');

                char keyCharacter = (char)(((ctCharacter + (26 - ptCharacter)) % 26) + 'a');
                key += keyCharacter;
            }

            int ptStartPosition = key.Length - 1;
            while(ptStartPosition >= 0)
            {
                string temp = key.Substring(ptStartPosition);
                if (plainText.StartsWith(temp))
                    return key.Substring(0, key.Length - (key.Length - ptStartPosition));
                ptStartPosition--;
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";
            int j = 0;
            bool autoKey = false;
            for(int i=0; i < cipherText.Length; i++)
            {
                int ctCharacter = cipherText[i] - (char.IsUpper(cipherText[i]) ? 'A' : 'a');

                if(!autoKey && j == key.Length)
                {
                    j = 0;
                    autoKey = true;
                }
                int keyCharacter;
                if (autoKey)
                    keyCharacter = plainText[j] - (char.IsUpper(plainText[j]) ? 'A' : 'a');
                else
                    keyCharacter = key[j] - (char.IsUpper(key[j]) ? 'A' : 'a');
                j++;

                char ptCharacter = (char)(((ctCharacter + (26 - keyCharacter)) % 26) + 'a');
                plainText += ptCharacter;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            int j = 0;
            bool autoKey = false;
            for(int i=0; i < plainText.Length; i++)
            {
                int ptCharacter = plainText[i] - (char.IsUpper(plainText[i]) ? 'A' : 'a');

                if (!autoKey && j == key.Length)
                {
                    j = 0;
                    autoKey = true;
                }
                int keyCharacter;
                if(autoKey)
                    keyCharacter = plainText[j] - (char.IsUpper(plainText[j]) ? 'A' : 'a');
                else
                    keyCharacter = key[j] - (char.IsUpper(key[j]) ? 'A' : 'a');
                j++;

                char ctCharacter = (char)(((ptCharacter + keyCharacter) % 26) + 'a');
                cipherText += ctCharacter;
            }
            return cipherText;
        }
    }
}
