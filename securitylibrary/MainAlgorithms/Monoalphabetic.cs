using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class Monoalphabetic : ICryptographicTechnique<string, string>
    {
        public string Analyse(string plainText, string cipherText)
        {
            string key = "";

            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();

            Dictionary<char, char> charactersMap = new Dictionary<char, char>();
            for(int i = 0; i<cipherText.Length; i++)
            {
                charactersMap[plainText[i]] = cipherText[i];
            }

            Queue<char> unMappedChars = new Queue<char>();    
            for(char i = 'a'; i<='z'; i++)
            {
                if (!charactersMap.ContainsValue(i))
                    unMappedChars.Enqueue(i);
            }

            for(char i = 'a'; i <= 'z'; i++)
            {
                if (!charactersMap.ContainsKey(i))
                    key += unMappedChars.Dequeue();
                else
                    key += charactersMap[i];
            }
            return key;
        }

        public string Decrypt(string cipherText, string key)
        {
            string plainText = "";

            Dictionary<char, char> keyMap = GetKeyMap(key);
            cipherText = cipherText.ToLower();

            foreach (char c in cipherText)
            {
                plainText += keyMap[c].ToString();
            }
            return plainText;
        }

        private Dictionary<char, char> GetKeyMap(string key)
        {
            Dictionary<char, char> keyMap = new Dictionary<char, char>();
            int keyLength = key.Length;
            for (int i=0; i<keyLength; i++)
            {
                char c = key[i];
                keyMap[c] = (char)(i +'a');
            }
            return keyMap;
        }

        public string Encrypt(string plainText, string key)
        {
            string cipherText = "";
            foreach(char c in plainText)
            {
                int charIdx = c - 'a';
                cipherText += key[charIdx].ToString();
            }
            return cipherText;
        }

        /// <summary>
        /// Frequency Information:
        /// E   12.51%
        /// T	9.25
        /// A	8.04
        /// O	7.60
        /// I	7.26
        /// N	7.09
        /// S	6.54
        /// R	6.12
        /// H	5.49
        /// L	4.14
        /// D	3.99
        /// C	3.06
        /// U	2.71
        /// M	2.53
        /// F	2.30
        /// P	2.00
        /// G	1.96
        /// W	1.92
        /// Y	1.73
        /// B	1.54
        /// V	0.99
        /// K	0.67
        /// X	0.19
        /// J	0.16
        /// Q	0.11
        /// Z	0.09
        /// </summary>
        /// <param name="cipher"></param>
        /// <returns>Plain text</returns>
        public string AnalyseUsingCharFrequency(string cipher)
        {
            Queue<char> charFrequencies = GetFrequencies();

            cipher = cipher.ToLower();
            Dictionary<char, int> cipherFrequencies = new Dictionary<char, int>();
            foreach (char c in cipher)
            {
                if (cipherFrequencies.ContainsKey(c))
                    cipherFrequencies[c]++;
                else
                    cipherFrequencies.Add(c, 1);
            }

            cipherFrequencies = cipherFrequencies.OrderByDescending(o => o.Value).ToDictionary(k => k.Key, v => v.Value);

            string key = "";
            Dictionary<char, char> mappedChars = new Dictionary<char, char>();
            foreach(char c in cipherFrequencies.Keys)
                mappedChars[c] = charFrequencies.Dequeue();
            

            foreach(char c in cipher)
                key += mappedChars[c];

            return key.ToLower();
        }

        private Queue<char> GetFrequencies()
        {
            Queue<char> frequencies = new Queue<char>();
            frequencies.Enqueue('E');
            frequencies.Enqueue('T');
            frequencies.Enqueue('A');
            frequencies.Enqueue('O');
            frequencies.Enqueue('I');
            frequencies.Enqueue('N');
            frequencies.Enqueue('S');
            frequencies.Enqueue('R');
            frequencies.Enqueue('H');
            frequencies.Enqueue('L');
            frequencies.Enqueue('D');
            frequencies.Enqueue('C');
            frequencies.Enqueue('U');
            frequencies.Enqueue('M');
            frequencies.Enqueue('F');
            frequencies.Enqueue('P');
            frequencies.Enqueue('G');
            frequencies.Enqueue('W');
            frequencies.Enqueue('Y');
            frequencies.Enqueue('B');
            frequencies.Enqueue('V');
            frequencies.Enqueue('K');
            frequencies.Enqueue('X');
            frequencies.Enqueue('J');
            frequencies.Enqueue('Q');
            frequencies.Enqueue('Z');
            return frequencies;
        }
    }
}
