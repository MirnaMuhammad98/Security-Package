using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;
using System.Text.RegularExpressions;

namespace SecurityLibrary {
    public class Columnar : ICryptographicTechnique<string, List<int>> {
        public List<int> Analyse(string plainText, string cipherText) {
            plainText = plainText.ToLower();
            cipherText = cipherText.ToLower();
            List<int> key = new List<int>();
            if(plainText == cipherText) {
                key.Add(1);
                return key;
            }
            bool foundKey = false;
            for (int i = 2; i <= plainText.Length; i++) {
                PermutationGenerator permutationGenerator = new PermutationGenerator(i);
                key = permutationGenerator.generate();
                while (key.Count != 0) {
                    string currentCipherText = this.Encrypt(plainText, key);
                    if (currentCipherText == cipherText) {
                        foundKey = true;
                        break;
                    }
                    key = permutationGenerator.generate();
                }
                if (foundKey)
                    break;
            }
            return key;
        }

        public string Decrypt(string cipherText, List<int> key) {
            string plainText = "";
            int cipherTextLength = cipherText.Length;
            int steps = cipherTextLength / key.Count;
            int remainder = cipherTextLength % key.Count;
            for (int i = 0; i < steps; i++) {
                for (int k = 0; k < key.Count; k++) {
                    int column = key[k] - 1;
                    int extraSteps = 0;
                    if (column < remainder)
                        extraSteps = column;
                    int cipherIndex = column * steps + extraSteps + i;
                    plainText += cipherText[cipherIndex];
                    if(column < remainder && i == steps - 1) {
                        plainText += cipherText[cipherIndex + 1];
                        i++;
                    }
                }
            }
            return plainText;
        }

        public string Encrypt(string plainText, List<int> key) {
            string cipherText = "";
            int plainTextLength = plainText.Length;
            int steps = key.Count;
            for(int k = 1; k <= key.Count; k++) {
                int currentColumn = key.IndexOf(k);
                for(int i = 0; i + currentColumn < plainTextLength; i += steps) {
                    cipherText += plainText[i + currentColumn];
                }
            }
            return cipherText;
        }
    }
}
