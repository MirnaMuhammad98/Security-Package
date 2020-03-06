using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary
{
    public class PlayFair : ICryptographicTechnique<string, string>
    {
        /// <summary>
        /// The most common diagrams in english (sorted): TH, HE, AN, IN, ER, ON, RE, ED, ND, HA, AT, EN, ES, OF, NT, EA, TI, TO, IO, LE, IS, OU, AR, AS, DE, RT, VE
        /// </summary>
        /// <param name="plainText"></param>
        /// <param name="cipherText"></param>
        /// <returns></returns>
        public string Analyse(string plainText)
        {
            throw new NotImplementedException();
        }

        public string Analyse(string plainText, string cipherText)
        {
            throw new NotSupportedException();
        }

        char[,] key_matrix = new char[5, 5];
        Tuple<int, int>[] character_indeces = new Tuple<int, int>[26];

        public void Fill_key_matrix(string key)
        {
            // Filling it with the key first.
            int key_ind = 0, last_row = 0;
            for(int i = 0; i < 5 && key_ind < key.Length; i++){
                for(int j = 0; j < 5 && key_ind < key.Length; j++){
                    if(character_indeces[key[key_ind] - 'a'] == null){
                        if(key[key_ind] == 'i' || key[key_ind] == 'j'){
                            character_indeces['i' - 'a'] = Tuple.Create(i, j);
                            character_indeces['j' - 'a'] = Tuple.Create(i, j);
                            key_matrix[i,j] = 'i';
                        }
                        else{
                            character_indeces[key[key_ind] - 'a'] = Tuple.Create(i, j);
                            key_matrix[i, j] = key[key_ind];
                        }
                    }
                    else
                        j--;
                    key_ind++;
                    last_row = i;
                }
            }
            //filling it with the remaining alphabet.
            char alphabet_ch = 'a';
            for(int i = last_row; i < 5; i++){
                for(int j = 0; j < 5; j++){
                    if(key_matrix[i, j] == '\0'){
                        if(character_indeces[alphabet_ch - 'a'] == null){
                            if(alphabet_ch == 'i' || alphabet_ch == 'j'){
                                character_indeces['i' - 'a'] = Tuple.Create(i, j);
                                character_indeces['j' - 'a'] = Tuple.Create(i, j);
                                key_matrix[i,j] = 'i';
                            }
                            else{
                                character_indeces[alphabet_ch  - 'a'] = Tuple.Create(i, j);
                                key_matrix[i, j] = alphabet_ch;
                            }
                        }
                        else
                            j--;
                        alphabet_ch++;
                    }
                }
            }
        }

        public string plain_String_Preprocessing(string plainString)
        {
            // Seperate every 2 consicutive similar charachters.
            for (int i = 0; i < plainString.Length - 1; i += 2)
            {
                if (plainString[i] == plainString[i + 1])
                    plainString = plainString.Insert(i+1, "x");
            }
            if (plainString.Length % 2 == 1)
                plainString += "x";
            return plainString;
        }

        public List<string> get_decryption_pairs_list(string inputText){
            List<string> decryotionPairs = new List<string>();

            for(int i = 0; i < inputText.Length - 1; i += 2){
                decryotionPairs.Add(inputText[i].ToString() + inputText[i + 1].ToString());
            }

            return decryotionPairs;
        }

        public Tuple<int, int> get_character_index(char character){
            Tuple<int, int> curInd = character_indeces[character - 'a'];
            return curInd;
        }

        public string Decrypt(string cipherText, string key)
        {
            cipherText = cipherText.ToLower();
            key = key.ToLower();

            Fill_key_matrix(key);
            List<string> decryptionPairs = get_decryption_pairs_list(cipherText);

            //Using the key matrix to decrypt the decription pairs.
            string plainText = "";
            for (int i = 0; i < decryptionPairs.Count; i++)
            {
                Tuple<int, int> chInd1 = get_character_index(decryptionPairs[i][0]);
                Tuple<int, int> chInd2 = get_character_index(decryptionPairs[i][1]);

                if (chInd1.Item1 == chInd2.Item1){

                    chInd1 = Tuple.Create(chInd1.Item1,  ((chInd1.Item2 - 1) % 5) < 0 ? ((chInd1.Item2 - 1) % 5) + 5 : ((chInd1.Item2 - 1) % 5));
                    plainText += key_matrix[chInd1.Item1, chInd1.Item2];

                    chInd2 = Tuple.Create(chInd2.Item1, ((chInd2.Item2 - 1) % 5) < 0 ? ((chInd2.Item2 - 1) % 5) + 5 : ((chInd2.Item2 - 1) % 5));
                    plainText += key_matrix[chInd2.Item1, chInd2.Item2];
                }
                else if (chInd1.Item2 == chInd2.Item2){

                    chInd1 = Tuple.Create(((chInd1.Item1 - 1) % 5) < 0 ? ((chInd1.Item1 - 1) % 5) + 5 : ((chInd1.Item1 - 1) % 5), chInd1.Item2);
                    plainText += key_matrix[chInd1.Item1, chInd1.Item2];

                    chInd2 = Tuple.Create(((chInd2.Item1 - 1) % 5) < 0 ? ((chInd2.Item1 - 1) % 5) + 5 : ((chInd2.Item1 - 1) % 5), chInd2.Item2);
                    plainText += key_matrix[chInd2.Item1, chInd2.Item2];
                }
                else{
                    plainText += key_matrix[chInd1.Item1, chInd2.Item2];
                    plainText += key_matrix[chInd2.Item1, chInd1.Item2];
                }
            }

            // Remove any excess x's in the decrypted string
            if(plainText[plainText.Length - 1] == 'x')
                plainText = plainText.Remove(plainText.Length - 1, 1);
            for (int i = 0; i < plainText.Length - 2; i++)
            {
                if (plainText[i] == plainText[i + 2] && plainText[i + 1] == 'x')
                    plainText = plainText.Remove(i + 1, 1);
                else
                    i++;
            }
            return plainText;
        }

        public string Encrypt(string plainText, string key)
        {
            plainText = plainText.ToLower();
            key = key.ToLower();

            Fill_key_matrix(key);
            List<string> decryptionPairs = get_decryption_pairs_list(plain_String_Preprocessing(plainText));

            //Using the key matrix to decrypt the decription pairs.
            string cipherText = "";
            for (int i = 0; i < decryptionPairs.Count; i++)
            {
                Tuple<int, int> chInd1 = get_character_index(decryptionPairs[i][0]);
                Tuple<int, int> chInd2 = get_character_index(decryptionPairs[i][1]);

                if (chInd1.Item1 == chInd2.Item1)
                {

                    chInd1 = Tuple.Create(chInd1.Item1, (chInd1.Item2 + 1) % 5);
                    cipherText += key_matrix[chInd1.Item1, chInd1.Item2];

                    chInd2 = Tuple.Create(chInd2.Item1, (chInd2.Item2 + 1) % 5);
                    cipherText += key_matrix[chInd2.Item1, chInd2.Item2];
                }
                else if (chInd1.Item2 == chInd2.Item2)
                {

                    chInd1 = Tuple.Create((chInd1.Item1 + 1) % 5, chInd1.Item2);
                    cipherText += key_matrix[chInd1.Item1, chInd1.Item2];

                    chInd2 = Tuple.Create((chInd2.Item1 + 1) % 5, chInd2.Item2);
                    cipherText += key_matrix[chInd2.Item1, chInd2.Item2];
                }
                else
                {
                    cipherText += key_matrix[chInd1.Item1, chInd2.Item2];
                    cipherText += key_matrix[chInd2.Item1, chInd1.Item2];
                }
            }
            return cipherText;
        }
    }
}
