using System;
using System.Collections.Generic;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace SecurityLibrary {
    class PermutationGenerator {
        int size;
        List<int> perm;

        List<int> fillBase() {
            for (int i = 1; i <= size; i++)
                perm.Add(i);
            return perm;
        }
        void swap(int pos1, int pos2) {
            int temp = perm[pos1];
            perm[pos1] = perm[pos2];
            perm[pos2] = temp;
        }
        public PermutationGenerator(int n) {
            size = n;
            perm = new List<int>();
        }
        public List<int> generate() {
            if (perm.Count == 0)
                return fillBase();
            int decreasePos = size - 2;
            while (decreasePos >= 0 && perm[decreasePos] > perm[decreasePos + 1]) {
                if (decreasePos == 0)
                    return new List<int>();
                decreasePos--;
            }
            int largerPos = size - 1;
            while(perm[largerPos] < perm[decreasePos]) {
                largerPos--;
            }
            swap(largerPos, decreasePos);
            int left = decreasePos + 1;
            int right = size - 1;
            while(left < right) {
                swap(left, right);
                left++;
                right--;
            }
            return perm;
        }

    }
}
