namespace WPFSerpent.Source.Models
{
    public class SerpentBitSliceMode : SerpentAlgorithm
    {
        public override int BlockSize { get; set; }
        public override int Rounds { get; set; }

        public override object MakeKey(byte[] key)
        {
            var w = new int[4 * (Rounds + 1)];
            var limit = key.Length / 4;
            int i, j, offset = 0;
            int t;
            for (i = 0; i < limit; i++)
                w[i] = (key[offset++] & 0xFF) |
                       ((key[offset++] & 0xFF) << 8) |
                       ((key[offset++] & 0xFF) << 16) |
                       ((key[offset++] & 0xFF) << 24);

            if (i < 8)
                w[i++] = 1;

            for (i = 8, j = 0; i < 16; i++)
            {
                t = (int) (w[j] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ j++);
                w[i] = (t << 11) | TripleRightShift(t, 21);
            }

            for (i = 0, j = 8; i < 8;)
                w[i++] = w[j++];
            limit = 4 * (Rounds + 1);

            for (; i < limit; i++)
            {
                t = (int) (w[i - 8] ^ w[i - 5] ^ w[i - 3] ^ w[i - 1] ^ PHI ^ i);
                w[i] = (t << 11) | TripleRightShift(t, 21);
            }

            for (i = 0; i < Rounds + 1; i++)
            {
                var x0 = w[4 * i];
                var x1 = w[4 * i + 1];
                var x2 = w[4 * i + 2];
                var x3 = w[4 * i + 3];
                int y1;
                int y2;
                int y3;
                var y0 = y1 = y2 = y3 = 0;
                var sb = Sbox[(Rounds + 3 - i) % Rounds];
                for (j = 0; j < 32; j++)
                {
                    int z = sb[(TripleRightShift(x0, j) & 0x01) |
                               ((TripleRightShift(x1, j) & 0x01) << 1) |
                               ((TripleRightShift(x2, j) & 0x01) << 2) |
                               ((TripleRightShift(x3, j) & 0x01) << 3)];
                    y0 |= (z & 0x01) << j;
                    y1 |= (TripleRightShift(z, 1) & 0x01) << j;
                    y2 |= (TripleRightShift(z, 2) & 0x01) << j;
                    y3 |= (TripleRightShift(z, 3) & 0x01) << j;
                }
                w[4 * i] = y0;
                w[4 * i + 1] = y1;
                w[4 * i + 2] = y2;
                w[4 * i + 3] = y3;
            }

            return w;
        }

        public override byte[] BlockEncrypt(byte[] InV, int inOffset, object sessionKey)
        {
            var K = (int[]) sessionKey;
            var x0 = (InV[inOffset++] & 0xFF) |
                     ((InV[inOffset++] & 0xFF) << 8) |
                     ((InV[inOffset++] & 0xFF) << 16) |
                     ((InV[inOffset++] & 0xFF) << 24);
            var x1 = (InV[inOffset++] & 0xFF) |
                     ((InV[inOffset++] & 0xFF) << 8) |
                     ((InV[inOffset++] & 0xFF) << 16) |
                     ((InV[inOffset++] & 0xFF) << 24);
            var x2 = (InV[inOffset++] & 0xFF) |
                     ((InV[inOffset++] & 0xFF) << 8) |
                     ((InV[inOffset++] & 0xFF) << 16) |
                     ((InV[inOffset++] & 0xFF) << 24);
            var x3 = (InV[inOffset++] & 0xFF) |
                     ((InV[inOffset++] & 0xFF) << 8) |
                     ((InV[inOffset++] & 0xFF) << 16) |
                     ((InV[inOffset] & 0xFF) << 24);

            x0 ^= K[0 * 4 + 0];
            x1 ^= K[0 * 4 + 1];
            x2 ^= K[0 * 4 + 2];
            x3 ^= K[0 * 4 + 3];

            // S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 

            // depth = 5,7,4,2, Total gates=18 

            var t01 = x1 ^ x2;
            var t02 = x0 | x3;
            var t03 = x0 ^ x1;
            var y3 = t02 ^ t01;
            var t05 = x2 | y3;
            var t06 = x0 ^ x3;
            var t07 = x1 | x2;
            var t08 = x3 & t05;
            var t09 = t03 & t07;
            var y2 = t09 ^ t08;
            var t11 = t09 & y2;
            var t12 = x2 ^ x3;
            var t13 = t07 ^ t11;
            var t14 = x1 & t06;
            var t15 = t06 ^ t13;
            var y0 = ~t15;
            var t17 = y0 ^ t14;
            var y1 = t12 ^ t17;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[1 * 4 + 0];
            x1 ^= K[1 * 4 + 1];
            x2 ^= K[1 * 4 + 2];
            x3 ^= K[1 * 4 + 3];

            // S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 

            // depth = 10,7,3,5, Total gates=18 

            t01 = x0 | x3;
            t02 = x2 ^ x3;
            t03 = ~x1;
            var t04 = x0 ^ x2;
            t05 = x0 | t03;
            t06 = x3 & t04;
            t07 = t01 & t02;
            t08 = x1 | t06;
            y2 = t02 ^ t05;
            var t10 = t07 ^ t08;
            t11 = t01 ^ t10;
            t12 = y2 ^ t11;
            t13 = x1 & x3;
            y3 = ~t10;
            y1 = t13 ^ t12;
            var t16 = t10 | y1;
            t17 = t05 & t16;
            y0 = x2 ^ t17;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[2 * 4 + 0];
            x1 ^= K[2 * 4 + 1];
            x2 ^= K[2 * 4 + 2];
            x3 ^= K[2 * 4 + 3];

            // S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 

            // depth = 3,8,11,7, Total gates=16 

            t01 = x0 | x2;
            t02 = x0 ^ x1;
            t03 = x3 ^ t01;
            y0 = t02 ^ t03;
            t05 = x2 ^ y0;
            t06 = x1 ^ t05;
            t07 = x1 | t05;
            t08 = t01 & t06;
            t09 = t03 ^ t07;
            t10 = t02 | t09;
            y1 = t10 ^ t08;
            t12 = x0 | x3;
            t13 = t09 ^ y1;
            t14 = x1 ^ t13;
            y3 = ~t09;
            y2 = t12 ^ t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[3 * 4 + 0];
            x1 ^= K[3 * 4 + 1];
            x2 ^= K[3 * 4 + 2];
            x3 ^= K[3 * 4 + 3];

            // S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 

            // depth = 8,3,5,5, Total gates=18 

            t01 = x0 ^ x2;
            t02 = x0 | x3;
            t03 = x0 & x3;
            t04 = t01 & t02;
            t05 = x1 | t03;
            t06 = x0 & x1;
            t07 = x3 ^ t04;
            t08 = x2 | t06;
            t09 = x1 ^ t07;
            t10 = x3 & t05;
            t11 = t02 ^ t10;
            y3 = t08 ^ t09;
            t13 = x3 | y3;
            t14 = x0 | t07;
            t15 = x1 & t13;
            y2 = t08 ^ t11;
            y0 = t14 ^ t15;
            y1 = t05 ^ t04;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[4 * 4 + 0];
            x1 ^= K[4 * 4 + 1];
            x2 ^= K[4 * 4 + 2];
            x3 ^= K[4 * 4 + 3];

            // S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 

            // depth = 6,7,5,3, Total gates=19 

            t01 = x0 | x1;
            t02 = x1 | x2;
            t03 = x0 ^ t02;
            t04 = x1 ^ x3;
            t05 = x3 | t03;
            t06 = x3 & t01;
            y3 = t03 ^ t06;
            t08 = y3 & t04;
            t09 = t04 & t05;
            t10 = x2 ^ t06;
            t11 = x1 & x2;
            t12 = t04 ^ t08;
            t13 = t11 | t03;
            t14 = t10 ^ t09;
            t15 = x0 & t05;
            t16 = t11 | t12;
            y2 = t13 ^ t08;
            y1 = t15 ^ t16;
            y0 = ~t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[5 * 4 + 0];
            x1 ^= K[5 * 4 + 1];
            x2 ^= K[5 * 4 + 2];
            x3 ^= K[5 * 4 + 3];

            // S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 

            // depth = 4,6,8,6, Total gates=17 

            t01 = x1 ^ x3;
            t02 = x1 | x3;
            t03 = x0 & t01;
            t04 = x2 ^ t02;
            t05 = t03 ^ t04;
            y0 = ~t05;
            t07 = x0 ^ t01;
            t08 = x3 | y0;
            t09 = x1 | t05;
            t10 = x3 ^ t08;
            t11 = x1 | t07;
            t12 = t03 | y0;
            t13 = t07 | t10;
            t14 = t01 ^ t11;
            y2 = t09 ^ t13;
            y1 = t07 ^ t08;
            y3 = t12 ^ t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[6 * 4 + 0];
            x1 ^= K[6 * 4 + 1];
            x2 ^= K[6 * 4 + 2];
            x3 ^= K[6 * 4 + 3];

            // S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 

            // depth = 8,3,6,3, Total gates=19 

            t01 = x0 & x3;
            t02 = x1 ^ x2;
            t03 = x0 ^ x3;
            t04 = t01 ^ t02;
            t05 = x1 | x2;
            y1 = ~t04;
            t07 = t03 & t05;
            t08 = x1 & y1;
            t09 = x0 | x2;
            t10 = t07 ^ t08;
            t11 = x1 | x3;
            t12 = x2 ^ t11;
            t13 = t09 ^ t10;
            y2 = ~t13;
            t15 = y1 & t03;
            y3 = t12 ^ t07;
            t17 = x0 ^ x1;
            var t18 = y2 ^ t15;
            y0 = t17 ^ t18;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[7 * 4 + 0];
            x1 ^= K[7 * 4 + 1];
            x2 ^= K[7 * 4 + 2];
            x3 ^= K[7 * 4 + 3];

            // S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 

            // depth = 10,7,10,4, Total gates=19 

            t01 = x0 & x2;
            t02 = ~x3;
            t03 = x0 & t02;
            t04 = x1 | t01;
            t05 = x0 & x1;
            t06 = x2 ^ t04;
            y3 = t03 ^ t06;
            t08 = x2 | y3;
            t09 = x3 | t05;
            t10 = x0 ^ t08;
            t11 = t04 & y3;
            y1 = t09 ^ t10;
            t13 = x1 ^ y1;
            t14 = t01 ^ y1;
            t15 = x2 ^ t05;
            t16 = t11 | t13;
            t17 = t02 | t14;
            y0 = t15 ^ t17;
            y2 = x0 ^ t16;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[8 * 4 + 0];
            x1 ^= K[8 * 4 + 1];
            x2 ^= K[8 * 4 + 2];
            x3 ^= K[8 * 4 + 3];

            // S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 

            // depth = 5,7,4,2, Total gates=18 

            t01 = x1 ^ x2;
            t02 = x0 | x3;
            t03 = x0 ^ x1;
            y3 = t02 ^ t01;
            t05 = x2 | y3;
            t06 = x0 ^ x3;
            t07 = x1 | x2;
            t08 = x3 & t05;
            t09 = t03 & t07;
            y2 = t09 ^ t08;
            t11 = t09 & y2;
            t12 = x2 ^ x3;
            t13 = t07 ^ t11;
            t14 = x1 & t06;
            t15 = t06 ^ t13;
            y0 = ~t15;
            t17 = y0 ^ t14;
            y1 = t12 ^ t17;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[9 * 4 + 0];
            x1 ^= K[9 * 4 + 1];
            x2 ^= K[9 * 4 + 2];
            x3 ^= K[9 * 4 + 3];

            // S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 

            // depth = 10,7,3,5, Total gates=18 

            t01 = x0 | x3;
            t02 = x2 ^ x3;
            t03 = ~x1;
            t04 = x0 ^ x2;
            t05 = x0 | t03;
            t06 = x3 & t04;
            t07 = t01 & t02;
            t08 = x1 | t06;
            y2 = t02 ^ t05;
            t10 = t07 ^ t08;
            t11 = t01 ^ t10;
            t12 = y2 ^ t11;
            t13 = x1 & x3;
            y3 = ~t10;
            y1 = t13 ^ t12;
            t16 = t10 | y1;
            t17 = t05 & t16;
            y0 = x2 ^ t17;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[10 * 4 + 0];
            x1 ^= K[10 * 4 + 1];
            x2 ^= K[10 * 4 + 2];
            x3 ^= K[10 * 4 + 3];

            // S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 

            // depth = 3,8,11,7, Total gates=16 

            t01 = x0 | x2;
            t02 = x0 ^ x1;
            t03 = x3 ^ t01;
            y0 = t02 ^ t03;
            t05 = x2 ^ y0;
            t06 = x1 ^ t05;
            t07 = x1 | t05;
            t08 = t01 & t06;
            t09 = t03 ^ t07;
            t10 = t02 | t09;
            y1 = t10 ^ t08;
            t12 = x0 | x3;
            t13 = t09 ^ y1;
            t14 = x1 ^ t13;
            y3 = ~t09;
            y2 = t12 ^ t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[11 * 4 + 0];
            x1 ^= K[11 * 4 + 1];
            x2 ^= K[11 * 4 + 2];
            x3 ^= K[11 * 4 + 3];

            // S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 

            // depth = 8,3,5,5, Total gates=18 

            t01 = x0 ^ x2;
            t02 = x0 | x3;
            t03 = x0 & x3;
            t04 = t01 & t02;
            t05 = x1 | t03;
            t06 = x0 & x1;
            t07 = x3 ^ t04;
            t08 = x2 | t06;
            t09 = x1 ^ t07;
            t10 = x3 & t05;
            t11 = t02 ^ t10;
            y3 = t08 ^ t09;
            t13 = x3 | y3;
            t14 = x0 | t07;
            t15 = x1 & t13;
            y2 = t08 ^ t11;
            y0 = t14 ^ t15;
            y1 = t05 ^ t04;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[12 * 4 + 0];
            x1 ^= K[12 * 4 + 1];
            x2 ^= K[12 * 4 + 2];
            x3 ^= K[12 * 4 + 3];

            // S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 

            // depth = 6,7,5,3, Total gates=19 

            t01 = x0 | x1;
            t02 = x1 | x2;
            t03 = x0 ^ t02;
            t04 = x1 ^ x3;
            t05 = x3 | t03;
            t06 = x3 & t01;
            y3 = t03 ^ t06;
            t08 = y3 & t04;
            t09 = t04 & t05;
            t10 = x2 ^ t06;
            t11 = x1 & x2;
            t12 = t04 ^ t08;
            t13 = t11 | t03;
            t14 = t10 ^ t09;
            t15 = x0 & t05;
            t16 = t11 | t12;
            y2 = t13 ^ t08;
            y1 = t15 ^ t16;
            y0 = ~t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[13 * 4 + 0];
            x1 ^= K[13 * 4 + 1];
            x2 ^= K[13 * 4 + 2];
            x3 ^= K[13 * 4 + 3];

            // S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 

            // depth = 4,6,8,6, Total gates=17 

            t01 = x1 ^ x3;
            t02 = x1 | x3;
            t03 = x0 & t01;
            t04 = x2 ^ t02;
            t05 = t03 ^ t04;
            y0 = ~t05;
            t07 = x0 ^ t01;
            t08 = x3 | y0;
            t09 = x1 | t05;
            t10 = x3 ^ t08;
            t11 = x1 | t07;
            t12 = t03 | y0;
            t13 = t07 | t10;
            t14 = t01 ^ t11;
            y2 = t09 ^ t13;
            y1 = t07 ^ t08;
            y3 = t12 ^ t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[14 * 4 + 0];
            x1 ^= K[14 * 4 + 1];
            x2 ^= K[14 * 4 + 2];
            x3 ^= K[14 * 4 + 3];

            // S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 

            // depth = 8,3,6,3, Total gates=19 

            t01 = x0 & x3;
            t02 = x1 ^ x2;
            t03 = x0 ^ x3;
            t04 = t01 ^ t02;
            t05 = x1 | x2;
            y1 = ~t04;
            t07 = t03 & t05;
            t08 = x1 & y1;
            t09 = x0 | x2;
            t10 = t07 ^ t08;
            t11 = x1 | x3;
            t12 = x2 ^ t11;
            t13 = t09 ^ t10;
            y2 = ~t13;
            t15 = y1 & t03;
            y3 = t12 ^ t07;
            t17 = x0 ^ x1;
            t18 = y2 ^ t15;
            y0 = t17 ^ t18;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[15 * 4 + 0];
            x1 ^= K[15 * 4 + 1];
            x2 ^= K[15 * 4 + 2];
            x3 ^= K[15 * 4 + 3];

            // S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 

            // depth = 10,7,10,4, Total gates=19 

            t01 = x0 & x2;
            t02 = ~x3;
            t03 = x0 & t02;
            t04 = x1 | t01;
            t05 = x0 & x1;
            t06 = x2 ^ t04;
            y3 = t03 ^ t06;
            t08 = x2 | y3;
            t09 = x3 | t05;
            t10 = x0 ^ t08;
            t11 = t04 & y3;
            y1 = t09 ^ t10;
            t13 = x1 ^ y1;
            t14 = t01 ^ y1;
            t15 = x2 ^ t05;
            t16 = t11 | t13;
            t17 = t02 | t14;
            y0 = t15 ^ t17;
            y2 = x0 ^ t16;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[16 * 4 + 0];
            x1 ^= K[16 * 4 + 1];
            x2 ^= K[16 * 4 + 2];
            x3 ^= K[16 * 4 + 3];

            // S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 

            // depth = 5,7,4,2, Total gates=18 

            t01 = x1 ^ x2;
            t02 = x0 | x3;
            t03 = x0 ^ x1;
            y3 = t02 ^ t01;
            t05 = x2 | y3;
            t06 = x0 ^ x3;
            t07 = x1 | x2;
            t08 = x3 & t05;
            t09 = t03 & t07;
            y2 = t09 ^ t08;
            t11 = t09 & y2;
            t12 = x2 ^ x3;
            t13 = t07 ^ t11;
            t14 = x1 & t06;
            t15 = t06 ^ t13;
            y0 = ~t15;
            t17 = y0 ^ t14;
            y1 = t12 ^ t17;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[17 * 4 + 0];
            x1 ^= K[17 * 4 + 1];
            x2 ^= K[17 * 4 + 2];
            x3 ^= K[17 * 4 + 3];

            // S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 

            // depth = 10,7,3,5, Total gates=18 

            t01 = x0 | x3;
            t02 = x2 ^ x3;
            t03 = ~x1;
            t04 = x0 ^ x2;
            t05 = x0 | t03;
            t06 = x3 & t04;
            t07 = t01 & t02;
            t08 = x1 | t06;
            y2 = t02 ^ t05;
            t10 = t07 ^ t08;
            t11 = t01 ^ t10;
            t12 = y2 ^ t11;
            t13 = x1 & x3;
            y3 = ~t10;
            y1 = t13 ^ t12;
            t16 = t10 | y1;
            t17 = t05 & t16;
            y0 = x2 ^ t17;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[18 * 4 + 0];
            x1 ^= K[18 * 4 + 1];
            x2 ^= K[18 * 4 + 2];
            x3 ^= K[18 * 4 + 3];

            // S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 

            // depth = 3,8,11,7, Total gates=16 

            t01 = x0 | x2;
            t02 = x0 ^ x1;
            t03 = x3 ^ t01;
            y0 = t02 ^ t03;
            t05 = x2 ^ y0;
            t06 = x1 ^ t05;
            t07 = x1 | t05;
            t08 = t01 & t06;
            t09 = t03 ^ t07;
            t10 = t02 | t09;
            y1 = t10 ^ t08;
            t12 = x0 | x3;
            t13 = t09 ^ y1;
            t14 = x1 ^ t13;
            y3 = ~t09;
            y2 = t12 ^ t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[19 * 4 + 0];
            x1 ^= K[19 * 4 + 1];
            x2 ^= K[19 * 4 + 2];
            x3 ^= K[19 * 4 + 3];

            // S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 

            // depth = 8,3,5,5, Total gates=18 

            t01 = x0 ^ x2;
            t02 = x0 | x3;
            t03 = x0 & x3;
            t04 = t01 & t02;
            t05 = x1 | t03;
            t06 = x0 & x1;
            t07 = x3 ^ t04;
            t08 = x2 | t06;
            t09 = x1 ^ t07;
            t10 = x3 & t05;
            t11 = t02 ^ t10;
            y3 = t08 ^ t09;
            t13 = x3 | y3;
            t14 = x0 | t07;
            t15 = x1 & t13;
            y2 = t08 ^ t11;
            y0 = t14 ^ t15;
            y1 = t05 ^ t04;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[20 * 4 + 0];
            x1 ^= K[20 * 4 + 1];
            x2 ^= K[20 * 4 + 2];
            x3 ^= K[20 * 4 + 3];

            // S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 

            // depth = 6,7,5,3, Total gates=19 

            t01 = x0 | x1;
            t02 = x1 | x2;
            t03 = x0 ^ t02;
            t04 = x1 ^ x3;
            t05 = x3 | t03;
            t06 = x3 & t01;
            y3 = t03 ^ t06;
            t08 = y3 & t04;
            t09 = t04 & t05;
            t10 = x2 ^ t06;
            t11 = x1 & x2;
            t12 = t04 ^ t08;
            t13 = t11 | t03;
            t14 = t10 ^ t09;
            t15 = x0 & t05;
            t16 = t11 | t12;
            y2 = t13 ^ t08;
            y1 = t15 ^ t16;
            y0 = ~t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[21 * 4 + 0];
            x1 ^= K[21 * 4 + 1];
            x2 ^= K[21 * 4 + 2];
            x3 ^= K[21 * 4 + 3];

            // S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 

            // depth = 4,6,8,6, Total gates=17 

            t01 = x1 ^ x3;
            t02 = x1 | x3;
            t03 = x0 & t01;
            t04 = x2 ^ t02;
            t05 = t03 ^ t04;
            y0 = ~t05;
            t07 = x0 ^ t01;
            t08 = x3 | y0;
            t09 = x1 | t05;
            t10 = x3 ^ t08;
            t11 = x1 | t07;
            t12 = t03 | y0;
            t13 = t07 | t10;
            t14 = t01 ^ t11;
            y2 = t09 ^ t13;
            y1 = t07 ^ t08;
            y3 = t12 ^ t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[22 * 4 + 0];
            x1 ^= K[22 * 4 + 1];
            x2 ^= K[22 * 4 + 2];
            x3 ^= K[22 * 4 + 3];

            // S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 

            // depth = 8,3,6,3, Total gates=19 

            t01 = x0 & x3;
            t02 = x1 ^ x2;
            t03 = x0 ^ x3;
            t04 = t01 ^ t02;
            t05 = x1 | x2;
            y1 = ~t04;
            t07 = t03 & t05;
            t08 = x1 & y1;
            t09 = x0 | x2;
            t10 = t07 ^ t08;
            t11 = x1 | x3;
            t12 = x2 ^ t11;
            t13 = t09 ^ t10;
            y2 = ~t13;
            t15 = y1 & t03;
            y3 = t12 ^ t07;
            t17 = x0 ^ x1;
            t18 = y2 ^ t15;
            y0 = t17 ^ t18;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[23 * 4 + 0];
            x1 ^= K[23 * 4 + 1];
            x2 ^= K[23 * 4 + 2];
            x3 ^= K[23 * 4 + 3];

            // S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 

            // depth = 10,7,10,4, Total gates=19 

            t01 = x0 & x2;
            t02 = ~x3;
            t03 = x0 & t02;
            t04 = x1 | t01;
            t05 = x0 & x1;
            t06 = x2 ^ t04;
            y3 = t03 ^ t06;
            t08 = x2 | y3;
            t09 = x3 | t05;
            t10 = x0 ^ t08;
            t11 = t04 & y3;
            y1 = t09 ^ t10;
            t13 = x1 ^ y1;
            t14 = t01 ^ y1;
            t15 = x2 ^ t05;
            t16 = t11 | t13;
            t17 = t02 | t14;
            y0 = t15 ^ t17;
            y2 = x0 ^ t16;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[24 * 4 + 0];
            x1 ^= K[24 * 4 + 1];
            x2 ^= K[24 * 4 + 2];
            x3 ^= K[24 * 4 + 3];

            // S0:   3  8 15  1 10  6  5 11 14 13  4  2  7  0  9 12 

            // depth = 5,7,4,2, Total gates=18 

            t01 = x1 ^ x2;
            t02 = x0 | x3;
            t03 = x0 ^ x1;
            y3 = t02 ^ t01;
            t05 = x2 | y3;
            t06 = x0 ^ x3;
            t07 = x1 | x2;
            t08 = x3 & t05;
            t09 = t03 & t07;
            y2 = t09 ^ t08;
            t11 = t09 & y2;
            t12 = x2 ^ x3;
            t13 = t07 ^ t11;
            t14 = x1 & t06;
            t15 = t06 ^ t13;
            y0 = ~t15;
            t17 = y0 ^ t14;
            y1 = t12 ^ t17;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[25 * 4 + 0];
            x1 ^= K[25 * 4 + 1];
            x2 ^= K[25 * 4 + 2];
            x3 ^= K[25 * 4 + 3];

            // S1:  15 12  2  7  9  0  5 10  1 11 14  8  6 13  3  4 

            // depth = 10,7,3,5, Total gates=18 

            t01 = x0 | x3;
            t02 = x2 ^ x3;
            t03 = ~x1;
            t04 = x0 ^ x2;
            t05 = x0 | t03;
            t06 = x3 & t04;
            t07 = t01 & t02;
            t08 = x1 | t06;
            y2 = t02 ^ t05;
            t10 = t07 ^ t08;
            t11 = t01 ^ t10;
            t12 = y2 ^ t11;
            t13 = x1 & x3;
            y3 = ~t10;
            y1 = t13 ^ t12;
            t16 = t10 | y1;
            t17 = t05 & t16;
            y0 = x2 ^ t17;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[26 * 4 + 0];
            x1 ^= K[26 * 4 + 1];
            x2 ^= K[26 * 4 + 2];
            x3 ^= K[26 * 4 + 3];

            // S2:   8  6  7  9  3 12 10 15 13  1 14  4  0 11  5  2 

            // depth = 3,8,11,7, Total gates=16 

            t01 = x0 | x2;
            t02 = x0 ^ x1;
            t03 = x3 ^ t01;
            y0 = t02 ^ t03;
            t05 = x2 ^ y0;
            t06 = x1 ^ t05;
            t07 = x1 | t05;
            t08 = t01 & t06;
            t09 = t03 ^ t07;
            t10 = t02 | t09;
            y1 = t10 ^ t08;
            t12 = x0 | x3;
            t13 = t09 ^ y1;
            t14 = x1 ^ t13;
            y3 = ~t09;
            y2 = t12 ^ t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[27 * 4 + 0];
            x1 ^= K[27 * 4 + 1];
            x2 ^= K[27 * 4 + 2];
            x3 ^= K[27 * 4 + 3];

            // S3:   0 15 11  8 12  9  6  3 13  1  2  4 10  7  5 14 

            // depth = 8,3,5,5, Total gates=18 

            t01 = x0 ^ x2;
            t02 = x0 | x3;
            t03 = x0 & x3;
            t04 = t01 & t02;
            t05 = x1 | t03;
            t06 = x0 & x1;
            t07 = x3 ^ t04;
            t08 = x2 | t06;
            t09 = x1 ^ t07;
            t10 = x3 & t05;
            t11 = t02 ^ t10;
            y3 = t08 ^ t09;
            t13 = x3 | y3;
            t14 = x0 | t07;
            t15 = x1 & t13;
            y2 = t08 ^ t11;
            y0 = t14 ^ t15;
            y1 = t05 ^ t04;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[28 * 4 + 0];
            x1 ^= K[28 * 4 + 1];
            x2 ^= K[28 * 4 + 2];
            x3 ^= K[28 * 4 + 3];

            // S4:   1 15  8  3 12  0 11  6  2  5  4 10  9 14  7 13 

            // depth = 6,7,5,3, Total gates=19 

            t01 = x0 | x1;
            t02 = x1 | x2;
            t03 = x0 ^ t02;
            t04 = x1 ^ x3;
            t05 = x3 | t03;
            t06 = x3 & t01;
            y3 = t03 ^ t06;
            t08 = y3 & t04;
            t09 = t04 & t05;
            t10 = x2 ^ t06;
            t11 = x1 & x2;
            t12 = t04 ^ t08;
            t13 = t11 | t03;
            t14 = t10 ^ t09;
            t15 = x0 & t05;
            t16 = t11 | t12;
            y2 = t13 ^ t08;
            y1 = t15 ^ t16;
            y0 = ~t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[29 * 4 + 0];
            x1 ^= K[29 * 4 + 1];
            x2 ^= K[29 * 4 + 2];
            x3 ^= K[29 * 4 + 3];

            // S5:  15  5  2 11  4 10  9 12  0  3 14  8 13  6  7  1 

            // depth = 4,6,8,6, Total gates=17 

            t01 = x1 ^ x3;
            t02 = x1 | x3;
            t03 = x0 & t01;
            t04 = x2 ^ t02;
            t05 = t03 ^ t04;
            y0 = ~t05;
            t07 = x0 ^ t01;
            t08 = x3 | y0;
            t09 = x1 | t05;
            t10 = x3 ^ t08;
            t11 = x1 | t07;
            t12 = t03 | y0;
            t13 = t07 | t10;
            t14 = t01 ^ t11;
            y2 = t09 ^ t13;
            y1 = t07 ^ t08;
            y3 = t12 ^ t14;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[30 * 4 + 0];
            x1 ^= K[30 * 4 + 1];
            x2 ^= K[30 * 4 + 2];
            x3 ^= K[30 * 4 + 3];

            // S6:   7  2 12  5  8  4  6 11 14  9  1 15 13  3 10  0 

            // depth = 8,3,6,3, Total gates=19 

            t01 = x0 & x3;
            t02 = x1 ^ x2;
            t03 = x0 ^ x3;
            t04 = t01 ^ t02;
            t05 = x1 | x2;
            y1 = ~t04;
            t07 = t03 & t05;
            t08 = x1 & y1;
            t09 = x0 | x2;
            t10 = t07 ^ t08;
            t11 = x1 | x3;
            t12 = x2 ^ t11;
            t13 = t09 ^ t10;
            y2 = ~t13;
            t15 = y1 & t03;
            y3 = t12 ^ t07;
            t17 = x0 ^ x1;
            t18 = y2 ^ t15;
            y0 = t17 ^ t18;

            x0 = (y0 << 13) | TripleRightShift(y0, 32 - 13);
            x2 = (y2 << 3) | TripleRightShift(y2, 32 - 3);
            x1 = y1 ^ x0 ^ x2;
            x3 = y3 ^ x2 ^ (x0 << 3);
            x1 = (x1 << 1) | TripleRightShift(x1, 32 - 1);
            x3 = (x3 << 7) | TripleRightShift(x3, 32 - 7);
            x0 = x0 ^ x1 ^ x3;
            x2 = x2 ^ x3 ^ (x1 << 7);
            x0 = (x0 << 5) | TripleRightShift(x0, 32 - 5);
            x2 = (x2 << 22) | TripleRightShift(x2, 32 - 22);

            x0 ^= K[31 * 4 + 0];
            x1 ^= K[31 * 4 + 1];
            x2 ^= K[31 * 4 + 2];
            x3 ^= K[31 * 4 + 3];

            // S7:   1 13 15  0 14  8  2 11  7  4 12 10  9  3  5  6 

            // depth = 10,7,10,4, Total gates=19 

            t01 = x0 & x2;
            t02 = ~x3;
            t03 = x0 & t02;
            t04 = x1 | t01;
            t05 = x0 & x1;
            t06 = x2 ^ t04;
            y3 = t03 ^ t06;
            t08 = x2 | y3;
            t09 = x3 | t05;
            t10 = x0 ^ t08;
            t11 = t04 & y3;
            y1 = t09 ^ t10;
            t13 = x1 ^ y1;
            t14 = t01 ^ y1;
            t15 = x2 ^ t05;
            t16 = t11 | t13;
            t17 = t02 | t14;
            y0 = t15 ^ t17;
            y2 = x0 ^ t16;

            x0 = y0;
            x1 = y1;
            x2 = y2;
            x3 = y3;

            x0 ^= K[32 * 4 + 0];
            x1 ^= K[32 * 4 + 1];
            x2 ^= K[32 * 4 + 2];
            x3 ^= K[32 * 4 + 3];

            var result = new[]
            {
                (byte) x0, (byte) TripleRightShift(x0, 8), (byte) TripleRightShift(x0, 16), (byte) TripleRightShift(x0, 24),
                (byte) x1, (byte) TripleRightShift(x1, 8), (byte) TripleRightShift(x1, 16), (byte) TripleRightShift(x1, 24),
                (byte) x2, (byte) TripleRightShift(x2, 8), (byte) TripleRightShift(x2, 16), (byte) TripleRightShift(x2, 24),
                (byte) x3, (byte) TripleRightShift(x3, 8), (byte) TripleRightShift(x3, 16), (byte) TripleRightShift(x3, 24)
            };

            return result;
        }
        
        public override byte[] BlockDecrypt(byte[] inV, int inOffset, object sessionKey)
        {
            var K = (int[]) sessionKey;
            var x0 = (inV[inOffset++] & 0xFF) |
                     ((inV[inOffset++] & 0xFF) << 8) |
                     ((inV[inOffset++] & 0xFF) << 16) |
                     ((inV[inOffset++] & 0xFF) << 24);
            var x1 = (inV[inOffset++] & 0xFF) |
                     ((inV[inOffset++] & 0xFF) << 8) |
                     ((inV[inOffset++] & 0xFF) << 16) |
                     ((inV[inOffset++] & 0xFF) << 24);
            var x2 = (inV[inOffset++] & 0xFF) |
                     ((inV[inOffset++] & 0xFF) << 8) |
                     ((inV[inOffset++] & 0xFF) << 16) |
                     ((inV[inOffset++] & 0xFF) << 24);
            var x3 = (inV[inOffset++] & 0xFF) |
                     ((inV[inOffset++] & 0xFF) << 8) |
                     ((inV[inOffset++] & 0xFF) << 16) |
                     ((inV[inOffset] & 0xFF) << 24);

            x0 ^= K[32 * 4 + 0];
            x1 ^= K[32 * 4 + 1];
            x2 ^= K[32 * 4 + 2];
            x3 ^= K[32 * 4 + 3];

            // InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 

            // depth = 9,7,3,3, Total gates=18 

            var t01 = x0 & x1;
            var t02 = x0 | x1;
            var t03 = x2 | t01;
            var t04 = x3 & t02;
            var y3 = t03 ^ t04;
            var t06 = x1 ^ t04;
            var t07 = x3 ^ y3;
            var t08 = ~t07;
            var t09 = t06 | t08;
            var t10 = x1 ^ x3;
            var t11 = x0 | x3;
            var y1 = x0 ^ t09;
            var t13 = x2 ^ t06;
            var t14 = x2 & t11;
            var t15 = x3 | y1;
            var t16 = t01 | t10;
            var y0 = t13 ^ t15;
            var y2 = t14 ^ t16;

            y0 ^= K[31 * 4 + 0];
            y1 ^= K[31 * 4 + 1];
            y2 ^= K[31 * 4 + 2];
            y3 ^= K[31 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 

            // depth = 5,3,8,6, Total gates=19 

            t01 = x0 ^ x2;
            t02 = ~x2;
            t03 = x1 & t01;
            t04 = x1 | t02;
            var t05 = x3 | t03;
            t06 = x1 ^ x3;
            t07 = x0 & t04;
            t08 = x0 | t02;
            t09 = t07 ^ t05;
            y1 = t06 ^ t08;
            y0 = ~t09;
            var t12 = x1 & y0;
            t13 = t01 & t05;
            t14 = t01 ^ t12;
            t15 = t07 ^ t13;
            t16 = x3 | t02;
            var t17 = x0 ^ y1;
            y3 = t17 ^ t15;
            y2 = t16 ^ t14;

            y0 ^= K[30 * 4 + 0];
            y1 ^= K[30 * 4 + 1];
            y2 ^= K[30 * 4 + 2];
            y3 ^= K[30 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 

            // depth = 4,6,9,7, Total gates=17 

            t01 = x0 & x3;
            t02 = x2 ^ t01;
            t03 = x0 ^ x3;
            t04 = x1 & t02;
            t05 = x0 & x2;
            y0 = t03 ^ t04;
            t07 = x0 & y0;
            t08 = t01 ^ y0;
            t09 = x1 | t05;
            t10 = ~x1;
            y1 = t08 ^ t09;
            t12 = t10 | t07;
            t13 = y0 | y1;
            y3 = t02 ^ t12;
            t15 = t02 ^ t13;
            t16 = x1 ^ x3;
            y2 = t16 ^ t15;

            y0 ^= K[29 * 4 + 0];
            y1 ^= K[29 * 4 + 1];
            y2 ^= K[29 * 4 + 2];
            y3 ^= K[29 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 

            // depth = 6,4,7,3, Total gates=17 

            t01 = x1 | x3;
            t02 = x2 | x3;
            t03 = x0 & t01;
            t04 = x1 ^ t02;
            t05 = x2 ^ x3;
            t06 = ~t03;
            t07 = x0 & t04;
            y1 = t05 ^ t07;
            t09 = y1 | t06;
            t10 = x0 ^ t07;
            t11 = t01 ^ t09;
            t12 = x3 ^ t04;
            t13 = x2 | t10;
            y3 = t03 ^ t12;
            t15 = x0 ^ t04;
            y2 = t11 ^ t13;
            y0 = t15 ^ t09;

            y0 ^= K[28 * 4 + 0];
            y1 ^= K[28 * 4 + 1];
            y2 ^= K[28 * 4 + 2];
            y3 ^= K[28 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 

            // depth = 3,6,4,4, Total gates=17 

            t01 = x2 | x3;
            t02 = x0 | x3;
            t03 = x2 ^ t02;
            t04 = x1 ^ t02;
            t05 = x0 ^ x3;
            t06 = t04 & t03;
            t07 = x1 & t01;
            y2 = t05 ^ t06;
            t09 = x0 ^ t03;
            y0 = t07 ^ t03;
            t11 = y0 | t05;
            t12 = t09 & t11;
            t13 = x0 & y2;
            t14 = t01 ^ t05;
            y1 = x1 ^ t12;
            t16 = x1 | t13;
            y3 = t14 ^ t16;

            y0 ^= K[27 * 4 + 0];
            y1 ^= K[27 * 4 + 1];
            y2 ^= K[27 * 4 + 2];
            y3 ^= K[27 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 

            // depth = 3,6,8,3, Total gates=18 

            t01 = x0 ^ x3;
            t02 = x2 ^ x3;
            t03 = x0 & x2;
            t04 = x1 | t02;
            y0 = t01 ^ t04;
            t06 = x0 | x2;
            t07 = x3 | y0;
            t08 = ~x3;
            t09 = x1 & t06;
            t10 = t08 | t03;
            t11 = x1 & t07;
            t12 = t06 & t02;
            y3 = t09 ^ t10;
            y1 = t12 ^ t11;
            t15 = x2 & y3;
            t16 = y0 ^ y1;
            t17 = t10 ^ t15;
            y2 = t16 ^ t17;

            y0 ^= K[26 * 4 + 0];
            y1 ^= K[26 * 4 + 1];
            y2 ^= K[26 * 4 + 2];
            y3 ^= K[26 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 

            // depth = 7,4,5,3, Total gates=18 

            t01 = x0 ^ x1;
            t02 = x1 | x3;
            t03 = x0 & x2;
            t04 = x2 ^ t02;
            t05 = x0 | t04;
            t06 = t01 & t05;
            t07 = x3 | t03;
            t08 = x1 ^ t06;
            t09 = t07 ^ t06;
            t10 = t04 | t03;
            t11 = x3 & t08;
            y2 = ~t09;
            y1 = t10 ^ t11;
            t14 = x0 | y2;
            t15 = t06 ^ y1;
            y3 = t01 ^ t04;
            t17 = x2 ^ t15;
            y0 = t14 ^ t17;

            y0 ^= K[25 * 4 + 0];
            y1 ^= K[25 * 4 + 1];
            y2 ^= K[25 * 4 + 2];
            y3 ^= K[25 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 

            // depth = 8,4,3,6, Total gates=19 

            t01 = x2 ^ x3;
            t02 = x0 | x1;
            t03 = x1 | x2;
            t04 = x2 & t01;
            t05 = t02 ^ t01;
            t06 = x0 | t04;
            y2 = ~t05;
            t08 = x1 ^ x3;
            t09 = t03 & t08;
            t10 = x3 | y2;
            y1 = t09 ^ t06;
            t12 = x0 | t05;
            t13 = y1 ^ t12;
            t14 = t03 ^ t10;
            t15 = x0 ^ x2;
            y3 = t14 ^ t13;
            t17 = t05 & t13;
            var t18 = t14 | t17;
            y0 = t15 ^ t18;

            y0 ^= K[24 * 4 + 0];
            y1 ^= K[24 * 4 + 1];
            y2 ^= K[24 * 4 + 2];
            y3 ^= K[24 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 

            // depth = 9,7,3,3, Total gates=18 

            t01 = x0 & x1;
            t02 = x0 | x1;
            t03 = x2 | t01;
            t04 = x3 & t02;
            y3 = t03 ^ t04;
            t06 = x1 ^ t04;
            t07 = x3 ^ y3;
            t08 = ~t07;
            t09 = t06 | t08;
            t10 = x1 ^ x3;
            t11 = x0 | x3;
            y1 = x0 ^ t09;
            t13 = x2 ^ t06;
            t14 = x2 & t11;
            t15 = x3 | y1;
            t16 = t01 | t10;
            y0 = t13 ^ t15;
            y2 = t14 ^ t16;

            y0 ^= K[23 * 4 + 0];
            y1 ^= K[23 * 4 + 1];
            y2 ^= K[23 * 4 + 2];
            y3 ^= K[23 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 

            // depth = 5,3,8,6, Total gates=19 

            t01 = x0 ^ x2;
            t02 = ~x2;
            t03 = x1 & t01;
            t04 = x1 | t02;
            t05 = x3 | t03;
            t06 = x1 ^ x3;
            t07 = x0 & t04;
            t08 = x0 | t02;
            t09 = t07 ^ t05;
            y1 = t06 ^ t08;
            y0 = ~t09;
            t12 = x1 & y0;
            t13 = t01 & t05;
            t14 = t01 ^ t12;
            t15 = t07 ^ t13;
            t16 = x3 | t02;
            t17 = x0 ^ y1;
            y3 = t17 ^ t15;
            y2 = t16 ^ t14;

            y0 ^= K[22 * 4 + 0];
            y1 ^= K[22 * 4 + 1];
            y2 ^= K[22 * 4 + 2];
            y3 ^= K[22 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 

            // depth = 4,6,9,7, Total gates=17 

            t01 = x0 & x3;
            t02 = x2 ^ t01;
            t03 = x0 ^ x3;
            t04 = x1 & t02;
            t05 = x0 & x2;
            y0 = t03 ^ t04;
            t07 = x0 & y0;
            t08 = t01 ^ y0;
            t09 = x1 | t05;
            t10 = ~x1;
            y1 = t08 ^ t09;
            t12 = t10 | t07;
            t13 = y0 | y1;
            y3 = t02 ^ t12;
            t15 = t02 ^ t13;
            t16 = x1 ^ x3;
            y2 = t16 ^ t15;

            y0 ^= K[21 * 4 + 0];
            y1 ^= K[21 * 4 + 1];
            y2 ^= K[21 * 4 + 2];
            y3 ^= K[21 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 

            // depth = 6,4,7,3, Total gates=17 

            t01 = x1 | x3;
            t02 = x2 | x3;
            t03 = x0 & t01;
            t04 = x1 ^ t02;
            t05 = x2 ^ x3;
            t06 = ~t03;
            t07 = x0 & t04;
            y1 = t05 ^ t07;
            t09 = y1 | t06;
            t10 = x0 ^ t07;
            t11 = t01 ^ t09;
            t12 = x3 ^ t04;
            t13 = x2 | t10;
            y3 = t03 ^ t12;
            t15 = x0 ^ t04;
            y2 = t11 ^ t13;
            y0 = t15 ^ t09;

            y0 ^= K[20 * 4 + 0];
            y1 ^= K[20 * 4 + 1];
            y2 ^= K[20 * 4 + 2];
            y3 ^= K[20 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 

            // depth = 3,6,4,4, Total gates=17 

            t01 = x2 | x3;
            t02 = x0 | x3;
            t03 = x2 ^ t02;
            t04 = x1 ^ t02;
            t05 = x0 ^ x3;
            t06 = t04 & t03;
            t07 = x1 & t01;
            y2 = t05 ^ t06;
            t09 = x0 ^ t03;
            y0 = t07 ^ t03;
            t11 = y0 | t05;
            t12 = t09 & t11;
            t13 = x0 & y2;
            t14 = t01 ^ t05;
            y1 = x1 ^ t12;
            t16 = x1 | t13;
            y3 = t14 ^ t16;

            y0 ^= K[19 * 4 + 0];
            y1 ^= K[19 * 4 + 1];
            y2 ^= K[19 * 4 + 2];
            y3 ^= K[19 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 

            // depth = 3,6,8,3, Total gates=18 

            t01 = x0 ^ x3;
            t02 = x2 ^ x3;
            t03 = x0 & x2;
            t04 = x1 | t02;
            y0 = t01 ^ t04;
            t06 = x0 | x2;
            t07 = x3 | y0;
            t08 = ~x3;
            t09 = x1 & t06;
            t10 = t08 | t03;
            t11 = x1 & t07;
            t12 = t06 & t02;
            y3 = t09 ^ t10;
            y1 = t12 ^ t11;
            t15 = x2 & y3;
            t16 = y0 ^ y1;
            t17 = t10 ^ t15;
            y2 = t16 ^ t17;

            y0 ^= K[18 * 4 + 0];
            y1 ^= K[18 * 4 + 1];
            y2 ^= K[18 * 4 + 2];
            y3 ^= K[18 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 

            // depth = 7,4,5,3, Total gates=18 

            t01 = x0 ^ x1;
            t02 = x1 | x3;
            t03 = x0 & x2;
            t04 = x2 ^ t02;
            t05 = x0 | t04;
            t06 = t01 & t05;
            t07 = x3 | t03;
            t08 = x1 ^ t06;
            t09 = t07 ^ t06;
            t10 = t04 | t03;
            t11 = x3 & t08;
            y2 = ~t09;
            y1 = t10 ^ t11;
            t14 = x0 | y2;
            t15 = t06 ^ y1;
            y3 = t01 ^ t04;
            t17 = x2 ^ t15;
            y0 = t14 ^ t17;

            y0 ^= K[17 * 4 + 0];
            y1 ^= K[17 * 4 + 1];
            y2 ^= K[17 * 4 + 2];
            y3 ^= K[17 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 

            // depth = 8,4,3,6, Total gates=19 

            t01 = x2 ^ x3;
            t02 = x0 | x1;
            t03 = x1 | x2;
            t04 = x2 & t01;
            t05 = t02 ^ t01;
            t06 = x0 | t04;
            y2 = ~t05;
            t08 = x1 ^ x3;
            t09 = t03 & t08;
            t10 = x3 | y2;
            y1 = t09 ^ t06;
            t12 = x0 | t05;
            t13 = y1 ^ t12;
            t14 = t03 ^ t10;
            t15 = x0 ^ x2;
            y3 = t14 ^ t13;
            t17 = t05 & t13;
            t18 = t14 | t17;
            y0 = t15 ^ t18;

            y0 ^= K[16 * 4 + 0];
            y1 ^= K[16 * 4 + 1];
            y2 ^= K[16 * 4 + 2];
            y3 ^= K[16 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 

            // depth = 9,7,3,3, Total gates=18 

            t01 = x0 & x1;
            t02 = x0 | x1;
            t03 = x2 | t01;
            t04 = x3 & t02;
            y3 = t03 ^ t04;
            t06 = x1 ^ t04;
            t07 = x3 ^ y3;
            t08 = ~t07;
            t09 = t06 | t08;
            t10 = x1 ^ x3;
            t11 = x0 | x3;
            y1 = x0 ^ t09;
            t13 = x2 ^ t06;
            t14 = x2 & t11;
            t15 = x3 | y1;
            t16 = t01 | t10;
            y0 = t13 ^ t15;
            y2 = t14 ^ t16;

            y0 ^= K[15 * 4 + 0];
            y1 ^= K[15 * 4 + 1];
            y2 ^= K[15 * 4 + 2];
            y3 ^= K[15 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 

            // depth = 5,3,8,6, Total gates=19 

            t01 = x0 ^ x2;
            t02 = ~x2;
            t03 = x1 & t01;
            t04 = x1 | t02;
            t05 = x3 | t03;
            t06 = x1 ^ x3;
            t07 = x0 & t04;
            t08 = x0 | t02;
            t09 = t07 ^ t05;
            y1 = t06 ^ t08;
            y0 = ~t09;
            t12 = x1 & y0;
            t13 = t01 & t05;
            t14 = t01 ^ t12;
            t15 = t07 ^ t13;
            t16 = x3 | t02;
            t17 = x0 ^ y1;
            y3 = t17 ^ t15;
            y2 = t16 ^ t14;

            y0 ^= K[14 * 4 + 0];
            y1 ^= K[14 * 4 + 1];
            y2 ^= K[14 * 4 + 2];
            y3 ^= K[14 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 

            // depth = 4,6,9,7, Total gates=17 

            t01 = x0 & x3;
            t02 = x2 ^ t01;
            t03 = x0 ^ x3;
            t04 = x1 & t02;
            t05 = x0 & x2;
            y0 = t03 ^ t04;
            t07 = x0 & y0;
            t08 = t01 ^ y0;
            t09 = x1 | t05;
            t10 = ~x1;
            y1 = t08 ^ t09;
            t12 = t10 | t07;
            t13 = y0 | y1;
            y3 = t02 ^ t12;
            t15 = t02 ^ t13;
            t16 = x1 ^ x3;
            y2 = t16 ^ t15;

            y0 ^= K[13 * 4 + 0];
            y1 ^= K[13 * 4 + 1];
            y2 ^= K[13 * 4 + 2];
            y3 ^= K[13 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 

            // depth = 6,4,7,3, Total gates=17 

            t01 = x1 | x3;
            t02 = x2 | x3;
            t03 = x0 & t01;
            t04 = x1 ^ t02;
            t05 = x2 ^ x3;
            t06 = ~t03;
            t07 = x0 & t04;
            y1 = t05 ^ t07;
            t09 = y1 | t06;
            t10 = x0 ^ t07;
            t11 = t01 ^ t09;
            t12 = x3 ^ t04;
            t13 = x2 | t10;
            y3 = t03 ^ t12;
            t15 = x0 ^ t04;
            y2 = t11 ^ t13;
            y0 = t15 ^ t09;

            y0 ^= K[12 * 4 + 0];
            y1 ^= K[12 * 4 + 1];
            y2 ^= K[12 * 4 + 2];
            y3 ^= K[12 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 

            // depth = 3,6,4,4, Total gates=17 

            t01 = x2 | x3;
            t02 = x0 | x3;
            t03 = x2 ^ t02;
            t04 = x1 ^ t02;
            t05 = x0 ^ x3;
            t06 = t04 & t03;
            t07 = x1 & t01;
            y2 = t05 ^ t06;
            t09 = x0 ^ t03;
            y0 = t07 ^ t03;
            t11 = y0 | t05;
            t12 = t09 & t11;
            t13 = x0 & y2;
            t14 = t01 ^ t05;
            y1 = x1 ^ t12;
            t16 = x1 | t13;
            y3 = t14 ^ t16;

            y0 ^= K[11 * 4 + 0];
            y1 ^= K[11 * 4 + 1];
            y2 ^= K[11 * 4 + 2];
            y3 ^= K[11 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 

            // depth = 3,6,8,3, Total gates=18 

            t01 = x0 ^ x3;
            t02 = x2 ^ x3;
            t03 = x0 & x2;
            t04 = x1 | t02;
            y0 = t01 ^ t04;
            t06 = x0 | x2;
            t07 = x3 | y0;
            t08 = ~x3;
            t09 = x1 & t06;
            t10 = t08 | t03;
            t11 = x1 & t07;
            t12 = t06 & t02;
            y3 = t09 ^ t10;
            y1 = t12 ^ t11;
            t15 = x2 & y3;
            t16 = y0 ^ y1;
            t17 = t10 ^ t15;
            y2 = t16 ^ t17;

            y0 ^= K[10 * 4 + 0];
            y1 ^= K[10 * 4 + 1];
            y2 ^= K[10 * 4 + 2];
            y3 ^= K[10 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 

            // depth = 7,4,5,3, Total gates=18 

            t01 = x0 ^ x1;
            t02 = x1 | x3;
            t03 = x0 & x2;
            t04 = x2 ^ t02;
            t05 = x0 | t04;
            t06 = t01 & t05;
            t07 = x3 | t03;
            t08 = x1 ^ t06;
            t09 = t07 ^ t06;
            t10 = t04 | t03;
            t11 = x3 & t08;
            y2 = ~t09;
            y1 = t10 ^ t11;
            t14 = x0 | y2;
            t15 = t06 ^ y1;
            y3 = t01 ^ t04;
            t17 = x2 ^ t15;
            y0 = t14 ^ t17;

            y0 ^= K[9 * 4 + 0];
            y1 ^= K[9 * 4 + 1];
            y2 ^= K[9 * 4 + 2];
            y3 ^= K[9 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 

            // depth = 8,4,3,6, Total gates=19 

            t01 = x2 ^ x3;
            t02 = x0 | x1;
            t03 = x1 | x2;
            t04 = x2 & t01;
            t05 = t02 ^ t01;
            t06 = x0 | t04;
            y2 = ~t05;
            t08 = x1 ^ x3;
            t09 = t03 & t08;
            t10 = x3 | y2;
            y1 = t09 ^ t06;
            t12 = x0 | t05;
            t13 = y1 ^ t12;
            t14 = t03 ^ t10;
            t15 = x0 ^ x2;
            y3 = t14 ^ t13;
            t17 = t05 & t13;
            t18 = t14 | t17;
            y0 = t15 ^ t18;

            y0 ^= K[8 * 4 + 0];
            y1 ^= K[8 * 4 + 1];
            y2 ^= K[8 * 4 + 2];
            y3 ^= K[8 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS7:   3  0  6 13  9 14 15  8  5 12 11  7 10  1  4  2 

            // depth = 9,7,3,3, Total gates=18 

            t01 = x0 & x1;
            t02 = x0 | x1;
            t03 = x2 | t01;
            t04 = x3 & t02;
            y3 = t03 ^ t04;
            t06 = x1 ^ t04;
            t07 = x3 ^ y3;
            t08 = ~t07;
            t09 = t06 | t08;
            t10 = x1 ^ x3;
            t11 = x0 | x3;
            y1 = x0 ^ t09;
            t13 = x2 ^ t06;
            t14 = x2 & t11;
            t15 = x3 | y1;
            t16 = t01 | t10;
            y0 = t13 ^ t15;
            y2 = t14 ^ t16;

            y0 ^= K[7 * 4 + 0];
            y1 ^= K[7 * 4 + 1];
            y2 ^= K[7 * 4 + 2];
            y3 ^= K[7 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS6:  15 10  1 13  5  3  6  0  4  9 14  7  2 12  8 11 

            // depth = 5,3,8,6, Total gates=19 

            t01 = x0 ^ x2;
            t02 = ~x2;
            t03 = x1 & t01;
            t04 = x1 | t02;
            t05 = x3 | t03;
            t06 = x1 ^ x3;
            t07 = x0 & t04;
            t08 = x0 | t02;
            t09 = t07 ^ t05;
            y1 = t06 ^ t08;
            y0 = ~t09;
            t12 = x1 & y0;
            t13 = t01 & t05;
            t14 = t01 ^ t12;
            t15 = t07 ^ t13;
            t16 = x3 | t02;
            t17 = x0 ^ y1;
            y3 = t17 ^ t15;
            y2 = t16 ^ t14;

            y0 ^= K[6 * 4 + 0];
            y1 ^= K[6 * 4 + 1];
            y2 ^= K[6 * 4 + 2];
            y3 ^= K[6 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS5:   8 15  2  9  4  1 13 14 11  6  5  3  7 12 10  0 

            // depth = 4,6,9,7, Total gates=17 

            t01 = x0 & x3;
            t02 = x2 ^ t01;
            t03 = x0 ^ x3;
            t04 = x1 & t02;
            t05 = x0 & x2;
            y0 = t03 ^ t04;
            t07 = x0 & y0;
            t08 = t01 ^ y0;
            t09 = x1 | t05;
            t10 = ~x1;
            y1 = t08 ^ t09;
            t12 = t10 | t07;
            t13 = y0 | y1;
            y3 = t02 ^ t12;
            t15 = t02 ^ t13;
            t16 = x1 ^ x3;
            y2 = t16 ^ t15;

            y0 ^= K[5 * 4 + 0];
            y1 ^= K[5 * 4 + 1];
            y2 ^= K[5 * 4 + 2];
            y3 ^= K[5 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS4:   5  0  8  3 10  9  7 14  2 12 11  6  4 15 13  1 

            // depth = 6,4,7,3, Total gates=17 

            t01 = x1 | x3;
            t02 = x2 | x3;
            t03 = x0 & t01;
            t04 = x1 ^ t02;
            t05 = x2 ^ x3;
            t06 = ~t03;
            t07 = x0 & t04;
            y1 = t05 ^ t07;
            t09 = y1 | t06;
            t10 = x0 ^ t07;
            t11 = t01 ^ t09;
            t12 = x3 ^ t04;
            t13 = x2 | t10;
            y3 = t03 ^ t12;
            t15 = x0 ^ t04;
            y2 = t11 ^ t13;
            y0 = t15 ^ t09;

            y0 ^= K[4 * 4 + 0];
            y1 ^= K[4 * 4 + 1];
            y2 ^= K[4 * 4 + 2];
            y3 ^= K[4 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS3:   0  9 10  7 11 14  6 13  3  5 12  2  4  8 15  1 

            // depth = 3,6,4,4, Total gates=17 

            t01 = x2 | x3;
            t02 = x0 | x3;
            t03 = x2 ^ t02;
            t04 = x1 ^ t02;
            t05 = x0 ^ x3;
            t06 = t04 & t03;
            t07 = x1 & t01;
            y2 = t05 ^ t06;
            t09 = x0 ^ t03;
            y0 = t07 ^ t03;
            t11 = y0 | t05;
            t12 = t09 & t11;
            t13 = x0 & y2;
            t14 = t01 ^ t05;
            y1 = x1 ^ t12;
            t16 = x1 | t13;
            y3 = t14 ^ t16;

            y0 ^= K[3 * 4 + 0];
            y1 ^= K[3 * 4 + 1];
            y2 ^= K[3 * 4 + 2];
            y3 ^= K[3 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS2:  12  9 15  4 11 14  1  2  0  3  6 13  5  8 10  7 

            // depth = 3,6,8,3, Total gates=18 

            t01 = x0 ^ x3;
            t02 = x2 ^ x3;
            t03 = x0 & x2;
            t04 = x1 | t02;
            y0 = t01 ^ t04;
            t06 = x0 | x2;
            t07 = x3 | y0;
            t08 = ~x3;
            t09 = x1 & t06;
            t10 = t08 | t03;
            t11 = x1 & t07;
            t12 = t06 & t02;
            y3 = t09 ^ t10;
            y1 = t12 ^ t11;
            t15 = x2 & y3;
            t16 = y0 ^ y1;
            t17 = t10 ^ t15;
            y2 = t16 ^ t17;

            y0 ^= K[2 * 4 + 0];
            y1 ^= K[2 * 4 + 1];
            y2 ^= K[2 * 4 + 2];
            y3 ^= K[2 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS1:   5  8  2 14 15  6 12  3 11  4  7  9  1 13 10  0 

            // depth = 7,4,5,3, Total gates=18 

            t01 = x0 ^ x1;
            t02 = x1 | x3;
            t03 = x0 & x2;
            t04 = x2 ^ t02;
            t05 = x0 | t04;
            t06 = t01 & t05;
            t07 = x3 | t03;
            t08 = x1 ^ t06;
            t09 = t07 ^ t06;
            t10 = t04 | t03;
            t11 = x3 & t08;
            y2 = ~t09;
            y1 = t10 ^ t11;
            t14 = x0 | y2;
            t15 = t06 ^ y1;
            y3 = t01 ^ t04;
            t17 = x2 ^ t15;
            y0 = t14 ^ t17;

            y0 ^= K[1 * 4 + 0];
            y1 ^= K[1 * 4 + 1];
            y2 ^= K[1 * 4 + 2];
            y3 ^= K[1 * 4 + 3];

            x2 = (y2 << (32 - 22)) | TripleRightShift(y2, 22);
            x0 = (y0 << (32 - 5)) | TripleRightShift(y0, 5);
            x2 = x2 ^ y3 ^ (y1 << 7);
            x0 = x0 ^ y1 ^ y3;
            x3 = (y3 << (32 - 7)) | TripleRightShift(y3, 7);
            x1 = (y1 << (32 - 1)) | TripleRightShift(y1, 1);
            x3 = x3 ^ x2 ^ (x0 << 3);
            x1 = x1 ^ x0 ^ x2;
            x2 = (x2 << (32 - 3)) | TripleRightShift(x2, 3);
            x0 = (x0 << (32 - 13)) | TripleRightShift(x0, 13);

            // InvS0:  13  3 11  0 10  6  5 12  1 14  4  7 15  9  8  2 

            // depth = 8,4,3,6, Total gates=19 

            t01 = x2 ^ x3;
            t02 = x0 | x1;
            t03 = x1 | x2;
            t04 = x2 & t01;
            t05 = t02 ^ t01;
            t06 = x0 | t04;
            y2 = ~t05;
            t08 = x1 ^ x3;
            t09 = t03 & t08;
            t10 = x3 | y2;
            y1 = t09 ^ t06;
            t12 = x0 | t05;
            t13 = y1 ^ t12;
            t14 = t03 ^ t10;
            t15 = x0 ^ x2;
            y3 = t14 ^ t13;
            t17 = t05 & t13;
            t18 = t14 | t17;
            y0 = t15 ^ t18;

            x0 = y0;
            x1 = y1;
            x2 = y2;
            x3 = y3;

            x0 ^= K[0 * 4 + 0];
            x1 ^= K[0 * 4 + 1];
            x2 ^= K[0 * 4 + 2];
            x3 ^= K[0 * 4 + 3];

            var result = new[]
            {
                (byte) x0, (byte) TripleRightShift(x0, 8), (byte) TripleRightShift(x0, 16), (byte) TripleRightShift(x0, 24),
                (byte) x1, (byte) TripleRightShift(x1, 8), (byte) TripleRightShift(x1, 16), (byte) TripleRightShift(x1, 24),
                (byte) x2, (byte) TripleRightShift(x2, 8), (byte) TripleRightShift(x2, 16), (byte) TripleRightShift(x2, 24),
                (byte) x3, (byte) TripleRightShift(x3, 8), (byte) TripleRightShift(x3, 16), (byte) TripleRightShift(x3, 24)
            };

            return result;
        }
        
        private static int TripleRightShift(int n, int s)
        {
            if (n >= 0)
                return n >> s;
            return (n >> s) + (2 << ~s);
        }

        public string IntToString(int n)
        {
            var buf = new char[8];
            for (var i = 7; i >= 0; i--)
            {
                buf[i] = HEX_DIGITS[n & 0x0F];
                n >>= 4;
            }
            return new string(buf);
        }
    }
}
