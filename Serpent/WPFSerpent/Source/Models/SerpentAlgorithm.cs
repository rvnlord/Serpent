namespace WPFSerpent.Source.Models
{
    public abstract class SerpentAlgorithm
    {
        public static readonly uint PHI = 0x9E3779B9; // (sqrt(5) - 1) * 2**31
        public abstract int BlockSize { get; set; }
        public abstract int Rounds { get; set; }

        #region S-Boxes and Transformation
        
        protected static byte[][] Sbox = {
	        new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	        new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	        new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	        new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	        new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	        new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	        new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	        new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
	        new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	        new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	        new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	        new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	        new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	        new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	        new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	        new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
	        new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	        new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	        new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	        new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	        new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	        new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	        new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	        new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 },/* S7: */
	        new byte[] { 3, 8,15, 1,10, 6, 5,11,14,13, 4, 2, 7, 0, 9,12 },/* S0: */
	        new byte[] {15,12, 2, 7, 9, 0, 5,10, 1,11,14, 8, 6,13, 3, 4 },/* S1: */
	        new byte[] { 8, 6, 7, 9, 3,12,10,15,13, 1,14, 4, 0,11, 5, 2 },/* S2: */
	        new byte[] { 0,15,11, 8,12, 9, 6, 3,13, 1, 2, 4,10, 7, 5,14 },/* S3: */
	        new byte[] { 1,15, 8, 3,12, 0,11, 6, 2, 5, 4,10, 9,14, 7,13 },/* S4: */
	        new byte[] {15, 5, 2,11, 4,10, 9,12, 0, 3,14, 8,13, 6, 7, 1 },/* S5: */
	        new byte[] { 7, 2,12, 5, 8, 4, 6,11,14, 9, 1,15,13, 3,10, 0 },/* S6: */
	        new byte[] { 1,13,15, 0,14, 8, 2,11, 7, 4,12,10, 9, 3, 5, 6 } /* S7: */
        };

        protected static byte[][] SboxInverse = {
	        new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	        new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	        new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	        new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	        new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	        new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	        new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	        new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
	        new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	        new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	        new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	        new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	        new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	        new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	        new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	        new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
	        new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	        new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	        new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	        new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	        new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	        new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	        new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	        new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 },/* InvS7: */
	        new byte[] {13, 3,11, 0,10, 6, 5,12, 1,14, 4, 7,15, 9, 8, 2 },/* InvS0: */
	        new byte[] { 5, 8, 2,14,15, 6,12, 3,11, 4, 7, 9, 1,13,10, 0 },/* InvS1: */
	        new byte[] {12, 9,15, 4,11,14, 1, 2, 0, 3, 6,13, 5, 8,10, 7 },/* InvS2: */
	        new byte[] { 0, 9,10, 7,11,14, 6,13, 3, 5,12, 2, 4, 8,15, 1 },/* InvS3: */
	        new byte[] { 5, 0, 8, 3,10, 9, 7,14, 2,12,11, 6, 4,15,13, 1 },/* InvS4: */
	        new byte[] { 8,15, 2, 9, 4, 1,13,14,11, 6, 5, 3, 7,12,10, 0 },/* InvS5: */
	        new byte[] {15,10, 1,13, 5, 3, 6, 0, 4, 9,14, 7, 2,12, 8,11 },/* InvS6: */
	        new byte[] { 3, 0, 6,13, 9,14,15, 8, 5,12,11, 7,10, 1, 4, 2 } /* InvS7: */
        };

        protected static byte[] IPtable = {
            0,  32, 64,  96,  1, 33, 65,  97,  2, 34, 66,  98,  3, 35, 67,  99,
            4,  36, 68, 100,  5, 37, 69, 101,  6, 38, 70, 102,  7, 39, 71, 103,
            8,  40, 72, 104,  9, 41, 73, 105, 10, 42, 74, 106, 11, 43, 75, 107,
            12, 44, 76, 108, 13, 45, 77, 109, 14, 46, 78, 110, 15, 47, 79, 111,
            16, 48, 80, 112, 17, 49, 81, 113, 18, 50, 82, 114, 19, 51, 83, 115,
            20, 52, 84, 116, 21, 53, 85, 117, 22, 54, 86, 118, 23, 55, 87, 119,
            24, 56, 88, 120, 25, 57, 89, 121, 26, 58, 90, 122, 27, 59, 91, 123,
            28, 60, 92, 124, 29, 61, 93, 125, 30, 62, 94, 126, 31, 63, 95, 127
        };

        protected static byte[] FPtable = {
             0,  4,  8, 12, 16, 20, 24, 28, 32,  36,  40,  44,  48,  52,  56,  60,
            64, 68, 72, 76, 80, 84, 88, 92, 96, 100, 104, 108, 112, 116, 120, 124,
             1,  5,  9, 13, 17, 21, 25, 29, 33,  37,  41,  45,  49,  53,  57,  61,
            65, 69, 73, 77, 81, 85, 89, 93, 97, 101, 105, 109, 113, 117, 121, 125,
             2,  6, 10, 14, 18, 22, 26, 30, 34,  38,  42,  46,  50,  54,  58,  62,
            66, 70, 74, 78, 82, 86, 90, 94, 98, 102, 106, 110, 114, 118, 122, 126,
             3,  7, 11, 15, 19, 23, 27, 31, 35,  39,  43,  47,  51,  55,  59,  63,
            67, 71, 75, 79, 83, 87, 91, 95, 99, 103, 107, 111, 115, 119, 123, 127
        };

        protected static byte xFF = (byte)0xFF;
        
        protected static byte[][] LTtable = {
            new byte[] {16,  52,  56,  70,  83,  94, 105, xFF},
            new byte[] {72, 114, 125, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 2,   9,  15,  30,  76,  84, 126, xFF},
            new byte[] {36,  90, 103, xFF, xFF, xFF, xFF, xFF},
            new byte[] {20,  56,  60,  74,  87,  98, 109, xFF},
            new byte[] { 1,  76, 118, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 2,   6,  13,  19,  34,  80,  88, xFF},
            new byte[] {40,  94, 107, xFF, xFF, xFF, xFF, xFF},
            new byte[] {24,  60,  64,  78,  91, 102, 113, xFF},
            new byte[] { 5,  80, 122, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 6,  10,  17,  23,  38,  84,  92, xFF},
            new byte[] {44,  98, 111, xFF, xFF, xFF, xFF, xFF},
            new byte[] {28,  64,  68,  82,  95, 106, 117, xFF},
            new byte[] { 9,  84, 126, xFF, xFF, xFF, xFF, xFF},
            new byte[] {10,  14,  21,  27,  42,  88,  96, xFF},
            new byte[] {48, 102, 115, xFF, xFF, xFF, xFF, xFF},
            new byte[] {32,  68,  72,  86,  99, 110, 121, xFF},
            new byte[] { 2,  13,  88, xFF, xFF, xFF, xFF, xFF},
            new byte[] {14,  18,  25,  31,  46,  92, 100, xFF},
            new byte[] {52, 106, 119, xFF, xFF, xFF, xFF, xFF},
            new byte[] {36,  72,  76,  90, 103, 114, 125, xFF},
            new byte[] { 6,  17,  92, xFF, xFF, xFF, xFF, xFF},
            new byte[] {18,  22,  29,  35,  50,  96, 104, xFF},
            new byte[] {56, 110, 123, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 1,  40,  76,  80,  94, 107, 118, xFF},
            new byte[] {10,  21,  96, xFF, xFF, xFF, xFF, xFF},
            new byte[] {22,  26,  33,  39,  54, 100, 108, xFF},
            new byte[] {60, 114, 127, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 5,  44,  80,  84,  98, 111, 122, xFF},
            new byte[] {14,  25, 100, xFF, xFF, xFF, xFF, xFF},
            new byte[] {26,  30,  37,  43,  58, 104, 112, xFF},
            new byte[] { 3, 118, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 9,  48,  84,  88, 102, 115, 126, xFF},
            new byte[] {18,  29, 104, xFF, xFF, xFF, xFF, xFF},
            new byte[] {30,  34,  41,  47,  62, 108, 116, xFF},
            new byte[] { 7, 122, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 2,  13,  52,  88,  92, 106, 119, xFF},
            new byte[] {22,  33, 108, xFF, xFF, xFF, xFF, xFF},
            new byte[] {34,  38,  45,  51,  66, 112, 120, xFF},
            new byte[] {11, 126, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 6,  17,  56,  92,  96, 110, 123, xFF},
            new byte[] {26,  37, 112, xFF, xFF, xFF, xFF, xFF},
            new byte[] {38,  42,  49,  55,  70, 116, 124, xFF},
            new byte[] { 2,  15,  76, xFF, xFF, xFF, xFF, xFF},
            new byte[] {10,  21,  60,  96, 100, 114, 127, xFF},
            new byte[] {30,  41, 116, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 0,  42,  46,  53,  59,  74, 120, xFF},
            new byte[] { 6,  19,  80, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 3,  14,  25, 100, 104, 118, xFF, xFF},
            new byte[] {34,  45, 120, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 4,  46,  50,  57,  63,  78, 124, xFF},
            new byte[] {10,  23,  84, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 7,  18,  29, 104, 108, 122, xFF, xFF},
            new byte[] {38,  49, 124, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 0,   8,  50,  54,  61,  67,  82, xFF},
            new byte[] {14,  27,  88, xFF, xFF, xFF, xFF, xFF},
            new byte[] {11,  22,  33, 108, 112, 126, xFF, xFF},
            new byte[] { 0,  42,  53, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 4,  12,  54,  58,  65,  71,  86, xFF},
            new byte[] {18,  31,  92, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 2,  15,  26,  37,  76, 112, 116, xFF},
            new byte[] { 4,  46,  57, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 8,  16,  58,  62,  69,  75,  90, xFF},
            new byte[] {22,  35,  96, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 6,  19,  30,  41,  80, 116, 120, xFF},
            new byte[] { 8,  50,  61, xFF, xFF, xFF, xFF, xFF},
            new byte[] {12,  20,  62,  66,  73,  79,  94, xFF},
            new byte[] {26,  39, 100, xFF, xFF, xFF, xFF, xFF},
            new byte[] {10,  23,  34,  45,  84, 120, 124, xFF},
            new byte[] {12,  54,  65, xFF, xFF, xFF, xFF, xFF},
            new byte[] {16,  24,  66,  70,  77,  83,  98, xFF},
            new byte[] {30,  43, 104, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 0,  14,  27,  38,  49,  88, 124, xFF},
            new byte[] {16,  58,  69, xFF, xFF, xFF, xFF, xFF},
            new byte[] {20,  28,  70,  74,  81,  87, 102, xFF},
            new byte[] {34,  47, 108, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 0,   4,  18,  31,  42,  53,  92, xFF},
            new byte[] {20,  62,  73, xFF, xFF, xFF, xFF, xFF},
            new byte[] {24,  32,  74,  78,  85,  91, 106, xFF},
            new byte[] {38,  51, 112, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 4,   8,  22,  35,  46,  57,  96, xFF},
            new byte[] {24,  66,  77, xFF, xFF, xFF, xFF, xFF},
            new byte[] {28,  36,  78,  82,  89,  95, 110, xFF},
            new byte[] {42,  55, 116, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 8,  12,  26,  39,  50,  61, 100, xFF},
            new byte[] {28,  70,  81, xFF, xFF, xFF, xFF, xFF},
            new byte[] {32,  40,  82,  86,  93,  99, 114, xFF},
            new byte[] {46,  59, 120, xFF, xFF, xFF, xFF, xFF},
            new byte[] {12,  16,  30,  43,  54,  65, 104, xFF},
            new byte[] {32,  74,  85, xFF, xFF, xFF, xFF, xFF},
            new byte[] {36,  90, 103, 118, xFF, xFF, xFF, xFF},
            new byte[] {50,  63, 124, xFF, xFF, xFF, xFF, xFF},
            new byte[] {16,  20,  34,  47,  58,  69, 108, xFF},
            new byte[] {36,  78,  89, xFF, xFF, xFF, xFF, xFF},
            new byte[] {40,  94, 107, 122, xFF, xFF, xFF, xFF},
            new byte[] { 0,  54,  67, xFF, xFF, xFF, xFF, xFF},
            new byte[] {20,  24,  38,  51,  62,  73, 112, xFF},
            new byte[] {40,  82,  93, xFF, xFF, xFF, xFF, xFF},
            new byte[] {44,  98, 111, 126, xFF, xFF, xFF, xFF},
            new byte[] { 4,  58,  71, xFF, xFF, xFF, xFF, xFF},
            new byte[] {24,  28,  42,  55,  66,  77, 116, xFF},
            new byte[] {44,  86,  97, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 2,  48, 102, 115, xFF, xFF, xFF, xFF},
            new byte[] { 8,  62,  75, xFF, xFF, xFF, xFF, xFF},
            new byte[] {28,  32,  46,  59,  70,  81, 120, xFF},
            new byte[] {48,  90, 101, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 6,  52, 106, 119, xFF, xFF, xFF, xFF},
            new byte[] {12,  66,  79, xFF, xFF, xFF, xFF, xFF},
            new byte[] {32,  36,  50,  63,  74,  85, 124, xFF},
            new byte[] {52,  94, 105, xFF, xFF, xFF, xFF, xFF},
            new byte[] {10,  56, 110, 123, xFF, xFF, xFF, xFF},
            new byte[] {16,  70,  83, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 0,  36,  40,  54,  67,  78,  89, xFF},
            new byte[] {56,  98, 109, xFF, xFF, xFF, xFF, xFF},
            new byte[] {14,  60, 114, 127, xFF, xFF, xFF, xFF},
            new byte[] {20,  74,  87, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 4,  40,  44,  58,  71,  82,  93, xFF},
            new byte[] {60, 102, 113, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 3,  18,  72, 114, 118, 125, xFF, xFF},
            new byte[] {24,  78,  91, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 8,  44,  48,  62,  75,  86,  97, xFF},
            new byte[] {64, 106, 117, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 1,   7,  22,  76, 118, 122, xFF, xFF},
            new byte[] {28,  82,  95, xFF, xFF, xFF, xFF, xFF},
            new byte[] {12,  48,  52,  66,  79,  90, 101, xFF},
            new byte[] {68, 110, 121, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 5,  11,  26,  80, 122, 126, xFF, xFF},
            new byte[] {32,  86,  99, xFF, xFF, xFF, xFF, xFF}
        };

        protected static byte[][] LTtableInverse = {
            new byte[] { 53,  55,  72, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  1,   5,  20,  90, xFF, xFF, xFF, xFF},
            new byte[] { 15, 102, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  3,  31,  90, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 57,  59,  76, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  5,   9,  24,  94, xFF, xFF, xFF, xFF},
            new byte[] { 19, 106, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  7,  35,  94, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 61,  63,  80, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  9,  13,  28,  98, xFF, xFF, xFF, xFF},
            new byte[] { 23, 110, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 11,  39,  98, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 65,  67,  84, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 13,  17,  32, 102, xFF, xFF, xFF, xFF},
            new byte[] { 27, 114, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  1,   3,  15,  20,  43, 102, xFF, xFF},
            new byte[] { 69,  71,  88, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 17,  21,  36, 106, xFF, xFF, xFF, xFF},
            new byte[] {  1,  31, 118, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  5,   7,  19,  24,  47, 106, xFF, xFF},
            new byte[] { 73,  75,  92, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 21,  25,  40, 110, xFF, xFF, xFF, xFF},
            new byte[] {  5,  35, 122, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  9,  11,  23,  28,  51, 110, xFF, xFF},
            new byte[] { 77,  79,  96, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 25,  29,  44, 114, xFF, xFF, xFF, xFF},
            new byte[] {  9,  39, 126, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 13,  15,  27,  32,  55, 114, xFF, xFF},
            new byte[] { 81,  83, 100, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  1,  29,  33,  48, 118, xFF, xFF, xFF},
            new byte[] {  2,  13,  43, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  1,  17,  19,  31,  36,  59, 118, xFF},
            new byte[] { 85,  87, 104, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  5,  33,  37,  52, 122, xFF, xFF, xFF},
            new byte[] {  6,  17,  47, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  5,  21,  23,  35,  40,  63, 122, xFF},
            new byte[] { 89,  91, 108, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  9,  37,  41,  56, 126, xFF, xFF, xFF},
            new byte[] { 10,  21,  51, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  9,  25,  27,  39,  44,  67, 126, xFF},
            new byte[] { 93,  95, 112, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  2,  13,  41,  45,  60, xFF, xFF, xFF},
            new byte[] { 14,  25,  55, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  2,  13,  29,  31,  43,  48,  71, xFF},
            new byte[] { 97,  99, 116, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  6,  17,  45,  49,  64, xFF, xFF, xFF},
            new byte[] { 18,  29,  59, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  6,  17,  33,  35,  47,  52,  75, xFF},
            new byte[] {101, 103, 120, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 10,  21,  49,  53,  68, xFF, xFF, xFF},
            new byte[] { 22,  33,  63, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 10,  21,  37,  39,  51,  56,  79, xFF},
            new byte[] {105, 107, 124, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 14,  25,  53,  57,  72, xFF, xFF, xFF},
            new byte[] { 26,  37,  67, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 14,  25,  41,  43,  55,  60,  83, xFF},
            new byte[] {  0, 109, 111, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 18,  29,  57,  61,  76, xFF, xFF, xFF},
            new byte[] { 30,  41,  71, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 18,  29,  45,  47,  59,  64,  87, xFF},
            new byte[] {  4, 113, 115, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 22,  33,  61,  65,  80, xFF, xFF, xFF},
            new byte[] { 34,  45,  75, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 22,  33,  49,  51,  63,  68,  91, xFF},
            new byte[] {  8, 117, 119, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 26,  37,  65,  69,  84, xFF, xFF, xFF},
            new byte[] { 38,  49,  79, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 26,  37,  53,  55,  67,  72,  95, xFF},
            new byte[] { 12, 121, 123, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 30,  41,  69,  73,  88, xFF, xFF, xFF},
            new byte[] { 42,  53,  83, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 30,  41,  57,  59,  71,  76,  99, xFF},
            new byte[] { 16, 125, 127, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 34,  45,  73,  77,  92, xFF, xFF, xFF},
            new byte[] { 46,  57,  87, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 34,  45,  61,  63,  75,  80, 103, xFF},
            new byte[] {  1,   3,  20, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 38,  49,  77,  81,  96, xFF, xFF, xFF},
            new byte[] { 50,  61,  91, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 38,  49,  65,  67,  79,  84, 107, xFF},
            new byte[] {  5,   7,  24, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 42,  53,  81,  85, 100, xFF, xFF, xFF},
            new byte[] { 54,  65,  95, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 42,  53,  69,  71,  83,  88, 111, xFF},
            new byte[] {  9,  11,  28, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 46,  57,  85,  89, 104, xFF, xFF, xFF},
            new byte[] { 58,  69,  99, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 46,  57,  73,  75,  87,  92, 115, xFF},
            new byte[] { 13,  15,  32, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 50,  61,  89,  93, 108, xFF, xFF, xFF},
            new byte[] { 62,  73, 103, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 50,  61,  77,  79,  91,  96, 119, xFF},
            new byte[] { 17,  19,  36, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 54,  65,  93,  97, 112, xFF, xFF, xFF},
            new byte[] { 66,  77, 107, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 54,  65,  81,  83,  95, 100, 123, xFF},
            new byte[] { 21,  23,  40, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 58,  69,  97, 101, 116, xFF, xFF, xFF},
            new byte[] { 70,  81, 111, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 58,  69,  85,  87,  99, 104, 127, xFF},
            new byte[] { 25,  27,  44, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 62,  73, 101, 105, 120, xFF, xFF, xFF},
            new byte[] { 74,  85, 115, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  3,  62,  73,  89,  91, 103, 108, xFF},
            new byte[] { 29,  31,  48, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 66,  77, 105, 109, 124, xFF, xFF, xFF},
            new byte[] { 78,  89, 119, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  7,  66,  77,  93,  95, 107, 112, xFF},
            new byte[] { 33,  35,  52, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  0,  70,  81, 109, 113, xFF, xFF, xFF},
            new byte[] { 82,  93, 123, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 11,  70,  81,  97,  99, 111, 116, xFF},
            new byte[] { 37,  39,  56, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  4,  74,  85, 113, 117, xFF, xFF, xFF},
            new byte[] { 86,  97, 127, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 15,  74,  85, 101, 103, 115, 120, xFF},
            new byte[] { 41,  43,  60, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  8,  78,  89, 117, 121, xFF, xFF, xFF},
            new byte[] {  3,  90, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 19,  78,  89, 105, 107, 119, 124, xFF},
            new byte[] { 45,  47,  64, xFF, xFF, xFF, xFF, xFF},
            new byte[] { 12,  82,  93, 121, 125, xFF, xFF, xFF},
            new byte[] {  7,  94, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  0,  23,  82,  93, 109, 111, 123, xFF},
            new byte[] { 49,  51,  68, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  1,  16,  86,  97, 125, xFF, xFF, xFF},
            new byte[] { 11,  98, xFF, xFF, xFF, xFF, xFF, xFF},
            new byte[] {  4,  27,  86,  97, 113, 115, 127, xFF}
        };

        protected static char[] HEX_DIGITS = { '0','1','2','3','4','5','6','7','8','9','A','B','C','D','E','F' };

        #endregion

        public abstract object MakeKey(byte[] key);
        public abstract byte[] BlockEncrypt(byte[] inV, int inOffset, object sessionKey);
        public abstract byte[] BlockDecrypt(byte[] inV, int inOffset, object sessionKey);
    }
}
