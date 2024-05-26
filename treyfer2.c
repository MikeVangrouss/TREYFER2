/*
 * TREYFER2 cipher
 * TREYFER2 by Alexander Pukall 2005
 * 
 * Based on TREYFER cipher by Gideon Yuval
 * 
 * 8192-bit keys with 1024 * 8-bit subkeys
 * 
 * 128-bit block cipher (like AES) 64 rounds
 * 
 * Uses MD2II hash function to create the 1024 subkeys
 * 
 * Code free for all, even for commercial software 
 * No restriction to use. Public Domain 
 * 
 * Compile with gcc: gcc treyfer2.c -o treyfer2
 * 
 */

#include <stdio.h>
#include <string.h>
#include <stdint.h>

#define n1 1024 /* 8192-bit TREYFER2 key for 1024 * 8-bit subkeys */


int x1,x2,i;
unsigned char h2[n1];
unsigned char h1[n1*3];


static void init()
{
    
   x1 = 0;
   x2 = 0;
    for (i = 0; i < n1; i++)
        h2[i] = 0;
    for (i = 0; i < n1; i++)
        h1[i] = 0;
}

static void hashing(unsigned char t1[], size_t b6)
{
    static unsigned char s4[256] = 
    {   13, 199,  11,  67, 237, 193, 164,  77, 115, 184, 141, 222,  73,
        38, 147,  36, 150,  87,  21, 104,  12,  61, 156, 101, 111, 145,
       119,  22, 207,  35, 198,  37, 171, 167,  80,  30, 219,  28, 213,
       121,  86,  29, 214, 242,   6,   4,  89, 162, 110, 175,  19, 157,
         3,  88, 234,  94, 144, 118, 159, 239, 100,  17, 182, 173, 238,
        68,  16,  79, 132,  54, 163,  52,   9,  58,  57,  55, 229, 192,
       170, 226,  56, 231, 187, 158,  70, 224, 233, 245,  26,  47,  32,
        44, 247,   8, 251,  20, 197, 185, 109, 153, 204, 218,  93, 178,
       212, 137,  84, 174,  24, 120, 130, 149,  72, 180, 181, 208, 255,
       189, 152,  18, 143, 176,  60, 249,  27, 227, 128, 139, 243, 253,
        59, 123, 172, 108, 211,  96, 138,  10, 215,  42, 225,  40,  81,
        65,  90,  25,  98, 126, 154,  64, 124, 116, 122,   5,   1, 168,
        83, 190, 131, 191, 244, 240, 235, 177, 155, 228, 125,  66,  43,
       201, 248, 220, 129, 188, 230,  62,  75,  71,  78,  34,  31, 216,
       254, 136,  91, 114, 106,  46, 217, 196,  92, 151, 209, 133,  51,
       236,  33, 252, 127, 179,  69,   7, 183, 105, 146,  97,  39,  15,
       205, 112, 200, 166, 223,  45,  48, 246, 186,  41, 148, 140, 107,
        76,  85,  95, 194, 142,  50,  49, 134,  23, 135, 169, 221, 210,
       203,  63, 165,  82, 161, 202,  53,  14, 206, 232, 103, 102, 195,
       117, 250,  99,   0,  74, 160, 241,   2, 113};
       
    int b1,b2,b3,b4,b5;
   
	b4=0;
    while (b6) {
    
        for (; b6 && x2 < n1; b6--, x2++) {
            b5 = t1[b4++];
            h1[x2 + n1] = b5;
            h1[x2 + (n1*2)] = b5 ^ h1[x2];

            x1 = h2[x2] ^= s4[b5 ^ x1];
        }

        if (x2 == n1)
        {
            b2 = 0;
            x2 = 0;
            
            for (b3 = 0; b3 < (n1+2); b3++) {
                for (b1 = 0; b1 < (n1*3); b1++)
                    b2 = h1[b1] ^= s4[b2];
                b2 = (b2 + b3) % 256;
            }
           }
          }
        }

static void end(unsigned char h4[n1])
{
    
    unsigned char h3[n1];
    int i, n4;
    
    n4 = n1 - x2;
    for (i = 0; i < n4; i++) h3[i] = n4;
    hashing(h3, n4);
    hashing(h2, sizeof(h2));
    for (i = 0; i < n1; i++) h4[i] = h1[i];
}

#define NumRounds 64

/* RC2 cipher Sbox by Ronald Rivest */

static const uint8_t sbox[256] =   {
217,120,249,196, 25,221,181,237, 40,233,253,121, 74,160,216,157,
198,126, 55,131, 43,118, 83,142, 98, 76,100,136, 68,139,251,162,
23,154, 89,245,135,179, 79, 19, 97, 69,109,141, 9,129,125, 50,
189,143, 64,235,134,183,123, 11,240,149, 33, 34, 92,107, 78,130,
84,214,101,147,206, 96,178, 28,115, 86,192, 20,167,140,241,220,
18,117,202, 31, 59,190,228,209, 66, 61,212, 48,163, 60,182, 38,
111,191, 14,218, 70,105, 7, 87, 39,242, 29,155,188,148, 67, 3,
248, 17,199,246,144,239, 62,231, 6,195,213, 47,200,102, 30,215,
8,232,234,222,128, 82,238,247,132,170,114,172, 53, 77,106, 42,
150, 26,210,113, 90, 21, 73,116, 75,159,208, 94, 4, 24,164,236,
194,224, 65,110, 15, 81,203,204, 36,145,175, 80,161,244,112, 57,
153,124, 58,133, 35,184,180,122,252, 2, 54, 91, 37, 85,151, 49,
45, 93,250,152,227,138,146,174, 5,223, 41, 16,103,108,186,201,
211, 0,230,207,225,158,168, 44, 99, 22, 1, 63, 88,226,137,169,
13, 56, 52, 27,171, 51,255,176,187, 72, 12, 95,185,177,205, 46,
197,243,219, 71,229,165,156,119, 10,166, 32,104,254,127,193,173
};

void encrypt(uint8_t text[17], uint8_t key[1024])
{
  int keyptr = 0;
  
for (int r=0; r < NumRounds; r++)
{
  text[16] = text[0];

  for (int i=0; i<16; i++)
  {
     
  text[i+1] = (text[i+1] + sbox[(key[keyptr++]+text[i])%256]);
  text[i+1] = (text[i+1] << 1) | (text[i+1] >> 7);
  
  }
  text[0] = text[16];
}

}

void decrypt(uint8_t text[17], uint8_t key[1024])
{
  int keyptr = 1023;
  
for (int r=0; r < NumRounds; r++)
{
  text[16] = text[0];

  for (int i=15; i>=0; i--)
  {
  
  text[i+1] = (text[i+1] >> 1 ) | (text[i+1] << 7);
  
  if (i==0) text[0]=text[16];
  
  text[i+1] = (text[i+1] - sbox[(key[keyptr--]+text[i])%256]);
 
  }

  
}
}


int main() {
  
  
    uint8_t plaintext[16];
  
    unsigned char text[33]; /* up to 256 chars for the password */
                            /* password can be hexadecimal */

  	unsigned char h4[n1];
	

    printf("TREYFER2 by Alexander PUKALL 2005 \n 128-bit block 8192-bit subkeys 64 rounds\n");
    printf("Code can be freely use even for commercial software\n");
    printf("Based on TREYFER by Gideon Yuval\n\n");

    /* The key creation procedure is slow, it only needs to be done once */
    /* as long as the user does not change the key. You can encrypt and decrypt */
    /* as many blocks as you want without having to hash the key again. */
    /* init(); hashing(text,length);  end(h4); -> only once */
   

    /* EXAMPLE 1 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789abc");

    hashing(text, 32);
    end(h4); /* h4 = 8192-bit key from hash "My secret password!0123456789abc */

    plaintext[0] = 0xFE; /* 0xFEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE TREYFER2 block plaintext */
    plaintext[1] = 0xFE; 
    plaintext[2] = 0xFE;
    plaintext[3] = 0xFE;
    plaintext[4] = 0xFE;
    plaintext[5] = 0xFE;
    plaintext[6] = 0xFE;
    plaintext[7] = 0xFE;
    plaintext[8] = 0xFE;
    plaintext[9] = 0xFE; 
    plaintext[10] = 0xFE;
    plaintext[11] = 0xFE;
    plaintext[12] = 0xFE; 
    plaintext[13] = 0xFE;
    plaintext[14] = 0xFE;
    plaintext[15] = 0xFE;
                
    printf("Key 1:%s\n",text);
    printf ("Plaintext   1:");
    for (int i=0;i<16;i++) printf("%0.2X",plaintext[i]);
    printf("\n");

    printf ("Encryption  1:");
    encrypt(plaintext, h4);
    for (int i=0;i<16;i++) printf("%0.2X",plaintext[i]);
    printf("\n");
    
    printf ("Decryption  1:");
    decrypt(plaintext, h4);
    for (int i=0;i<16;i++) printf("%0.2X",plaintext[i]);
    printf("\n\n");
 
    /* EXAMPLE 2 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789ABC");

    hashing(text, 32);
    end(h4); /* h4 = 8192-bit key from hash "My secret password!0123456789ABC */
   
    plaintext[0] = 0x00; /* 0x00000000000000000000000000000000 TREYFER2 block plaintext */
    plaintext[1] = 0x00; 
    plaintext[2] = 0x00;
    plaintext[3] = 0x00;
    plaintext[4] = 0x00;
    plaintext[5] = 0x00;
    plaintext[6] = 0x00;
    plaintext[7] = 0x00;
    plaintext[8] = 0x00;
    plaintext[9] = 0x00; 
    plaintext[10] = 0x00;
    plaintext[11] = 0x00;
    plaintext[12] = 0x00; 
    plaintext[13] = 0x00;
    plaintext[14] = 0x00;
    plaintext[15] = 0x00;
                
    printf("Key 2:%s\n",text);
    printf ("Plaintext   2:");
    for (int i=0;i<16;i++) printf("%0.2X",plaintext[i]);
    printf("\n");

    printf ("Encryption  2:");
    encrypt(plaintext, h4);
    for (int i=0;i<16;i++) printf("%0.2X",plaintext[i]);
    printf("\n");
    
    printf ("Decryption  2:");
    decrypt(plaintext, h4);
    for (int i=0;i<16;i++) printf("%0.2X",plaintext[i]);
    printf("\n\n");
	
    /* EXAMPLE 3 */
    
    init();

    strcpy((char *) text,"My secret password!0123456789abZ");

    hashing(text, 32);
    end(h4); /* h4 = 8192-bit key from hash "My secret password!0123456789abZ */
   
    plaintext[0] = 0x00; /* 0x00000000000000000000000000000001 TREYFER2 block plaintext */
    plaintext[1] = 0x00; 
    plaintext[2] = 0x00;
    plaintext[3] = 0x00;
    plaintext[4] = 0x00;
    plaintext[5] = 0x00;
    plaintext[6] = 0x00;
    plaintext[7] = 0x00;
    plaintext[8] = 0x00;
    plaintext[9] = 0x00; 
    plaintext[10] = 0x00;
    plaintext[11] = 0x00;
    plaintext[12] = 0x00; 
    plaintext[13] = 0x00;
    plaintext[14] = 0x00;
    plaintext[15] = 0x01;
                
    printf("Key 3:%s\n",text);
    printf ("Plaintext   3:");
    for (int i=0;i<16;i++) printf("%0.2X",plaintext[i]);
    printf("\n");

    printf ("Encryption  3:");
    encrypt(plaintext, h4);
    for (int i=0;i<16;i++) printf("%0.2X",plaintext[i]);
    printf("\n");
    
    printf ("Decryption  3:");
    decrypt(plaintext, h4);
    for (int i=0;i<16;i++) printf("%0.2X",plaintext[i]);
    printf("\n");
	
}

/*
 
 TREYFER2 by Alexander PUKALL 2005 
 128-bit block 8192-bit subkeys 64 rounds
Code can be freely use even for commercial software
Based on TREYFER by Gideon Yuval

Key 1:My secret password!0123456789abc
Plaintext   1:FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE
Encryption  1:D958AE943289C3DB6D8153B54F376205
Decryption  1:FEFEFEFEFEFEFEFEFEFEFEFEFEFEFEFE

Key 2:My secret password!0123456789ABC
Plaintext   2:00000000000000000000000000000000
Encryption  2:B5D6E6A606759084D39F2642117C3974
Decryption  2:00000000000000000000000000000000

Key 3:My secret password!0123456789abZ
Plaintext   3:00000000000000000000000000000001
Encryption  3:96AFFBFCA125032C19DE2CF2F3B5E221
Decryption  3:00000000000000000000000000000001

*/
