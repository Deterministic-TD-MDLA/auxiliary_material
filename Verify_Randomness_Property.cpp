#include <iostream>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <fstream>

#define RepeatedTestTime 1000 // Random tests are repeated for 1000 times.
#define DataRequirement (1<<21) // In each test, we use 2^{21} randomly selected pairs to check the distribution of \Delta x_{5}^{S}[1,0].

using namespace std;

int S[16][16] = { // The S-box of AES
{0x63,0x7c,0x77,0x7b,0xf2,0x6b,0x6f,0xc5,0x30,0x01,0x67,0x2b,0xfe,0xd7,0xab,0x76},
{0xca,0x82,0xc9,0x7d,0xfa,0x59,0x47,0xf0,0xad,0xd4,0xa2,0xaf,0x9c,0xa4,0x72,0xc0},
{0xb7,0xfd,0x93,0x26,0x36,0x3f,0xf7,0xcc,0x34,0xa5,0xe5,0xf1,0x71,0xd8,0x31,0x15},
{0x04,0xc7,0x23,0xc3,0x18,0x96,0x05,0x9a,0x07,0x12,0x80,0xe2,0xeb,0x27,0xb2,0x75},
{0x09,0x83,0x2c,0x1a,0x1b,0x6e,0x5a,0xa0,0x52,0x3b,0xd6,0xb3,0x29,0xe3,0x2f,0x84},
{0x53,0xd1,0x00,0xed,0x20,0xfc,0xb1,0x5b,0x6a,0xcb,0xbe,0x39,0x4a,0x4c,0x58,0xcf},
{0xd0,0xef,0xaa,0xfb,0x43,0x4d,0x33,0x85,0x45,0xf9,0x02,0x7f,0x50,0x3c,0x9f,0xa8},
{0x51,0xa3,0x40,0x8f,0x92,0x9d,0x38,0xf5,0xbc,0xb6,0xda,0x21,0x10,0xff,0xf3,0xd2},
{0xcd,0x0c,0x13,0xec,0x5f,0x97,0x44,0x17,0xc4,0xa7,0x7e,0x3d,0x64,0x5d,0x19,0x73},
{0x60,0x81,0x4f,0xdc,0x22,0x2a,0x90,0x88,0x46,0xee,0xb8,0x14,0xde,0x5e,0x0b,0xdb},
{0xe0,0x32,0x3a,0x0a,0x49,0x06,0x24,0x5c,0xc2,0xd3,0xac,0x62,0x91,0x95,0xe4,0x79},
{0xe7,0xc8,0x37,0x6d,0x8d,0xd5,0x4e,0xa9,0x6c,0x56,0xf4,0xea,0x65,0x7a,0xae,0x08},
{0xba,0x78,0x25,0x2e,0x1c,0xa6,0xb4,0xc6,0xe8,0xdd,0x74,0x1f,0x4b,0xbd,0x8b,0x8a},
{0x70,0x3e,0xb5,0x66,0x48,0x03,0xf6,0x0e,0x61,0x35,0x57,0xb9,0x86,0xc1,0x1d,0x9e},
{0xe1,0xf8,0x98,0x11,0x69,0xd9,0x8e,0x94,0x9b,0x1e,0x87,0xe9,0xce,0x55,0x28,0xdf},
{0x8c,0xa1,0x89,0x0d,0xbf,0xe6,0x42,0x68,0x41,0x99,0x2d,0x0f,0xb0,0x54,0xbb,0x16}};

void Sbox(int * input, int *output) // The operation of S-box
{
    int row = (((*input)>>4)&(0xf));
    int column = ((*input)&(0xf));
    (*output) = S[row][column];
}

void SubBytes(int in[4][4], int out[4][4]) // The SubBytes operation
{
    int X[4][4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            X[i][j] = in[i][j];
        }
    }
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            Sbox(&X[i][j], &out[i][j]);
        }
    }
}

void KeySchedule(int MasterKey[6], int Subkey[13][4][4]) // The KeySchedule of AES-192
{
    int W[52][4];
    for (int i = 0; i <6 ; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            W[i][j] = ((MasterKey[i]>>((3-j)*8))&(0xff));
        }
    }
    
    int Rcon[9] = {0, 0x01000000, 0x02000000, 0x04000000, 0x08000000,
        0x10000000, 0x20000000, 0x40000000, 0x80000000};
    
    for (int i = 6; i < 52; i++)
    {
        int temp[4];
        for (int j = 0; j < 4; j++)
        {
            temp[j] = W[i-1][j];
        }
        int temp1[4];
        if ((i%6)==0)
        {
            for (int j = 0; j < 3; j++)
            {
                temp1[j] = temp[j+1];
            }
            temp1[3] = temp[0];
            for (int j = 0; j < 4; j++)
            {
                Sbox(&temp1[j], &temp[j]);
                temp[j] ^= ((Rcon[i/6]>>((3-j)*8))&(0xff));
            }
        }
        for (int j = 0; j < 4; j++)
        {
            W[i][j] = W[i-6][j]^temp[j];
        }
    }
    
    for (int i = 0; i < 13; i++)
    {
        for(int j = 0; j < 4; j++)
        {
            for (int k = 0; k < 4; k++)
            {
                Subkey[i][k][j] = W[4*i+j][k];
            }
        }
    }
}

void ShiftRows(int in [4][4], int out[4][4]) // The ShiftRows operation
{
    int X[4][4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            X[i][j] = in[i][j];
        }
    }
    
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[i][j] = X[i][(j+i)%4];
        }
    }
}

void Multiplication(int * a, int * x, int *b) // The multiplication of a and x over F_{2}^{8}
{
    int Modulo = 0x11b;
    int V[8];
    V[0] = (*x);
    for (int i = 1; i < 8; i++)
    {
        V[i] = (V[i-1]<<1);
        if ((V[i]>>8)&(0x1))
        {
            V[i] ^= Modulo;
        }
    }
    
    int out = 0;
    for (int i = 0; i < 8; i++)
    {
        if (((*a)>>i)&(0x1))
        {
            out ^= V[i];
        }
    }
    (*b) = out;
}

void MixColumns(int in[4][4], int out[4][4]) // The MixColumns operation
{
    int X[4][4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            X[i][j] = in[i][j];
        }
    }
    
    int M[4][4] = {{2,3,1,1},{1,2,3,1},{1,1,2,3},{3,1,1,2}};
    
    for (int j = 0; j < 4; j++)
    {
        int MCin[4];
        int MCout[4];
        for (int i = 0; i < 4; i++)
        {
            MCin[i] = X[i][j];
        }
        
        for (int i = 0; i < 4; i++)
        {
            MCout[i] = 0;
            int temp;
            for (int j = 0; j < 4; j++)
            {
                Multiplication(&M[i][j], &MCin[j], &temp);
                MCout[i] ^= temp;
            }
        }
        for (int i = 0; i < 4; i++)
        {
            out[i][j] = MCout[i];
        }
    }
}

void AddRoundKey(int in[4][4], int out[4][4], int key[4][4]) // The AddRoundKey operation
{
    int X[4][4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            X[i][j] = in[i][j];
        }
    }
    
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            out[i][j] = X[i][j] ^ key[i][j];
        }
    }
}

void AES192(int plaintext[4], int ciphertext[4], int Subkey[13][4][4]) // The encryption algorithm of AES-192
{
    int X[4][4];
    for (int i = 0; i < 4; i++)
    {
        for (int j = 0; j < 4; j++)
        {
            X[j][i] = ((plaintext[i]>>((3-j)*8))&(0xff));
        }
    }
    AddRoundKey(X, X, Subkey[0]);
    for (int round = 0; round < 4; round++)
    {
        SubBytes(X, X);
        ShiftRows(X, X);
        MixColumns(X, X);
        AddRoundKey(X, X, Subkey[round + 1]);
    }
    SubBytes(X, X);
    
    for (int i = 0; i < 4; i++)
    {
        ciphertext[i] = 0;
        for (int j = 0; j < 4; j++)
        {
            ciphertext[i] ^= (X[j][i]<<((3-j)*8));
        }
    }
}


int main()
{
    ofstream fout("DistributionOfDifference.out"); // The file to store the distribution of \Delta x_{5}^{S}[1,0]
    ofstream fouteuc("EuclideanDistance.out"); // The file to store the Euclidean Distance between the distribution of the differences and the 255-dimensional vector (1/255, 1/255, ..., 1/255)
    srand(time(0));
    
    clock_t test_start, test_end;
    test_start = clock();
    
    for (int repeatedtest = 0; repeatedtest < RepeatedTestTime; repeatedtest++)
    {
        int MasterKey1[6]; // The first masterkey
        int MasterKey2[6]; // The second masterkey
        int Subkey1[13][4][4]; // The first subkey
        int Subkey2[13][4][4]; // The second subkey
        
        int temp[4];
        for (int i = 0; i < 6; i++)
        {
            for (int j = 0; j < 4; j++)
            {
                temp[j] = (rand()&(0xff));
            }
            MasterKey1[i] = ((temp[0]<<24)^(temp[1]<<16)^(temp[2]<<8)^temp[3]);
            // Randomly generate the first masterkey
        }
        int Alpha = (rand()&(0xff)); // Randomly select the difference \alpha
        if (Alpha == 0)
        {
            Alpha = Alpha + 1; // To escape the case '\alpha == 0'
        }
        // Set the value of the second masterkey
        for (int i = 0; i < 6; i++)
        {
            MasterKey2[i] = MasterKey1[i];
        }
        MasterKey2[2] ^= (Alpha<<24);
        MasterKey2[3] ^= (Alpha<<24);
        
        KeySchedule(MasterKey1, Subkey1); // Generate the first subkey
        KeySchedule(MasterKey2, Subkey2); // Generate the second subkey
        
        int CounterOfDistribution[256]; // The counter to record the frequency of \Delta x_{5}^{S}[1,0]
        for (int i = 0; i < 256; i++)
        {
            CounterOfDistribution[i] = 0;
        }
        
        for (int data = 0; data < DataRequirement; data++) // The distribution of \Delta x_{5}^{S}[1,0] is verified with 2^{21} pairs
        {
            int Plaintext1[4]; // The first plaintext
            int Plaintext2[4]; // The second plaintext
            int Ciphertext1[4]; // The first ciphertext
            int Ciphertext2[4]; // The second ciphertext
            
            // Generate the plaintext pair
            for (int i = 0; i < 4; i++)
            {
                for (int j = 0; j < 4; j++)
                {
                    temp[j] = (rand()&(0xff));
                }
                Plaintext1[i] = ((temp[0]<<24)^(temp[1]<<16)^(temp[2]<<8)^temp[3]);
                Plaintext2[i] = Plaintext1[i];
            }
            Plaintext2[2] ^= (Alpha << 24);
            Plaintext2[3] ^= (Alpha << 24);
            
            AES192(Plaintext1, Ciphertext1, Subkey1);
            AES192(Plaintext2, Ciphertext2, Subkey2);
            
            int OutputDiffS_5_1_0 = (((Ciphertext1[0]>>16)&(0xff)) ^ ((Ciphertext2[0]>>16)&(0xff)));
            
            CounterOfDistribution[OutputDiffS_5_1_0] += 1;
        }
        
        // Output the distribution of \Delta x_{5}^{S}[1,0]
        for (int i = 1; i < 256; i++)
        {
            fout<<CounterOfDistribution[i]<<" (" << (double)CounterOfDistribution[i]/DataRequirement << ")"<<"\t";
        }
        fout<<"\n";
        
        // Compute the Euclidean Distance between the distribution of the differences and the 255-dimensional vector (1/255, 1/255, ..., 1/255)
        double EuclideanDistance = 0;
        for (int i = 1; i < 256; i++)
        {
            EuclideanDistance += (((double)CounterOfDistribution[i]/DataRequirement) - ((double)(1/255.0))) * (((double)CounterOfDistribution[i]/DataRequirement) - ((double)(1/255.0)));
        }
        // Output the Euclidean Distance
        fouteuc<<EuclideanDistance<<"\n";
    }
    
    
    test_end = clock();
    cout <<"Runtime: " << (double)(test_end - test_start)/CLOCKS_PER_SEC << "s" << endl;
    fout.close();
    fouteuc.close();
    return 0;
}
