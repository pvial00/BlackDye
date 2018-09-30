#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>
#include "reddye_kdf.c"

int keylen = 32;
int k[32] = {0};
int j = 0;
int temp[32] = {0};
int last[32] = {0};
int next[32] = {0};
int sbox[] = { 135, 27, 224, 248, 245, 7, 231, 117, 120, 178, 156, 119, 132, 180, 102, 252, 4, 190, 112, 25, 61, 63, 122, 142, 198, 106, 159, 172, 18, 126, 24, 69, 188, 6, 37, 98, 246, 181, 101, 254, 36, 194, 100, 239, 40, 253, 204, 77, 60, 114, 1, 86, 16, 5, 94, 166, 157, 104, 250, 105, 116, 17, 113, 197, 217, 223, 240, 173, 0, 92, 234, 201, 247, 41, 108, 167, 48, 8, 54, 23, 220, 182, 127, 118, 204, 95, 53, 243, 241, 81, 136, 31, 50, 228, 88, 211, 144, 90, 139, 165, 91, 251, 97, 59, 56, 147, 45, 175, 249, 125, 26, 206, 176, 133, 184, 68, 213, 187, 32, 219, 191, 170, 129, 128, 244, 227, 103, 238, 19, 171, 207, 196, 130, 141, 151, 152, 235, 51, 89, 62, 153, 34, 179, 123, 169, 74, 73, 134, 15, 124, 35, 255, 174, 78, 29, 20, 115, 214, 75, 215, 183, 44, 87, 93, 222, 202, 43, 221, 39, 111, 99, 212, 158, 107, 3, 49, 163, 52, 12, 200, 57, 160, 42, 138, 146, 84, 64, 38, 203, 96, 10, 2, 46, 164, 161, 72, 28, 218, 55, 150, 71, 195, 192, 79, 83, 13, 121, 142, 193, 208, 232, 216, 210, 177, 131, 155, 189, 162, 76, 229, 66, 65, 242, 148, 14, 21, 70, 47, 233, 137, 225, 82, 9, 110, 209, 149, 236, 33, 186, 199, 154, 185, 230, 58, 80, 226, 140, 247, 30, 145, 11, 22, 85, 168, 67, 109 };

int sbox2[] = { 87, 160, 91, 184, 147, 40, 35, 81, 117, 119, 138, 195, 105, 101, 238, 229, 148, 99, 8, 247, 255, 13, 106, 82, 31, 221, 121, 222, 239, 183, 62, 243, 178, 83, 129, 2, 249, 211, 220, 80, 70, 225, 232, 12, 254, 69, 33, 179, 49, 146, 144, 53, 208, 107, 252, 166, 236, 122, 202, 108, 65, 100, 114, 135, 60, 191, 234, 50, 64, 214, 189, 30, 248, 84, 190, 15, 112, 250, 141, 42, 151, 231, 194, 157, 124, 36, 47, 132, 97, 14, 79, 54, 51, 9, 89, 201, 18, 0, 131, 128, 4, 127, 134, 23, 76, 120, 111, 59, 253, 29, 187, 139, 72, 181, 56, 45, 174, 11, 165, 200, 203, 230, 192, 41, 219, 34, 227, 67, 126, 10, 96, 142, 180, 228, 28, 205, 44, 93, 171, 17, 159, 155, 149, 48, 170, 115, 206, 235, 109, 216, 224, 43, 153, 25, 116, 223, 102, 150, 244, 237, 74, 16, 130, 240, 123, 1, 143, 196, 198, 38, 5, 68, 207, 110, 3, 209, 188, 161, 27, 32, 140, 57, 39, 21, 251, 104, 66, 46, 246, 167, 133, 241, 204, 156, 73, 177, 118, 90, 52, 86, 175, 77, 233, 103, 19, 58, 212, 164, 215, 95, 98, 24, 61, 88, 193, 37, 199, 92, 218, 182, 113, 217, 85, 172, 186, 173, 137, 226, 6, 168, 176, 154, 162, 26, 163, 158, 197, 169, 71, 242, 145, 136, 7, 20, 78, 63, 210, 94, 22, 125, 75, 245, 152, 55, 185, 213 };

int sbox2i[] = { 97, 165, 35, 174, 100, 170, 228, 242, 18, 93, 129, 117, 43, 21, 89, 75, 161, 139, 96, 204, 243, 183, 248, 103, 211, 153, 233, 178, 134, 109, 71, 24, 179, 46, 125, 6, 85, 215, 169, 182, 5, 123, 79, 151, 136, 115, 187, 86, 143, 48, 67, 92, 198, 51, 91, 253, 114, 181, 205, 107, 64, 212, 30, 245, 68, 60, 186, 127, 171, 45, 40, 238, 112, 194, 160, 250, 104, 201, 244, 90, 39, 7, 23, 33, 73, 222, 199, 0, 213, 94, 197, 2, 217, 137, 247, 209, 130, 88, 210, 17, 61, 13, 156, 203, 185, 12, 22, 53, 59, 148, 173, 106, 76, 220, 62, 145, 154, 8, 196, 9, 105, 26, 57, 164, 84, 249, 128, 101, 99, 34, 162, 98, 87, 190, 102, 63, 241, 226, 10, 111, 180, 78, 131, 166, 50, 240, 49, 4, 16, 142, 157, 80, 252, 152, 231, 141, 193, 83, 235, 140, 1, 177, 232, 234, 207, 118, 55, 189, 229, 237, 144, 138, 223, 225, 116, 200, 230, 195, 32, 47, 132, 113, 219, 29, 3, 254, 224, 110, 176, 70, 74, 65, 122, 214, 82, 11, 167, 236, 168, 216, 119, 95, 58, 120, 192, 135, 146, 172, 52, 175, 246, 37, 206, 255, 69, 208, 149, 221, 218, 124, 38, 25, 27, 155, 150, 41, 227, 126, 133, 15, 121, 81, 42, 202, 66, 147, 56, 159, 14, 28, 163, 191, 239, 31, 158, 251, 188, 19, 72, 36, 77, 184, 54, 108, 44, 20 };

void keysetup(unsigned char *key, unsigned char *nonce) {
    int c;
    for (c=0; c < strlen(key); c++) {
        k[c] = (k[c] + key[c]) & 0xff;
        j = (j + k[c]) & 0xff; }
    keylen = strlen(key);
    for (c = 0; c < 256; c++) {
        k[c % keylen] = (k[c % keylen] + j) & 0xff;
        j = (j + k[c % keylen]) & 0xff; }
    for (c = 0; c < strlen(nonce); c++) {
        k[c] = (k[c] + nonce[c]) & 0xff;
        j = (j + k[c]) & 0xff; }
    for (c = 0; c < keylen; c++) {
        last[c] = k[c]; }
    for (c = 0; c < 256; c++) {
        k[c % keylen] = (k[c % keylen] + j) % 256;
        j = (j + k[c % keylen]) & 0xff; }
}

void annihilate() {
    k[0] = (k[17] + k[15] + k[28] + 1) & 0xff;
    k[1] = (k[25] + k[23] + k[5]) & 0xff;
    k[2] = (k[27] + k[14] + k[16]) & 0xff;
    k[3] = (k[16] + k[29] + k[31]) & 0xff;
    k[4] = (k[26] + k[18] + k[4]) & 0xff;
    k[5] = (k[20] + k[3] + k[20]) & 0xff;
    k[6] = (k[28] + k[2] + k[1]) & 0xff;
    k[7] = (k[19] + k[20] + k[23]) & 0xff;
    k[8] = (k[12] + k[27] + k[11]) & 0xff;
    k[9] = (k[21] + k[28] + k[10]) & 0xff;
    k[10] = (k[3] + k[22] + k[26]) & 0xff;
    k[11] = (k[8] + k[4] + k[21]) & 0xff;
    k[12] = (k[18] + k[8] + k[25]) & 0xff;
    k[13] = (k[15] + k[11] + k[18]) & 0xff;
    k[14] = (k[9] + k[25] + k[24]) & 0xff;
    k[15] = (k[11] + k[0] + k[22]) & 0xff;
    k[16] = (k[14] + k[24] + k[7]) & 0xff;
    k[17] = (k[31] + k[16] + k[0]) & 0xff;
    k[18] = (k[10] + k[31] + k[15]) & 0xff;
    k[19] = (k[13] + k[7] + k[17]) & 0xff;
    k[20] = (k[24] + k[1] + k[3]) & 0xff;
    k[21] = (k[23] + k[19] + k[6]) & 0xff;
    k[22] = (k[30] + k[21] + k[30]) & 0xff;
    k[23] = (k[2] + k[9] + k[2]) & 0xff;
    k[24] = (k[29] + k[6] + k[27]) & 0xff;
    k[25] = (k[0] + k[17] + k[29]) & 0xff;
    k[26] = (k[6] + k[5] + k[13]) & 0xff;
    k[27] = (k[1] + k[12] + k[8]) & 0xff;
    k[28] = (k[7] + k[26] + k[9]) & 0xff;
    k[29] = (k[5] + k[30] + k[14]) & 0xff;
    k[30] = (k[22] + k[13] + k[12]) & 0xff;
    k[31] = (k[4] + k[10] + k[19]) & 0xff;
}

void crush(int a, int b, int c, int d, int e, int f, int g, int h) {
    k[a] = (((k[a] + k[b]) ^ k[e]) ^ k[f]);
    k[b] = (((k[c] ^ k[d]) + k[g]) & 0xff) ^ k[h];
    k[c] = (((k[b] + k[c]) ^ k[f]) ^ k[g]);
    k[d] = (((k[d] ^ k[e]) + k[h]) & 0xff)  ^ k[a];
    k[e] = (((k[e] + k[a]) ^ k[b]) ^ k[c]);
    k[f] = (((k[f] ^ k[g]) + k[c]) & 0xff) ^ k[d];
    k[g] = (((k[g] + k[h]) ^ k[a]) ^ k[b]);
    k[h] = (((k[h] ^ k[b]) + k[d]) & 0xff) ^ k[e];
}

void usage() {
    printf("blackdye-cbc <encrypt/decrypt> <input file> <output file> <password>\n");
    exit(0);
}

int main(int argc, char *argv[]) {
    FILE *infile, *outfile, *randfile;
    char *in, *out, *mode;
    unsigned char *data = NULL;
    unsigned char *buf = NULL;
    int x = 0;
    int ch;
    int buflen = 32;
    int bsize;
    unsigned char *key[keylen];
    unsigned char *password;
    int nonce_length = 16;
    unsigned char nonce[nonce_length];
    unsigned char block[buflen];
    if (argc != 5) {
        usage();
    }
    mode = argv[1];
    in = argv[2];
    out = argv[3];
    password = argv[4];
    infile = fopen(in, "rb");
    fseek(infile, 0, SEEK_END);
    long fsize = ftell(infile);
    fseek(infile, 0, SEEK_SET);
    outfile = fopen(out, "wb");
    int c = 0;
    int b = 0;
    int m = 0;
    int r;
    int rounds = 1;
    if (strcmp(mode, "encrypt") == 0) {
        long blocks = fsize / buflen;
        long extra = fsize % buflen;
        if (extra != 0) {
            blocks += 1;
        }
        randfile = fopen("/dev/urandom", "rb");
        fread(&nonce, nonce_length, 1, randfile);
        fclose(randfile);
        fwrite(nonce, 1, nonce_length, outfile);
	unsigned char salt[] = "BlackDyeCipher";
	int iter = 10000;
	kdf(password, key, salt, iter, keylen);
        keysetup(key, nonce);
        for (int d = 0; d < blocks; d++) {
	    for (m = 0; m < keylen; m++) {
	        temp[m] = k[m]; }
	    crush(11, 14, 13, 0, 5, 25, 30, 19);
	    crush(31, 8, 27, 22, 6, 10, 20, 12);
	    crush(4, 7, 9, 24, 26, 16, 1, 21);
	    crush(3, 2, 29, 18, 23, 17, 15, 28);
	    annihilate();
	    for (m = 0; m < keylen; m++) {
	        k[m] = (k[m] + temp[m]) & 0xff;
	    }
            fread(block, buflen, 1, infile);
            if (d == (blocks - 1) && extra != 0) {
		for (m = extra; m < keylen; m++) {
		    block[m] = (keylen - extra);
		}
            }
            bsize = sizeof(block);
            for (b = 0; b < bsize; b++) {
                block[b] = block[b] ^ last[b];
            }
            for (b = 0; b < bsize; b++) {
                block[b] = block[b] ^ k[b];
            }
            for (b = 0; b < bsize; b++) {
		block[b] = sbox2[block[b]];
                block[b] = block[b] ^ sbox[k[b]];
                block[b] = block[b] ^ sbox2[temp[b]];
                block[b] = block[b] ^ sbox2[k[b]];
            }
	    for (m = 0; m < bsize; m++) {
	        last[m] = block[m]; }
            fwrite(block, 1, bsize, outfile);
        }
    }
    else if (strcmp(mode, "decrypt") == 0) {
        long blocks = (fsize - nonce_length) / buflen;
        long extra = (fsize - nonce_length) % buflen;
        if (extra != 0) {
            blocks += 1;
        }
        fread(nonce, 1, nonce_length, infile);
	unsigned char salt[] = "BlackDyeCipher";
	int iter = 10000;
	kdf(password, key, salt, iter, keylen);
        keysetup(key, nonce);
        for (int d = 0; d < blocks; d++) {
	    for (m = 0; m < keylen; m++) {
	        temp[m] = k[m]; }
	    crush(11, 14, 13, 0, 5, 25, 30, 19);
	    crush(31, 8, 27, 22, 6, 10, 20, 12);
	    crush(4, 7, 9, 24, 26, 16, 1, 21);
	    crush(3, 2, 29, 18, 23, 17, 15, 28);
	    annihilate();
	    for (m = 0; m < keylen; m++) {
	        k[m] = (k[m] + temp[m]) & 0xff;
	    }
            fread(block, buflen, 1, infile);
            if ((d == (blocks - 1)) && extra != 0) {
                bsize = extra;
            }
            bsize = sizeof(block);
	    for (m = 0; m < bsize; m++) {
	        next[m] = block[m]; }
            for (b = 0; b < bsize; b++) {
                block[b] = block[b] ^ sbox2[k[b]];
                block[b] = block[b] ^ sbox2[temp[b]];
                block[b] = block[b] ^ sbox[k[b]];
		block[b] = sbox2i[block[b]];
            }
            for (b = 0; b < bsize; b++) {
                block[b] = block[b] ^ k[b];
            }
            for (b = 0; b < bsize; b++) {
                block[b] = block[b] ^ last[b];
            }
	    for (m = 0; m < bsize; m++) {
	        last[m] = next[m]; }
            if (d == (blocks - 1)) {
		int count = 0;
		int padcheck = block[31];
		int g = 31;
		for (m = 0; m < padcheck; m++) {
		    if ((int)block[g] == padcheck) {
		        count += 1;
		    }
		    g = (g - 1);
		}
		if (count == padcheck) {
		    bsize = (keylen - count);
		}
            }
            fwrite(block, 1, bsize, outfile);
        }
    }
    fclose(infile);
    fclose(outfile);
    return 0;
}
