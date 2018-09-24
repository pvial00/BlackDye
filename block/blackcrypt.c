#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int keylen = 32;
//int k[] = { 83, 41, 201, 107, 175, 150, 205, 119, 188, 140, 154, 210, 72, 30, 194, 189, 130, 9, 134, 201, 11, 145, 29, 179, 192, 0, 125, 209, 184, 132, 207, 219 };
int k[32] = {0};
int j = 0;
int temp[32] = {0};
int last[32] = {0};
int next[32] = {0};
int sbox[] = { 135, 27, 224, 248, 245, 7, 231, 117, 120, 178, 156, 119, 132, 180, 102, 252, 4, 190, 112, 25, 61, 63, 122, 142, 198, 106, 159, 172, 18, 126, 24, 69, 188, 6, 37, 98, 246, 181, 101, 254, 36, 194, 100, 239, 40, 253, 204, 77, 60, 114, 1, 86, 16, 5, 94, 166, 157, 104, 250, 105, 116, 17, 113, 197, 217, 223, 240, 173, 0, 92, 234, 201, 247, 41, 108, 167, 48, 8, 54, 23, 220, 182, 127, 118, 204, 95, 53, 243, 241, 81, 136, 31, 50, 228, 88, 211, 144, 90, 139, 165, 91, 251, 97, 59, 56, 147, 45, 175, 249, 125, 26, 206, 176, 133, 184, 68, 213, 187, 32, 219, 191, 170, 129, 128, 244, 227, 103, 238, 19, 171, 207, 196, 130, 141, 151, 152, 235, 51, 89, 62, 153, 34, 179, 123, 169, 74, 73, 134, 15, 124, 35, 255, 174, 78, 29, 20, 115, 214, 75, 215, 183, 44, 87, 93, 222, 202, 43, 221, 39, 111, 99, 212, 158, 107, 3, 49, 163, 52, 12, 200, 57, 160, 42, 138, 146, 84, 64, 38, 203, 96, 10, 2, 46, 164, 161, 72, 28, 218, 55, 150, 71, 195, 192, 79, 83, 13, 121, 142, 193, 208, 232, 216, 210, 177, 131, 155, 189, 162, 76, 229, 66, 65, 242, 148, 14, 21, 70, 47, 233, 137, 225, 82, 9, 110, 209, 149, 236, 33, 186, 199, 154, 185, 230, 58, 80, 226, 140, 247, 30, 145, 11, 22, 85, 168, 67, 109 };

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

void crush(int a, int b, int c, int d) {
    k[a] = (k[a] + k[b]) & 0xff;
    k[b] = (k[b] + k[c]) & 0xff;
    k[c] = (k[d] + k[a]) & 0xff;
    k[d] = (k[b] + k[c]) & 0xff;
    k[d] = (k[a] + k[d]) & 0xff;
    k[b] = (k[c] + k[b]) & 0xff;
    k[a] = (k[a] + k[c]) & 0xff;
    k[c] = (k[d] + k[b]) & 0xff;
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
	unsigned char salt[] = "RedDyeCipher";
	int iter = 10000;
	PKCS5_PBKDF2_HMAC (password, sizeof(password) -1, salt, sizeof(salt)-1, iter, EVP_sha1(), keylen, key);
        keysetup(key, nonce);
        for (int d = 0; d < blocks; d++) {
	    for (m = 0; m < keylen; m++) {
	        temp[m] = k[m]; }
	    annihilate();
	    crush(14, 17, 22, 30);
	    annihilate();
	    crush(12, 7, 2, 8);
	    annihilate();
	    crush(24, 18, 9, 31);
	    annihilate();
	    crush(3, 15, 19, 28);
	    annihilate();
	    crush(23, 27, 29, 26);
	    annihilate();
	    crush(10, 6, 25, 16);
	    annihilate();
	    crush(4, 21, 11, 0);
	    annihilate();
	    crush(13, 20, 5, 1);
	    annihilate();
	    for (m = 0; m < keylen; m++) {
	        k[m] = (k[m] + temp[m] + c) & 0xff;
		c = (c + 1) & 0xff;
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
                block[b] = block[b] ^ sbox[k[b]];
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
	unsigned char salt[] = "RedDyeCipher";
	int iter = 10000;
	PKCS5_PBKDF2_HMAC (password, sizeof(password) -1, salt, sizeof(salt)-1, iter, EVP_sha1(), keylen, key);
        keysetup(key, nonce);
        for (int d = 0; d < blocks; d++) {
	    for (m = 0; m < keylen; m++) {
	        temp[m] = k[m]; }
	    annihilate();
	    crush(14, 17, 22, 30);
	    annihilate();
	    crush(12, 7, 2, 8);
	    annihilate();
	    crush(24, 18, 9, 31);
	    annihilate();
	    crush(3, 15, 19, 28);
	    annihilate();
	    crush(23, 27, 29, 26);
	    annihilate();
	    crush(10, 6, 25, 16);
	    annihilate();
	    crush(4, 21, 11, 0);
	    annihilate();
	    crush(13, 20, 5, 1);
	    annihilate();
	    for (m = 0; m < keylen; m++) {
	        k[m] = (k[m] + temp[m] + c) & 0xff;
		c = (c + 1) & 0xff;
	    }
            fread(block, buflen, 1, infile);
            if ((d == (blocks - 1)) && extra != 0) {
                bsize = extra;
            }
            bsize = sizeof(block);
	    for (m = 0; m < bsize; m++) {
	        next[m] = block[m]; }
            for (b = 0; b < bsize; b++) {
                block[b] = block[b] ^ sbox[k[b]];
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
