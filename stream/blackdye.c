#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/evp.h>

int keylen = 32;
//int k[] = { 83, 41, 201, 107, 175, 150, 205, 119, 188, 140, 154, 210, 72, 30, 194, 189, 130, 9, 134, 201, 11, 145, 29, 179, 192, 0, 125, 209, 184, 132, 207, 219 };
int k[32] = {0};
int j = 0;
int temp[32] = {0};

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
    printf("blackdye <encrypt/decrypt> <input file> <output file> <password>\n");
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
            bsize = sizeof(block);
            for (b = 0; b < bsize; b++) {
                block[b] = block[b] ^ k[b];
            }
            if (d == (blocks - 1) && extra != 0) {
                bsize = extra;
            }
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
            bsize = sizeof(block);
            for (b = 0; b < bsize; b++) {
                block[b] = block[b] ^ k[b];
            }
            if ((d == (blocks - 1)) && extra != 0) {
                bsize = extra;
            }
            fwrite(block, 1, bsize, outfile);
        }
    }
    fclose(infile);
    fclose(outfile);
    return 0;
}
