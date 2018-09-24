# BlackDye Block Cipher

High speed block cipher - 256 bit

BlackDye aka Annihilation is an experimental block cipher that achieves maximum security through annihilation and crush functions.  There are 9 total annihilation calls and 8 crush calls.  This is equivalent to about a 10 round block cipher function as the 8 crush calls is considered one whole round.

The cipher starts by initializing an array k[] that is 256 bits wide.  Blackdye always operates on 256 bits of data at a time.  An initialization or nonce is combined and out of this is generated a private IV.  This private IV is used as the CBC primer.  Round function is k[] is combined with ciphertext block.  There is additionally an 8 bit k[] dependant substitution box that must be beat.

# Usage:

blackdye-cbc encrypt infile outfile password

blackdye-cbc decrypt infile outfile password

