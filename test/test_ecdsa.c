/* Copyright 2014, Kenneth MacKay. Licensed under the BSD 2-clause license. */

#include "../uECC.h"

#include <stdio.h>
#include <string.h>
#include <time.h>
int main() {
    int i, c;
    uint8_t private[32] = {0};
    uint8_t public[64] = {0};
    uint8_t hash[32] = {0};
    uint8_t sig[64] = {0};

	clock_t begin,end;
	double time_spent;
	
    const struct uECC_Curve_t * curves[5];
    int num_curves = 0;
#if uECC_SUPPORTS_secp160r1
    curves[num_curves++] = uECC_secp160r1();
#endif
#if uECC_SUPPORTS_secp192r1
    curves[num_curves++] = uECC_secp192r1();
#endif
#if uECC_SUPPORTS_secp224r1
    curves[num_curves++] = uECC_secp224r1();
#endif
#if uECC_SUPPORTS_secp256r1
    curves[num_curves++] = uECC_secp256r1();
#endif
#if uECC_SUPPORTS_secp256k1
    curves[num_curves++] = uECC_secp256k1();
#endif

	begin = clock();
	
	/* here, do your time-consuming job */
    //printf("Testing 256 signatures\n");
    if (!uECC_make_key(public, private, curves[c])) {
                printf("uECC_make_key() failed\n");
                return 1;
            }
	memcpy(hash, public, sizeof(hash));
	
    for (c = 0; c < num_curves; ++c) {
        for (i = 0; i < 1000; ++i) {
        //    printf(".");
          //  fflush(stdout);

            
            
            
            if (!uECC_sign(private, hash, sizeof(hash), sig, curves[c])) {
                printf("uECC_sign() failed\n");
                return 1;
            }

    		/*  
    		if (!uECC_verify(public, hash, sizeof(hash), sig, curves[c])) {
                printf("uECC_verify() failed\n");
                return 1;
            }*/
        }
       // printf("\n");
    }
	
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("\nExecution time for signing :%f",time_spent);


	begin = clock();
	
	/* here, do your time-consuming job */
    //printf("Testing 256 signatures\n");
    if (!uECC_make_key(public, private, curves[c])) {
                printf("uECC_make_key() failed\n");
                return 1;
            }
	memcpy(hash, public, sizeof(hash));
	if (!uECC_sign(private, hash, sizeof(hash), sig, curves[c])) {
                printf("uECC_sign() failed\n");
                return 1;
            }
			
	
    for (c = 0; c < num_curves; ++c) {
        for (i = 0; i < 1000; ++i) {
        //    printf(".");
          //  fflush(stdout);

            
            

		
    		  
    		if (!uECC_verify(public, hash, sizeof(hash), sig, curves[c])) {
                printf("uECC_verify() failed\n");
                return 1;
            }
        }
       // printf("\n");
    }
	
	end = clock();
	time_spent = (double)(end - begin) / CLOCKS_PER_SEC;
	printf("\nExecution time for verification :%f",time_spent);

	    
    return 0;
}
