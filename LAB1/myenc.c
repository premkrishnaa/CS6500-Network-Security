#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/sha.h>
#include <time.h>

unsigned char* sha256func(char *pass){
  unsigned char *key = (unsigned char*)malloc(SHA256_DIGEST_LENGTH*sizeof(unsigned char));
  SHA256_CTX sha;
  SHA256_Init(&sha);
  SHA256_Update(&sha, pass, strlen(pass));
  SHA256_Final(key, &sha);
  return key;
}

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext, char *mode, int keySize)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(strcmp(mode,"CBC")==0){
    if(keySize==192){
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
        handleErrors();      
    }
    else{
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();            
    }
  }
  else if(strcmp(mode,"ECB")==0){
    if(keySize==192){
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, iv))
        handleErrors();      
    }
    else{
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        handleErrors();            
    }    
  }
  else if(strcmp(mode,"CTR")==0){
    if(keySize==192){
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_192_ctr(), NULL, key, iv))
        handleErrors();      
    }
    else{
      if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();            
    }       
  }

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext, char *mode, int keySize)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(strcmp(mode,"CBC")==0){
    if(keySize==192){
      if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_cbc(), NULL, key, iv))
        handleErrors();
    }
    else{
      if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_cbc(), NULL, key, iv))
        handleErrors();
    }
  }
  else if(strcmp(mode,"ECB")==0){
    if(keySize==192){
      if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_ecb(), NULL, key, iv))
        handleErrors();      
    }
    else{
      if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
        handleErrors();            
    }    
  }
  else if(strcmp(mode,"CTR")==0){
    if(keySize==192){
      if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_192_ctr(), NULL, key, iv))
        handleErrors();      
    }
    else{
      if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ctr(), NULL, key, iv))
        handleErrors();            
    }        
  }

  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int des_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext, char *mode, int keySize)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(strcmp(mode,"CBC")==0){
    if(1 != EVP_EncryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv))
      handleErrors();    
  }
  else if(strcmp(mode,"ECB")==0){
    if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ecb(), NULL, key, iv))
      handleErrors();    
  }

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int des_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext, char *mode, int keySize)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(strcmp(mode,"CBC")==0){
    if(1 != EVP_DecryptInit_ex(ctx, EVP_des_cbc(), NULL, key, iv))
      handleErrors();    
  }
  else if(strcmp(mode,"ECB")==0){
    if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ecb(), NULL, key, iv))
      handleErrors();    
  }

  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int des3_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext, char *mode, int keySize)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(strcmp(mode,"CBC")==0){
    if(keySize==112){
      if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv))
        handleErrors();      
    }
    else{
      if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv))
        handleErrors();            
    }
  }
  else if(strcmp(mode,"ECB")==0){
    if(keySize==112){
      if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede(), NULL, key, iv))
        handleErrors();      
    }
    else{
      if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3(), NULL, key, iv))
        handleErrors();            
    }    
  }

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int des3_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext, char *mode, int keySize)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(strcmp(mode,"CBC")==0){
    if(keySize==112){
      if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede_cbc(), NULL, key, iv))
        handleErrors();      
    }
    else{
      if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3_cbc(), NULL, key, iv))
        handleErrors();            
    }
  }
  else if(strcmp(mode,"ECB")==0){
    if(keySize==112){
      if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede(), NULL, key, iv))
        handleErrors();      
    }
    else{
      if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3(), NULL, key, iv))
        handleErrors();            
    }    
  }

  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


int main(int argc, char *argv[]){

	char op[5]="", alg[5]="", mode[5]="", input[100]="", output[100]="";
	int i=1, keySize=0;
	clock_t begin, end;
	double spent;
  unsigned char *plaintext_fin = (unsigned char*)malloc(110000*sizeof(char));
  unsigned char *ciphertext = (unsigned char*)malloc(110000*sizeof(char));
  unsigned char *decryptedtext = (unsigned char*)malloc(110000*sizeof(char));

	/* Get the command line input options */

	while(i<argc){
		if(strcmp("-p",argv[i])==0){
			i++;
			if(i>=argc){
				printf("Incorrect command line!\n");
				exit(0);
			}
			strcpy(op,argv[i]);
			if(strcmp(op,"Enc")!=0 && strcmp(op,"Dec")!=0){
				printf("Invalid choice of operation\n");
				exit(0);
			}
		}
		else if(strcmp("-a",argv[i])==0){
			i++;
			if(i>=argc){
				printf("Incorrect command line!\n");
				exit(0);
			}
			strcpy(alg,argv[i]);
			if(strcmp(alg,"AES")!=0 && strcmp(alg,"DES")!=0 && strcmp(alg,"3DES")!=0){
				printf("Invalid choice of algorithm\n");
				exit(0);
			}
		}
		else if(strcmp("-m",argv[i])==0){
			i++;
			if(i>=argc){
				printf("Incorrect command line!\n");
				exit(0);
			}
			strcpy(mode,argv[i]);
			if(strcmp(mode,"CBC")!=0 && strcmp(mode,"ECB")!=0 && strcmp(mode,"CTR")!=0){
				printf("Invalid choice of mode\n");
				exit(0);
			}
		}
		else if(strcmp("-k",argv[i])==0){
			i++;
			if(i>=argc){
				printf("Incorrect command line!\n");
				exit(0);
			}
			char temp[10];
			strcpy(temp,argv[i]);
			keySize = atoi(temp);
			if(keySize!=56 && keySize!=112 && keySize!=168 && keySize!=128 && keySize!=192){
				printf("Invalid choice of keySize\n");
				exit(0);
			}
		}		
		else if(strcmp("-i",argv[i])==0){
			i++;
			if(i>=argc){
				printf("Incorrect command line!\n");
				exit(0);
			}
			strcpy(input,argv[i]);
		}
		else if(strcmp("-o",argv[i])==0){
			i++;
			if(i>=argc){
				printf("Incorrect command line!\n");
				exit(0);
			}
			strcpy(output,argv[i]);
		}
		else{
			printf("Incorrect command line!\n");
			exit(0);
		}

		i++;
	}

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);

	FILE *f;
	int ciphertext_len, decryptedtext_len;
  unsigned char* key56=(unsigned char*)malloc(8);
  unsigned char* key112=(unsigned char*)malloc(15);
  unsigned char* key168=(unsigned char*)malloc(22);  
  unsigned char* key128=(unsigned char*)malloc(17);  
	unsigned char* key192=(unsigned char*)malloc(25);
  unsigned char* iv64=(unsigned char*)malloc(9);
  unsigned char* iv128=(unsigned char*)malloc(17);


  unsigned char *passphrase = (unsigned char*)"iitmcse2017";
  unsigned char *hash = sha256func(passphrase);
  // printf("%ld\n", strlen(hash));
  strncpy(key56,hash,7);
  key56[7] = '\0';
  strncpy(key112,hash,14);
  key112[14] = '\0';
  strncpy(key168,hash,21);
  key168[21] = '\0';
  strncpy(key128,hash,16);
  key128[16] = '\0';
  strncpy(key192,hash,24);
  key192[24] = '\0';
  strncpy(iv64,&hash[24],8);
  iv64[8] = '\0';
  strncpy(iv128,&hash[16],16);
  iv128[16] = '\0';
  // printf("%ld %ld %ld %ld %ld %ld %ld\n", strlen(key56), strlen(key112), strlen(key168), strlen(key128), strlen(key192), strlen(iv64), strlen(iv128));

  if(strcmp(op,"Enc")==0){
    f = fopen(input,"r");
    strcpy(plaintext_fin,"");
    unsigned char plaintext[100];
    int ct = 0;
    while(!feof(f)){
      fgets(plaintext,100,f);
      ct += strlen(plaintext);
      strcat(plaintext_fin,plaintext);
      if(feof(f))
        break;
    }
    fclose(f);
    begin = clock();
    if(strcmp("AES",alg)==0){
      if(keySize == 128){
        ciphertext_len = aes_encrypt(plaintext_fin, strlen((char *)plaintext_fin), key128, iv128, ciphertext, mode, keySize);
      }
      else{
        ciphertext_len = aes_encrypt(plaintext_fin, strlen((char *)plaintext_fin), key192, iv128, ciphertext, mode, keySize);   
      }     
    }
    else if(strcmp("DES",alg)==0){
      ciphertext_len = des_encrypt(plaintext_fin, strlen((char *)plaintext_fin), key56, iv64, ciphertext, mode, keySize);              
    }
    else{
      if(keySize == 112){
        ciphertext_len = des3_encrypt(plaintext_fin, strlen((char *)plaintext_fin), key112, iv64, ciphertext, mode, keySize);
      }
      else{
        ciphertext_len = des3_encrypt(plaintext_fin, strlen((char *)plaintext_fin), key168, iv64, ciphertext, mode, keySize);        
      }
    }
    end = clock();
    spent = 1000000 * (double) (end-begin) / CLOCKS_PER_SEC;
    printf("%s %s %s %d : %f\n",input,alg,mode,keySize,spent); 
    // printf("%d\n", ciphertext_len);

    f = fopen(output,"wb");
    fwrite(ciphertext,1,ciphertext_len,f);
    fclose(f);
  }
  else if(strcmp(op,"Dec")==0){
    f = fopen(input,"rb");
    fseek(f,0L,2);
    long sz = ftell(f);
    // printf("%ld\n", sz);
    rewind(f);
    fread(ciphertext,1,sz,f);
    fclose(f);
    ciphertext_len = sz;
    begin = clock();
    if(strcmp("AES",alg)==0){
      if(keySize == 128){
        decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, key128, iv128, decryptedtext, mode, keySize);
      }
      else{
        decryptedtext_len = aes_decrypt(ciphertext, ciphertext_len, key192, iv128, decryptedtext, mode, keySize);
      }     
    }
    else if(strcmp("DES",alg)==0){
      decryptedtext_len = des_decrypt(ciphertext, ciphertext_len, key56, iv64, decryptedtext, mode, keySize);
    }
    else{
      if(keySize == 112){
        decryptedtext_len = des3_decrypt(ciphertext, ciphertext_len, key112, iv64, decryptedtext, mode, keySize);
      }
      else{
        decryptedtext_len = des3_decrypt(ciphertext, ciphertext_len, key168, iv64, decryptedtext, mode, keySize);
      }
    }
    end = clock();
    decryptedtext[decryptedtext_len] = '\0';
    spent = 1000000 * (double) (end-begin) / CLOCKS_PER_SEC;     
  	printf("%s %s %d : %f\n",alg,mode,keySize,spent);
    f = fopen(output,"w");
    fputs(decryptedtext, f);
    fclose(f);    
  }

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();
  free(plaintext_fin);
  free(ciphertext);
  free(decryptedtext);
	return 0;
}