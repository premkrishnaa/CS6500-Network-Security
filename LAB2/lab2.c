#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <openssl/conf.h>
#include <openssl/evp.h>
#include <openssl/err.h>
#include <openssl/buffer.h>
#include <openssl/sha.h>
#include <openssl/bio.h>
#include <openssl/rsa.h>
#include <openssl/pem.h>
#include <openssl/blowfish.h>
#include <openssl/rand.h>
#include <time.h>
#include <assert.h>
#include <stdlib.h>

void handleErrors(void)
{
  ERR_print_errors_fp(stderr);
  abort();
}

int B64enc(const unsigned char* msg, size_t len, char** enctext) {
  BUF_MEM *msgPtr;
  BIO *bio;
  BIO *encB64;

  encB64 = BIO_new(BIO_f_base64());
  bio = BIO_new(BIO_s_mem());
  bio = BIO_push(encB64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  BIO_write(bio, msg, len);
  BIO_flush(bio);
  BIO_get_mem_ptr(bio, &msgPtr);
  BIO_set_close(bio, BIO_NOCLOSE);

  *enctext = (char*) malloc((msgPtr->length + 1) * sizeof(char));
  memcpy(*enctext, msgPtr->data, msgPtr->length);
  (*enctext)[msgPtr->length] = '\0';

  BIO_free_all(bio);

  return 0;
}


int B64dec(char* enctext, unsigned char** decodedText, size_t* len) {
  BIO *bio;
  BIO *encB64;

  int l = strlen(enctext);
  *decodedText = (unsigned char*)malloc(l + 1);
  (*decodedText)[l] = '\0';

  bio = BIO_new_mem_buf(enctext, -1);
  encB64 = BIO_new(BIO_f_base64());
  bio = BIO_push(encB64, bio);

  BIO_set_flags(bio, BIO_FLAGS_BASE64_NO_NL);
  *len = BIO_read(bio, *decodedText, strlen(enctext));
  BIO_free_all(bio);

  return 0;
}


unsigned char* sha1func(char *pass){
  unsigned char *hashfinal = (unsigned char*)malloc(SHA_DIGEST_LENGTH*sizeof(unsigned char));
  SHA_CTX sha;
  SHA1_Init(&sha);
  SHA1_Update(&sha, pass, strlen(pass));
  SHA1_Final(hashfinal, &sha);
  return hashfinal;
}

unsigned char* sha256func(char *pass){
  unsigned char *hashfinal = (unsigned char*)malloc(SHA256_DIGEST_LENGTH*sizeof(unsigned char));
  SHA256_CTX sha;
  SHA256_Init(&sha);
  SHA256_Update(&sha, pass, strlen(pass));
  SHA256_Final(hashfinal, &sha);
  return hashfinal;
}

int aes_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_EncryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
    handleErrors();            

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int aes_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_DecryptInit_ex(ctx, EVP_aes_128_ecb(), NULL, key, iv))
    handleErrors();            

  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}

int bf_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_EncryptInit_ex(ctx, EVP_bf_ecb(), NULL, key, iv))
    handleErrors();            

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int bf_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_DecryptInit_ex(ctx, EVP_bf_ecb(), NULL, key, iv))
    handleErrors();            

  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;

  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return plaintext_len;
}


int des3_encrypt(unsigned char *plaintext, int plaintext_len, unsigned char *key,
  unsigned char *iv, unsigned char *ciphertext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int ciphertext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_EncryptInit_ex(ctx, EVP_des_ede3(), NULL, key, iv))
    handleErrors();            

  if(1 != EVP_EncryptUpdate(ctx, ciphertext, &len, plaintext, plaintext_len))
    handleErrors();
  ciphertext_len = len;

  if(1 != EVP_EncryptFinal_ex(ctx, ciphertext + len, &len)) handleErrors();
  ciphertext_len += len;
  EVP_CIPHER_CTX_free(ctx);

  return ciphertext_len;
}

int des3_decrypt(unsigned char *ciphertext, int ciphertext_len, unsigned char *key,
  unsigned char *iv, unsigned char *plaintext)
{
  EVP_CIPHER_CTX *ctx;
  int len;
  int plaintext_len;

  if(!(ctx = EVP_CIPHER_CTX_new())) handleErrors();

  if(1 != EVP_DecryptInit_ex(ctx, EVP_des_ede3(), NULL, key, iv))
    handleErrors();            

  if(1 != EVP_DecryptUpdate(ctx, plaintext, &len, ciphertext, ciphertext_len))
    handleErrors();
  plaintext_len = len;
  plaintext[plaintext_len] = '\0';
  if(1 != EVP_DecryptFinal_ex(ctx, plaintext + len, &len)) handleErrors();
  plaintext_len += len;
  EVP_CIPHER_CTX_free(ctx);
  return plaintext_len;
}


int main(int argc, char const *argv[])
{
	char userlist[100];
	char secType[20], sender[100], receiver[100], emailInput[100];
	char emailOutput[100], digestAlg[10], encAlg[20];
	char plainTextOutput[100], secureInput[100]; 

	ERR_load_crypto_strings();
	OpenSSL_add_all_algorithms();
	OPENSSL_config(NULL);


	if(strcmp(argv[1],"CreateKeys")==0){
		strcpy(userlist,argv[2]);
		FILE *f = fopen(userlist,"r");
		char name[100];
		while(!feof(f)){
			fgets(name,100,f);
			if(!feof(f))
				name[strlen(name)-1] = '\0';
			RSA *temp;
			do{
				temp = RSA_generate_key(2048,RSA_3,NULL,NULL);
			}while(RSA_check_key(temp)!=1);
			
			char writePriv[100], writePub[100];
			strcpy(writePub,name);
			strcpy(writePriv,name);
			strcat(writePub,"_pub.txt");
			strcat(writePriv,"_priv.txt");
			FILE *fo1 = fopen(writePub,"w");
			FILE *fo2 = fopen(writePriv,"w");
			if(PEM_write_RSA_PUBKEY(fo1,temp)==0)
				printf("Error!\n");
			if(PEM_write_RSAPrivateKey(fo2,temp,NULL,"cseiitm",7,NULL,NULL)==0)
				printf("Error!\n");
			RSA_free(temp);
			fclose(fo1);
			fclose(fo2);
			if(feof(f))
				break;
		}
		fclose(f);
	}
	else if(strcmp(argv[1],"CreateMail")==0){
		if(argc < 9){
			printf("Error in command line input\n");
			exit(0);			
		}
		strcpy(secType,argv[2]);
		strcpy(sender,argv[3]);
		strcpy(receiver,argv[4]);
		strcpy(emailInput,argv[5]);
		strcpy(emailOutput,argv[6]);
		strcpy(digestAlg,argv[7]);
		strcpy(encAlg,argv[8]);
		if(strcmp(secType,"CONF")!=0 && strcmp(secType,"AUIN")!=0 && strcmp(secType,"COAI")!=0){
			printf("Invalid SecType\n");
			exit(0);
		}
		if(strcmp(digestAlg,"sha256")!=0 && strcmp(digestAlg,"sha1")!=0){
			printf("Invalid Digest Algorithm\n");
			exit(0);
		}
		if(strcmp(encAlg,"bf-ecb")!=0 && strcmp(encAlg,"des3")!=0 && strcmp(encAlg,"aes-128-ecb")!=0){
			printf("Invalid Encryption Algorithm\n");
			exit(0);
		}

	    FILE *f = fopen(emailInput,"rb");
		int ciphertext_len;
		char *ciphertext_encoded;
		fseek(f,0L,2);
		long sz = ftell(f);
		unsigned char *plaintext = (unsigned char*)malloc(sz+1);
		unsigned char *ciphertext = (unsigned char*)malloc(2*sz);		
		rewind(f);
		fread(plaintext,1,sz,f);
		plaintext[sz] = '\0';	    
	    fclose(f);

		if(strcmp(secType,"CONF")==0){
			char *pubKeyFile = (char *)malloc(100);
			strcpy(pubKeyFile,receiver);
			strcat(pubKeyFile,"_pub.txt");
			printf("%s\n", pubKeyFile);

			if(strcmp(encAlg,"aes-128-ecb")==0){
				printf("aes\n");
				unsigned char* key = (unsigned char*)malloc(16);
				char* iv = (char*)malloc(16);
				int success = RAND_bytes(key, sizeof(key));
				unsigned long err = ERR_get_error();
				if(success != 1)
					handleErrors();
				success = RAND_bytes(iv, sizeof(iv));
				err = ERR_get_error();
				if(success != 1)
					handleErrors();

				f = fopen(pubKeyFile, "r");
				if(f==NULL){
					printf("Receiver public key does not exist!\n");
					exit(0);
				}
				RSA *pubKey;
				pubKey = PEM_read_RSA_PUBKEY(f,NULL,NULL,"dummy");
				fclose(f);
				long largest = RSA_size(pubKey);
				unsigned char* key_encrypted = (unsigned char*)malloc(largest);
				long encSize = RSA_public_encrypt(16,key,key_encrypted,pubKey,RSA_PKCS1_PADDING);
				printf("%d\n", encSize);
				if(encSize==-1){
					printf("Error, aborting!\n");
					exit(0);
				}

				char *key_encoded;
				B64enc(key_encrypted, encSize, &key_encoded);
			    f = fopen(emailOutput,"wb");
			    fwrite(key_encoded,1,strlen(key_encoded),f);
			    fwrite("\n",1,1,f);			    
			    fclose(f);		
		        ciphertext_len = aes_encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);	
		        B64enc(ciphertext, ciphertext_len, &ciphertext_encoded);		
		        free(key_encrypted);	
			}
			else if(strcmp(encAlg,"des3")==0){
				printf("des3\n");
				unsigned char* key = (unsigned char*)malloc(24);
				char* iv = (char*)malloc(8);
				int success = RAND_bytes(key, sizeof(key));
				unsigned long err = ERR_get_error();
				if(success != 1)
					handleErrors();
				success = RAND_bytes(iv, sizeof(iv));
				err = ERR_get_error();
				if(success != 1)
					handleErrors();

				f = fopen(pubKeyFile, "r");
				if(f==NULL){
					printf("Receiver public key does not exist!\n");
					exit(0);
				}
				RSA *pubKey;
				pubKey = PEM_read_RSA_PUBKEY(f,NULL,NULL,"dummy");
				fclose(f);
				long largest = RSA_size(pubKey);
				unsigned char* key_encrypted = (unsigned char*)malloc(largest);
				long encSize = RSA_public_encrypt(24,key,key_encrypted,pubKey,RSA_PKCS1_PADDING);
				printf("%d\n", encSize);
				if(encSize==-1){
					printf("Error, aborting!\n");
					exit(0);
				}

				char *key_encoded;
				B64enc(key_encrypted, encSize, &key_encoded);
			    f = fopen(emailOutput,"wb");
			    fwrite(key_encoded,1,strlen(key_encoded),f);
			    fwrite("\n",1,1,f);			    
			    fclose(f);		
		        ciphertext_len = des3_encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);	
		        B64enc(ciphertext, ciphertext_len, &ciphertext_encoded);			
		        free(key_encrypted);	
			}
			else{
				printf("bf\n");
				unsigned char* key = (unsigned char*)malloc(16);
				char* iv = (char*)malloc(8);
				int success = RAND_bytes(key, sizeof(key));
				unsigned long err = ERR_get_error();
				if(success != 1)
					handleErrors();
				success = RAND_bytes(iv, sizeof(iv));
				err = ERR_get_error();
				if(success != 1)
					handleErrors();

				f = fopen(pubKeyFile, "r");
				if(f==NULL){
					printf("Receiver public key does not exist!\n");
					exit(0);
				}
				RSA *pubKey;
				pubKey = PEM_read_RSA_PUBKEY(f,NULL,NULL,"dummy");
				fclose(f);
				long largest = RSA_size(pubKey);
				unsigned char* key_encrypted = (unsigned char*)malloc(largest);
				long encSize = RSA_public_encrypt(16,key,key_encrypted,pubKey,RSA_PKCS1_PADDING);
				printf("%d\n", encSize);
				if(encSize==-1){
					printf("Error, aborting!\n");
					exit(0);
				}

				char *key_encoded;
				B64enc(key_encrypted, encSize, &key_encoded);
			    f = fopen(emailOutput,"wb");
			    fwrite(key_encoded,1,strlen(key_encoded),f);
			    fwrite("\n",1,1,f);			    
			    fclose(f);		
		        ciphertext_len = bf_encrypt(plaintext, strlen((char *)plaintext), key, iv, ciphertext);	
		        B64enc(ciphertext, ciphertext_len, &ciphertext_encoded);			
		        free(key_encrypted);	
			}
		}
		else if(strcmp(secType,"AUIN")==0){
			printf("AUIN\n");
			char *privKeyFile = (char *)malloc(100);
			strcpy(privKeyFile,sender);
			strcat(privKeyFile,"_priv.txt");
			printf("%s\n", privKeyFile);
			ciphertext_encoded = (char *)malloc(sz+1);
			strcpy(ciphertext_encoded,plaintext);
			unsigned char *digest;
			unsigned char *digest_encrypted;
			int len;
			if(strcmp(digestAlg,"sha1")==0){
				digest = sha1func(plaintext);
				len = SHA_DIGEST_LENGTH;
			}
			else{
				digest = sha256func(plaintext);
				len = SHA256_DIGEST_LENGTH;
			}
			f = fopen(privKeyFile, "r");
			if(f==NULL){
				printf("Sender private key does not exist!\n");
				exit(0);
			}
			RSA *privKey;
			privKey = PEM_read_RSAPrivateKey(f,NULL,NULL,"dummy");
			fclose(f);
			long largest = RSA_size(privKey);
			digest_encrypted = (unsigned char*)malloc(largest);
			long encSize = RSA_private_encrypt(len,digest,digest_encrypted,privKey,RSA_PKCS1_PADDING);
			printf("%d\n", encSize);
			if(encSize==-1){
				printf("Error, aborting!\n");
				exit(0);
			}
			char *digest_encoded;
			B64enc(digest_encrypted,encSize,&digest_encoded);
			// printf("%s\n",digest_encoded);
		    f = fopen(emailOutput,"wb");
		    fwrite(digest_encoded,1,strlen(digest_encoded),f);
		    fwrite("\n",1,1,f);			    
		    fclose(f);		
		    free(digest_encrypted);
		    free(digest_encoded);
		    free(digest);
		}
		else{

			char *pubKeyFile = (char *)malloc(100);
			strcpy(pubKeyFile,receiver);
			strcat(pubKeyFile,"_pub.txt");
			printf("%s\n", pubKeyFile);

			char *privKeyFile = (char *)malloc(100);
			strcpy(privKeyFile,sender);
			strcat(privKeyFile,"_priv.txt");
			printf("%s\n", privKeyFile);

			unsigned char* key;
			char* iv;

			if(strcmp(encAlg,"aes-128-ecb")==0){
				key = (unsigned char*)malloc(16);
				iv = (char*)malloc(16);
			}
			else if(strcmp(encAlg,"des3")==0){
				key = (unsigned char*)malloc(24);
				iv = (char*)malloc(8);
			}
			else{
				key = (unsigned char*)malloc(16);
				iv = (char*)malloc(8);
			}			

			int success = RAND_bytes(key, sizeof(key));
			unsigned long err = ERR_get_error();
			if(success != 1)
				handleErrors();
			success = RAND_bytes(iv, sizeof(iv));
			err = ERR_get_error();
			if(success != 1)
				handleErrors();

			f = fopen(pubKeyFile, "r");
			if(f==NULL){
				printf("Receiver public key does not exist!\n");
				exit(0);
			}
			RSA *pubKey;
			pubKey = PEM_read_RSA_PUBKEY(f,NULL,NULL,"dummy");
			fclose(f);
			long largest = RSA_size(pubKey);
			unsigned char* key_encrypted = (unsigned char*)malloc(largest);
			long encSize = RSA_public_encrypt(16,key,key_encrypted,pubKey,RSA_PKCS1_PADDING);
			printf("%d\n", encSize);
			if(encSize==-1){
				printf("Error, aborting!\n");
				exit(0);
			}

			char *key_encoded;
			B64enc(key_encrypted, encSize, &key_encoded);
		    f = fopen(emailOutput,"wb");
		    fwrite(key_encoded,1,strlen(key_encoded),f);
		    fwrite("\n",1,1,f);			    
		    fclose(f);		

			unsigned char *digest;
			unsigned char *digest_encrypted;
			int len;
			if(strcmp(digestAlg,"sha1")==0){
				digest = sha1func(plaintext);
				len = SHA_DIGEST_LENGTH;
			}
			else{
				digest = sha256func(plaintext);
				len = SHA256_DIGEST_LENGTH;
			}
			f = fopen(privKeyFile, "r");
			if(f==NULL){
				printf("Sender private key does not exist!\n");
				exit(0);
			}
			RSA *privKey;
			privKey = PEM_read_RSAPrivateKey(f,NULL,NULL,"dummy");
			fclose(f);
			largest = RSA_size(privKey);
			digest_encrypted = (unsigned char*)malloc(largest);
			encSize = RSA_private_encrypt(len,digest,digest_encrypted,privKey,RSA_PKCS1_PADDING);
			printf("%d\n", encSize);
			if(encSize==-1){
				printf("Error, aborting!\n");
				exit(0);
			}
			char *digest_encoded;
			B64enc(digest_encrypted,encSize,&digest_encoded);
			int tot_len = strlen(digest_encoded) + strlen(plaintext);
			char *plaintext_fin = (char *)malloc(tot_len + 2);
			strcpy(plaintext_fin,digest_encoded);
			strcat(plaintext_fin,"\n");
			strcat(plaintext_fin,plaintext);
			plaintext_fin[tot_len+1] = '\0';
			// printf("%d\n", strlen(plaintext_fin));

			if(strcmp(encAlg,"aes-128-ecb")==0){
				printf("aes\n");
		        ciphertext_len = aes_encrypt(plaintext_fin, strlen((char *)plaintext_fin), key, iv, ciphertext);	
			}
			else if(strcmp(encAlg,"des3")==0){
				printf("des3\n");
		        ciphertext_len = des3_encrypt(plaintext_fin, strlen((char *)plaintext_fin), key, iv, ciphertext);	
			}
			else{
				printf("bf\n");
		        ciphertext_len = bf_encrypt(plaintext_fin, strlen((char *)plaintext_fin), key, iv, ciphertext);	
			}			
			// printf("%d\n", ciphertext_len);
	        B64enc(ciphertext, ciphertext_len, &ciphertext_encoded);		
	        // printf("%d\n", strlen(ciphertext_encoded));	
	        free(key_encrypted);	
		}
	    f = fopen(emailOutput,"ab");
	    fwrite(ciphertext_encoded,1,strlen(ciphertext_encoded),f);
	    fclose(f);		
		free(plaintext);
		free(ciphertext);
		free(ciphertext_encoded);
	}
	else if(strcmp(argv[1],"ReadMail")==0){
		if(argc < 9){
			printf("Error in command line input\n");
			exit(0);			
		}
		strcpy(secType,argv[2]);
		strcpy(sender,argv[3]);
		strcpy(receiver,argv[4]);
		strcpy(secureInput,argv[5]);
		strcpy(plainTextOutput,argv[6]);
		strcpy(digestAlg,argv[7]);
		strcpy(encAlg,argv[8]);
		if(strcmp(secType,"CONF")!=0 && strcmp(secType,"AUIN")!=0 && strcmp(secType,"COAI")!=0){
			printf("Invalid SecType\n");
			exit(0);
		}
		if(strcmp(digestAlg,"sha256")!=0 && strcmp(digestAlg,"sha1")!=0){
			printf("Invalid Digest Algorithm\n");
			exit(0);
		}
		if(strcmp(encAlg,"bf-ecb")!=0 && strcmp(encAlg,"des3")!=0 && strcmp(encAlg,"aes-128-ecb")!=0){
			printf("Invalid Encryption Algorithm\n");
			exit(0);
		}

		FILE *f;
		unsigned char* ciphertext;
		unsigned char* ciphertext_encoded;
		unsigned char* plaintext;
		long plaintext_len;

		if(strcmp(secType,"CONF")==0){
			char *privKeyFile = (char *)malloc(100);
			strcpy(privKeyFile,receiver);
			strcat(privKeyFile,"_priv.txt");
			printf("%s\n", privKeyFile);

			if(strcmp(encAlg,"aes-128-ecb")==0){
				printf("aes\n");
				char *key_encoded = (char*)malloc(1000);
				unsigned char* key_encrypted;
				unsigned char* key;
				char* iv = (char*)malloc(16);
				strcpy(iv,"0123456789012345");
				size_t test, test1;
			    f = fopen(secureInput,"r");
			    fseek(f,0L,2);
			    long ciphertext_len = ftell(f);
			    rewind(f);
			    fgets(key_encoded,1000,f);
			    int l = strlen(key_encoded);
			    ciphertext_len -= l;
			    ciphertext_encoded = (unsigned char *)malloc(ciphertext_len+1);
			    plaintext = (unsigned char *)malloc(ciphertext_len+1);
			    fread(ciphertext_encoded,1,ciphertext_len+1,f);
			    ciphertext_encoded[ciphertext_len] = '\0';
			    fclose(f);		
			    B64dec(key_encoded, &key_encrypted, &test1);

				f = fopen(privKeyFile, "r");
				if(f==NULL){
					printf("Receiver private key does not exist!\n");
					exit(0);
				}
				RSA *privKey;
				privKey = PEM_read_RSAPrivateKey(f,NULL,NULL,"dummy");
				fclose(f);
				long largest = RSA_size(privKey);
				key = (unsigned char*)malloc(largest);
				long decSize = RSA_private_decrypt(test1,key_encrypted,key,privKey,RSA_PKCS1_PADDING);
				printf("%d\n", decSize);
				if(decSize==-1){
					printf("Error, aborting!\n");
					exit(0);
				}

			    B64dec(ciphertext_encoded, &ciphertext, &test);
		        plaintext_len = aes_decrypt(ciphertext, test, key, iv, plaintext);	
			}
			else if(strcmp(encAlg,"des3")==0){
				printf("des3\n");
				char *key_encoded = (char*)malloc(1000);
				unsigned char* key_encrypted;
				unsigned char* key;
				char* iv = (char*)malloc(8);
				strcpy(iv,"01234567");
				size_t test, test1;
			    f = fopen(secureInput,"r");
			    fseek(f,0L,2);
			    long ciphertext_len = ftell(f);
			    rewind(f);
			    fgets(key_encoded,1000,f);
			    int l = strlen(key_encoded);
			    ciphertext_len -= l;
			    ciphertext_encoded = (unsigned char *)malloc(ciphertext_len+1);
			    plaintext = (unsigned char *)malloc(ciphertext_len+1);
			    fread(ciphertext_encoded,1,ciphertext_len+1,f);
			    ciphertext_encoded[ciphertext_len] = '\0';
			    fclose(f);		
			    B64dec(key_encoded, &key_encrypted, &test1);

				f = fopen(privKeyFile, "r");
				if(f==NULL){
					printf("Receiver private key does not exist!\n");
					exit(0);
				}
				RSA *privKey;
				privKey = PEM_read_RSAPrivateKey(f,NULL,NULL,"dummy");
				fclose(f);
				long largest = RSA_size(privKey);
				key = (unsigned char*)malloc(largest);
				long decSize = RSA_private_decrypt(test1,key_encrypted,key,privKey,RSA_PKCS1_PADDING);
				printf("%d\n", decSize);
				if(decSize==-1){
					printf("Error, aborting!\n");
					exit(0);
				}

			    B64dec(ciphertext_encoded, &ciphertext, &test);
		        plaintext_len = des3_decrypt(ciphertext, test, key, iv, plaintext);	
			}
			else{
				printf("bf\n");
				char *key_encoded = (char*)malloc(1000);
				unsigned char* key_encrypted;
				unsigned char* key;
				char* iv = (char*)malloc(8);
				strcpy(iv,"01234567");
				size_t test, test1;
			    f = fopen(secureInput,"r");
			    fseek(f,0L,2);
			    long ciphertext_len = ftell(f);
			    rewind(f);
			    fgets(key_encoded,1000,f);
			    int l = strlen(key_encoded);
			    ciphertext_len -= l;
			    ciphertext_encoded = (unsigned char *)malloc(ciphertext_len+1);
			    plaintext = (unsigned char *)malloc(ciphertext_len+1);
			    fread(ciphertext_encoded,1,ciphertext_len+1,f);
			    ciphertext_encoded[ciphertext_len] = '\0';
			    fclose(f);		
			    B64dec(key_encoded, &key_encrypted, &test1);

				f = fopen(privKeyFile, "r");
				if(f==NULL){
					printf("Receiver private key does not exist!\n");
					exit(0);
				}
				RSA *privKey;
				privKey = PEM_read_RSAPrivateKey(f,NULL,NULL,"dummy");
				fclose(f);
				long largest = RSA_size(privKey);
				key = (unsigned char*)malloc(largest);
				long decSize = RSA_private_decrypt(test1,key_encrypted,key,privKey,RSA_PKCS1_PADDING);
				printf("%d\n", decSize);
				if(decSize==-1){
					printf("Error, aborting!\n");
					exit(0);
				}

			    B64dec(ciphertext_encoded, &ciphertext, &test);
		        plaintext_len = bf_decrypt(ciphertext, test, key, iv, plaintext);	
			}
		}
		else if(strcmp(secType,"AUIN")==0){
			printf("AUIN\n");
			char *pubKeyFile = (char *)malloc(100);
			strcpy(pubKeyFile,sender);
			strcat(pubKeyFile,"_pub.txt");
			printf("%s\n", pubKeyFile);
			unsigned char *digest;
			unsigned char *digest_encrypted;
			unsigned char *digest_decrypted;
			unsigned char *dig1;
			unsigned char *dig2;
			char *digest_encoded = (char *)malloc(1000);

		    f = fopen(secureInput,"r");
		    fseek(f,0L,2);
		    plaintext_len = ftell(f);
		    rewind(f);
		    fgets(digest_encoded,1000,f);
		    int l = strlen(digest_encoded);
		    plaintext_len -= l;
		    plaintext = (unsigned char *)malloc(plaintext_len+1);
		    fread(plaintext,1,plaintext_len+1,f);
		    plaintext[plaintext_len] = '\0';
		    fclose(f);		

			int len;
			if(strcmp(digestAlg,"sha1")==0){
				digest = sha1func(plaintext);
				len = SHA_DIGEST_LENGTH;
			}
			else{
				digest = sha256func(plaintext);
				len = SHA256_DIGEST_LENGTH;
			}

			f = fopen(pubKeyFile, "r");
			if(f==NULL){
				printf("Sender public key does not exist!\n");
				exit(0);
			}
			RSA *pubKey;
			pubKey = PEM_read_RSA_PUBKEY(f,NULL,NULL,"dummy");
			fclose(f);
			long largest = RSA_size(pubKey);
			digest_decrypted = (char *)malloc(largest);
			size_t test;
			B64dec(digest_encoded,&digest_encrypted,&test);
			long decSize = RSA_public_decrypt(test,digest_encrypted,digest_decrypted,pubKey,RSA_PKCS1_PADDING);
			printf("%d\n", decSize);
			if(decSize==-1){
				printf("Error, aborting!\n");
				exit(0);
			}
			B64enc(digest_decrypted,decSize,&dig1);
			B64enc(digest,len,&dig2);
			// printf("%s\n", dig1);
			// printf("%s\n", dig2);
			if(strcmp(dig1,dig2) == 0)
				printf("Authentication & Integrity successful!\n");
			else
				printf("Authentication & Integrity failed :(\n");
		}
		else{

			char *plaintext_fin;
			long plaintext_fin_len;
			char *privKeyFile = (char *)malloc(100);
			strcpy(privKeyFile,receiver);
			strcat(privKeyFile,"_priv.txt");
			printf("%s\n", privKeyFile);

			char *pubKeyFile = (char *)malloc(100);
			strcpy(pubKeyFile,sender);
			strcat(pubKeyFile,"_pub.txt");
			printf("%s\n", pubKeyFile);

			char *key_encoded = (char*)malloc(1000);
			unsigned char* key_encrypted;
			unsigned char* key;

			char* iv;
			if(strcmp(encAlg,"aes-128-ecb")==0){
				iv = (char*)malloc(16);
				strcpy(iv,"0123456789012345");
			}
			else if(strcmp(encAlg,"des3")==0){
				iv = (char*)malloc(8);
				strcpy(iv,"01234567");
			}
			else{
				iv = (char*)malloc(8);
				strcpy(iv,"01234567");
			}			
			
			size_t test, test1;
		    f = fopen(secureInput,"r");
		    fseek(f,0L,2);
		    long ciphertext_len = ftell(f);
		    rewind(f);
		    fgets(key_encoded,1000,f);
		    int l = strlen(key_encoded);
		    ciphertext_len -= l;
		    ciphertext_encoded = (unsigned char *)malloc(ciphertext_len+1);
		    plaintext_fin = (unsigned char *)malloc(2*ciphertext_len);
		    plaintext = (unsigned char *)malloc(2*ciphertext_len);
		    fread(ciphertext_encoded,1,ciphertext_len+1,f);
		    ciphertext_encoded[ciphertext_len] = '\0';
		    fclose(f);		
		    B64dec(key_encoded, &key_encrypted, &test1);

			f = fopen(privKeyFile, "r");
			if(f==NULL){
				printf("Receiver private key does not exist!\n");
				exit(0);
			}
			RSA *privKey;
			privKey = PEM_read_RSAPrivateKey(f,NULL,NULL,"dummy");
			fclose(f);
			long largest = RSA_size(privKey);
			key = (unsigned char*)malloc(largest);
			long decSize = RSA_private_decrypt(test1,key_encrypted,key,privKey,RSA_PKCS1_PADDING);
			printf("%d\n", decSize);
			if(decSize==-1){
				printf("Error, aborting!\n");
				exit(0);
			}

		    B64dec(ciphertext_encoded, &ciphertext, &test);

			if(strcmp(encAlg,"aes-128-ecb")==0){
				printf("aes\n");
		        plaintext_fin_len = aes_decrypt(ciphertext, test, key, iv, plaintext_fin);	
			}
			else if(strcmp(encAlg,"des3")==0){
				printf("des3\n");
		        plaintext_fin_len = des3_decrypt(ciphertext, test, key, iv, plaintext_fin);	
			}
			else{
				printf("bf\n");
		        plaintext_fin_len = bf_decrypt(ciphertext, test, key, iv, plaintext_fin);	
			}			

			unsigned char *digest;
			unsigned char *digest_encrypted;
			unsigned char *digest_decrypted;
			unsigned char *dig1;
			unsigned char *dig2;
			char *digest_encoded = (char *)malloc(1000);

			int i;
			for(i=0; i<plaintext_fin_len; i++){
				if(plaintext_fin[i] == '\n')
					break;
				digest_encoded[i] = plaintext_fin[i];
			}
			digest_encoded[i] = '\0';
			i = i+1;
			int tmp = i;
			for(; i<plaintext_fin_len; i++){
				plaintext[i-tmp] = plaintext_fin[i];
			}
			plaintext[i-tmp] = '\0';
			plaintext_len = i-tmp;

			int len;
			if(strcmp(digestAlg,"sha1")==0){
				digest = sha1func(plaintext);
				len = SHA_DIGEST_LENGTH;
			}
			else{
				digest = sha256func(plaintext);
				len = SHA256_DIGEST_LENGTH;
			}

			f = fopen(pubKeyFile, "r");
			if(f==NULL){
				printf("Sender public key does not exist!\n");
				exit(0);
			}
			RSA *pubKey;
			pubKey = PEM_read_RSA_PUBKEY(f,NULL,NULL,"dummy");
			fclose(f);
			largest = RSA_size(pubKey);
			digest_decrypted = (char *)malloc(largest);
			B64dec(digest_encoded,&digest_encrypted,&test);
			decSize = RSA_public_decrypt(test,digest_encrypted,digest_decrypted,pubKey,RSA_PKCS1_PADDING);
			printf("%d\n", decSize);
			if(decSize==-1){
				printf("Error, aborting!\n");
				exit(0);
			}
			B64enc(digest_decrypted,decSize,&dig1);
			B64enc(digest,len,&dig2);
			// printf("%s\n", dig1);
			// printf("%s\n", dig2);
			if(strcmp(dig1,dig2) == 0)
				printf("Confidentiality, Authentication & Integrity successful!\n");
			else
				printf("Confidentiality, Authentication & Integrity failed :(\n");

		}
		plaintext[plaintext_len] = '\0';
	    f = fopen(plainTextOutput,"wb");
	    fwrite(plaintext,1,strlen(plaintext),f);
	    fclose(f);		
	}
	else{
		printf("Error in command line input\n");
		exit(0);
	}

	EVP_cleanup();
	CRYPTO_cleanup_all_ex_data();
	ERR_free_strings();

	return 0;
}