#include <stdio.h>
#include <openssl/sha.h>
#include <string.h>
#include <stdlib.h>
#include <openssl/hmac.h>
#include <openssl/opensslconf.h>
#include <time.h>


int N=5; /* Num. of devices */
int User = 3; /* Num. of users */
int sec_lev = 32;

const char *command = {"Command Message"}; /* command */
const char *command_ver = {"Command Message"}; 
 

static void printDump(const unsigned char *buff, int length, unsigned char *copy)
{
    int i;

    for (i = 0; i < length; i++) {
        copy[i] = buff[i];
        printf("%02x", (buff[i] & 0x000000ff));
    }
}

/*
static void printDump(const unsigned char *buff, int length)
{
    int i;

    for (i = 0; i < length; i++) {
        printf("%02x", (buff[i] & 0x000000ff));
        if ((i + 1) % 16 == 0) {
            printf("\n");
        }
        else {
            printf(" ");
        }
    }
    printf("\n\n");
}
*/



/* definition of device info. */
struct device_info {
    unsigned char id[32];        /*  member: name */
    unsigned char name0[33];
    unsigned char name1[33];
    /*
    unsigned char *pname0;
    unsigned char *pname1;
    */
    char keyy[EVP_MAX_MD_SIZE]; /* key y_id */
    char keyr[EVP_MAX_MD_SIZE]; /* key r_id */
    char keyk[EVP_MAX_MD_SIZE]; /* key K_id */
};

/* definition of device info. */
struct command_info {
    unsigned char id[32];        /*  member: name */
    char gamma[EVP_MAX_MD_SIZE]; /* auth gamma */
    char tau[EVP_MAX_MD_SIZE]; /* auth tau */
};

int GetRandom(int min, int max)
{
	return min + (int)(rand()*(max-min+1.0)/(1.0+RAND_MAX));
}

void rand_text(int length, char result[32]) {
    int i, index;
    const char char_set[] = "0123456789ABCDEFGHIJKLMNOPQRSTUVWXYZ";
 
    for (i = 0; i < length; i++) {
        index = GetRandom(0,strlen(char_set) - 1);
        result[i] = char_set[index];
    }
    result[i];
}

void key_gen(char result[32]) {
    int i, index;
    const char char_set[] = "0123456789abcdef";
 
    for (i = 0; i < sec_lev; i++) {
        index = GetRandom(0,strlen(char_set) - 1);
        result[i] = char_set[index];
    }
    result[i];
}

char* name_gen0(char* s1, const char* s2)
{
    int i;
    for(i=0 ; i < s2[i] != '\0'; i++)
    {
        s1[i] = s2[i];
    }
    s1[i] = '0';
    s1[i+1] = s2[i];
    return s1;
}

char* name_gen1(char* s1, const char* s2)
{
    int i;
    for(i=0 ; i < s2[i] != '\0'; i++)
    {
        s1[i] = s2[i];
    }
    s1[i] = '1';
    s1[i+1] = s2[i];
    return s1;
}

int check_strings(const char* s1, const char* s2)
{
    int i, s1_len, s2_len;
    s1_len = strlen(s1);
    s2_len = strlen(s2);

    if (s1_len != s2_len) return 0;

    printf("strings 1\n");
    for(i=0 ; i < s1_len; i++)
    {
        if (s1[i] != s2[i]) return 0;
    }
    printf("strings 2\n");
    return 1;
}

char* init(char* s1)
{
    int i;
    for(i=0 ; i != strlen(s1); i++)
    {
        s1[i] = '\0';
    }
    return s1;
}

int main(int argc, char *argv[])
{
    char *message = {"Sample Message"};
    unsigned char digest[SHA256_DIGEST_LENGTH];
    int i, j; 

/* setup */

    char    key[]   = "93f75ae483d03c23358fa5330ff4a3f5"; /* master key = hmac key */
	size_t  keylen  = strlen (key);

    SHA256_CTX sha_ctx;
    SHA256_Init(&sha_ctx); /* initialize ctx of sha*/
    SHA256_Update(&sha_ctx, message, sizeof(message)); /* input message */
    SHA256_Final(digest, &sha_ctx); /* output as digest */

    printf("%s\n", message);

    for (int i = 0; i < sizeof(digest); ++i) {
        printf("%x", digest[i]);
    }
    printf("\n");

/* Join: process of HMAC */

    /* Define device_info and pointers for copy */
    struct device_info dev[N];

    /* initialization of device info. */

    printf("bbb\n");
    for (i=0; i < N; i++){

        for (j=0; j < 32; j++){
            dev[i].id[j] = '\0';
        }
        for (j=0; j<33; j++){
            dev[i].name0[j] = '\0';
            dev[i].name1[j] = '\0';
        }
        for (j=0; j < EVP_MAX_MD_SIZE; j++){
            dev[i].keyy[j] = '\0';
            dev[i].keyr[j] = '\0';
            dev[i].keyk[j] = '\0';
        }
    }

        
    printf("ccc\n");
    



    const char data[] = "abcdefghijklmnopqrstuvwxyz";
	unsigned char out[EVP_MAX_MD_SIZE];
    unsigned int data_len, out_len = EVP_MAX_MD_SIZE;
    int name_len = 10; /* Device name length is here */

/*
    char str_zero = "0";
    char str_one = "1";
*/
    printf("test\n");
    for (i = 0; i < N; i++){

        /* Generation of device name */
        rand_text(name_len, dev[i].id);
        printf("test 0\n");

        printf("device name  %d:", i);
        for (j = 0; j < strlen(dev[i].id); j++) {
            printf("%x", dev[i].id[j]);
        }
        printf("\n");

        printf("device name  %d:", i);
        for (j = 0; j < strlen(dev[i].id); j++) {
            printf("%c", dev[i].id[j]);
        }
        printf("\n");

        /* copy from dev[i] to dev[i]||0*/
        printf("test 1\n");

        name_gen0(dev[i].name0, dev[i].id);

        printf("device name||0  %d:", i);
        for (j = 0; j < sizeof(dev[i].name0); j++) {
            printf("%x", dev[i].name0[j]);
        }
        printf("\n");

        printf("device name||0  %d:", i);
        for (j = 0; j < sizeof(dev[i].name0); j++) {
            printf("%c", dev[i].name0[j]);
        }
        printf("\n");


        /* pointer version

        dev[i].pname0 = dev[i].id;
        strcat(dev[i].name0, "0");

        printf("device name0 %d:", i);
        for (j = 0; j < sizeof(dev[i].name0); j++) {
            printf("%x", dev[i].name0[j]);
        }
        printf("\n");
        */

         /* copy from dev[i] to dev[i]||1*/
        printf("test 2\n");
 
        name_gen1(dev[i].name1, dev[i].id);

        printf("device name||1  %d:", i);
        for (j = 0; j < sizeof(dev[i].name1); j++) {
            printf("%x", dev[i].name1[j]);
        }
        printf("\n");

        
        printf("device name||1  %d:", i);
        for (j = 0; j < sizeof(dev[i].name1); j++) {
            printf("%c", dev[i].name1[j]);
        }
        printf("\n");

        /* Generation of key r_id */

        data_len = strlen(dev[i].name0);
        keylen  = strlen (key);
        HMAC(EVP_sha256(), key, keylen, dev[i].name0, data_len, out, &out_len);
        /*    HMAC(EVP_sha256(), key, keylen, data, data_len, out, &out_len);*/
/*
        printf("key rid x:\n");
        for (j = 0; j < sizeof(out); j++) {
            printf("%x", out[i]);
            dev[i].keyr[j] = out[j];
        }
        printf("\n");
*/
        printf("key rid c:\n");
        printDump(out, out_len, dev[i].keyr);
        printf("\n");


        /* Generation of key K_id */

        HMAC(EVP_sha256(), key, keylen, dev[i].keyr, data_len, out, &out_len);
/*        
        printf("key Kid x:\n");
        for (j = 0; j < sizeof(out); j++) {
            printf("%x", out[i]);
            dev[i].keyk[j] = out[j];
        }
        printf("\n");
*/
        printf("key Kid c:\n");
        printDump(out, out_len, dev[i].keyk);
        printf("\n");

        
        /* Generation of key y_id */

        data_len = strlen(dev[i].name1);
        HMAC(EVP_sha256(), key, keylen, dev[i].name1, data_len, out, &out_len);
        /*    HMAC(EVP_sha256(), key, keylen, data, data_len, out, &out_len);*/
/*
        printf("key yid x:\n");
        for (j = 0; j < sizeof(out); j++) {
            printf("%x", out[i]);
            dev[i].keyy[j] = out[j];
        }
        printf("\n");
*/
        printf("key yid c:\n");
        printDump(out, out_len, dev[i].keyy);


/*
        for (j = 0; j < sizeof(out); j++) {
            printf("%c", out[i]);
            dev[i].keyr[j] = out[j];
        }
*/
        printf("\n\n"); 

    }
/* Auth: process of HMAC */

    struct command_info cmd[N];
    unsigned char cmd_tmp[sec_lev];

    printf("%s\n", command);

    /* temporal key \bar{k} */
    char key_temp[EVP_MAX_MD_SIZE]; 
    for (j=0; j < EVP_MAX_MD_SIZE; j++){
            key_temp[j] = '\0';
    }

    
    printf("ddd\n");

    for (i=0; i < N; i++){
        for (j = 0; j < sec_lev; j++){
            cmd[i].id[j] = '\0';
        }
        for (j =0; j < EVP_MAX_MD_SIZE; j++){
            cmd[i].gamma[j] = '\0';
            cmd[i].tau[j] = '\0';
        }
    }

    printf("eee\n");


    for (j=0; j < sec_lev; j++){
        cmd_tmp[j]  = '\0';
    }

    key_gen(key_temp);
    keylen = strlen (key_temp);

    for (j=0; j< N; j++){
        data_len = strlen(dev[j].keyy);
        HMAC(EVP_sha256(), key_temp, keylen, dev[j].keyy, data_len, out, &out_len);
        printf("Gamma for %d:\n", j);
        printDump(out, out_len, cmd[j].gamma);
        printf("\n");        

        if (j < User) {
            name_gen1(cmd_tmp, command);
            printf("%s\n", cmd_tmp);

            data_len= strlen(cmd_tmp);
            keylen = strlen(dev[j].keyk);

            HMAC(EVP_sha256(), dev[j].keyk, keylen, cmd_tmp, data_len, out, &out_len);
            printf("Tau for %d in List:\n", j);
            printDump(out, out_len, cmd[j].tau);
            printf("\n");        
        } else {
            name_gen0(cmd_tmp, command);
            printf("%s\n", cmd_tmp);

            data_len= strlen(cmd_tmp);
            keylen = strlen(dev[j].keyk);


            HMAC(EVP_sha256(), dev[j].keyk, keylen, cmd_tmp, data_len, out, &out_len);
            printf("Tau for %d not in List:\n", j);
            printDump(out, out_len,cmd[j].tau);
            printf("\n\n");        

        }
    }


/* Verify: process of HMAC */

    unsigned char gamma_temp[EVP_MAX_MD_SIZE];
    unsigned char tau_temp[EVP_MAX_MD_SIZE];
    int ver_result[N];
    unsigned char ver_temp[sec_lev];

    for (j=0; j < sec_lev; j++){
            ver_temp[j] = '\0';
    }

    for (j=0; j < EVP_MAX_MD_SIZE; j++){
        gamma_temp[j] = '\0';
        tau_temp[j] = '\0';
    }



    

    for (j=0; j< N; j++){
        name_gen1(ver_temp, command);
        printf("%s\n", ver_temp);

        keylen = strlen(key_temp);
        data_len= strlen(dev[j].keyy);
        

        HMAC(EVP_sha256(), key_temp, keylen, dev[j].keyy, data_len, out, &out_len);
        /*
        HMAC(EVP_sha256(), key_temp, keylen, dev[j].keyy, data_len, out, &out_len);
        */
        printf("%d: Verification of Gamma for %s:\n", j, dev[j].id);
        printDump(out, out_len, gamma_temp);
        printf("\n");        

        if (check_strings(gamma_temp, cmd[j].gamma) == 0 ) {
            printf("verify check 1\n");
            ver_result[j] = 0;
        } else {
            keylen = strlen(dev[j].keyk);

            data_len = strlen(ver_temp);

            HMAC(EVP_sha256(), dev[j].keyk, keylen, ver_temp, data_len, out, &out_len);
            printDump(out, out_len, tau_temp);
            printf("\n"); 
            if ( check_strings(tau_temp, cmd[j].tau) == 1) {
                printf("verify check 2\n");
                ver_result[j] = 1;
            } else {
                ver_result[j] = 0;
            }
        }

        printf("Device %d: Result %d\n\n", j, ver_result[j]);

    }



    for (int i = 0; i < sizeof(digest); ++i) {
        printf("%x", digest[i]);
    }
    printf("\n");




    printf("hmac_sha256 output:\n");
    for (int i = 0; i < sizeof(out); ++i) {
        printf("%x", out[i]);
    }
    printf("\n");

    

    return 0;
}