/* ESP8266 PKCS1 Implementation, a minimalistic implementation of PKCS1 Standard, including a RSA implementation.

Copyright 2017 Felix Mitterer.

This file is part of the ESP8266 PKCS1 Library.

The ESP8266 PKCS1 Library is free software; you can redistribute it and/or modify
it under the terms of either:

  * the GNU Lesser General Public License as published by the Free
    Software Foundation; either version 3 of the License, or (at your
    option) any later version.

or

  * the GNU General Public License as published by the Free Software
    Foundation; either version 2 of the License, or (at your option) any
    later version.

or both in parallel, as here.

The ESP8266 PKCS1 Library is distributed in the hope that it will be useful, but
WITHOUT ANY WARRANTY; without even the implied warranty of MERCHANTABILITY
or FITNESS FOR A PARTICULAR PURPOSE.  See the GNU General Public License
for more details.

You should have received copies of the GNU General Public License and the
GNU Lesser General Public License along with the ESP8266 PKCS1 Library.  If not,
see https://www.gnu.org/licenses/.  */



/*
 * PKCS1.cpp
 *
 *  Created on: 23 Apr 2017
 *      Author: felix mitterer
 *		E-mail: felix.mitterer@technikum-wien.at
 */

#include "PKCS1.h"
extern "C"{
#include "user_interface.h"
#include <mem.h>
}
//#include <umm_malloc/umm_malloc.h>


PKCS1::PKCS1() {

	// TODO Auto-generated constructor stub

}

PKCS1::~PKCS1() {
	//TODO: include a pointer which holds all allocated memory and frees it upon deletion
}

int PKCS1::getLengthInOctet(const mpz_t num){
	int counts = 1;
	mpz_t q;
	mpz_init(q);
	mpz_set(q,num);
	while(mpz_cmp_ui(q, 256)>0){
		mpz_fdiv_q_ui(q,q,256);
		counts++;
	}
	mpz_clear(q);
	return counts;
}

bool PKCS1::I2OSP(char* res, const mpz_t x, int xLen){
	//char* res;
	//res = (char*)umm_malloc(xLen);
	//res = os_malloc(xLen);
	//char res[xLen];
	mpz_t cp;
	mpz_t div;
	mpz_t power;
	mpz_init(cp);
	mpz_init(div);
	mpz_init(power);
	mpz_set(cp,x);
	int i = 0;
	xLen--;
	while(xLen){
		mpz_ui_pow_ui(power, 256, xLen);	//power = 256^xLen
		mpz_fdiv_q(div,cp,power);			//div = number/power

		res[i++] = mpz_get_ui(div);	//Fixme: might get error due to implicit type conversion

		mpz_mul(div, div, power);			// div = div*power
		mpz_sub(cp, cp, div);				//cp -= div
		xLen--;
		//yield();	seems to cause problems, replace with:
		//delay(0);
	}
	res[i] = mpz_get_ui(cp);
	mpz_clear(cp);
	mpz_clear(div);
	mpz_clear(power);
	return true;
}





bool PKCS1::OS2IP(mpz_t res, char* x, int xLen){
	//Fixme: this needs to be done reverse
	if(xLen<1) return false;
	int max = xLen;
	mpz_set_ui(res, (int)x[--xLen]);
	mpz_t power;
	mpz_t mul;
	mpz_init(power);
	mpz_init(mul);
	for(int i=1;i<max; i++){
		mpz_ui_pow_ui(power, 256, i);
		mpz_set_ui(mul,(int)x[--xLen]);
		mpz_mul(mul,mul,power);
		mpz_add(res, res, mul);
		//yield();	//seems to cause problems, replace with:
		//delay(0);
	}
	mpz_clear(power);
	mpz_clear(mul);
	return true;
}


bool PKCS1::RSAEP(mpz_t res, const mpz_t message, RSAkey& key){
	if((mpz_cmp(message,key.Modulus)>=0)||(mpz_cmp_ui(message,0)<0)) return false;
	mpz_powm(res,message,key.Exponent,key.Modulus);
	return true;
}

bool PKCS1::RSADP(mpz_t res, const mpz_t ciphertext, RSAkey& key){
	if((mpz_cmp(ciphertext,key.Modulus)>=0)||(mpz_cmp_ui(ciphertext,0)<0)) return false;
	mpz_powm(res,ciphertext,key.Exponent,key.Modulus);
	return true;
}


int PKCS1::RSAES_PKCS1_v1_5_Encrypt(char** res, char* message, int mLen, RSAkey& key){
	int retLen=0;
	int k = getLengthInOctet(key.Modulus);
	//yield();
#if DEBUG_PKCS >=1
	Serial.print("Length in Octets:");
	Serial.println(k);
#endif
	if(mLen > (k-11)) return -1;
	//TODO: allocate the memory for the result dynamically or request the user to allocate?
	char* EM = (char*)os_malloc(k);

	EM[0] = 0x00;
	EM[1] = 0x02;
	int i;
	for(i =2; i< k-mLen-1; i++){
		EM[i] = random(1,255);
	}
	EM[i++]=0x00;
	for(int j =0; i<k; i++, j++){
		EM[i] = message[j];
	}

	mpz_t m;
	mpz_t c;
	mpz_init(m);
	mpz_init(c);
#if DEBUG_PKCS >=1
	Serial.print("Message to encrypt:");
	Serial.println(EM);
#endif
	//yield();
	this->OS2IP(m,EM,getLengthInOctet(key.Modulus));
	//yield();
#if DEBUG_PKCS >=1
	Serial.println("Message as long number calculated");
#endif
	yield();
#if DEBUG_PKCS >=1
	Serial.println("Yield worked");
#endif
	this->RSAEP(c,m,key);
#if DEBUG_PKCS >=1
	Serial.print("RSA Encryption primitive applied");
#endif
	retLen= this->getLengthInOctet(c);
	*res= (char*)os_malloc(retLen);

	this->I2OSP(*res,c,retLen);

	os_free(EM);
	mpz_clear(m);
	mpz_clear(c);
	return retLen;
}

int PKCS1::RSAES_PKCS1_v1_5_Decrypt(char** res, char* ciphertext, int cLen, RSAkey& key){
	int k = this->getLengthInOctet(key.Modulus);
	if((cLen!=k)||(k<11)) return -1;

	mpz_t c;
	mpz_init(c);
	this->OS2IP(c,ciphertext,cLen);
	mpz_t m;
	mpz_init(m);
	this->RSADP(m,c,key);

	char* EM = (char*)os_malloc(k);
	this->I2OSP(EM,m,k);
	int i;
	for(i=2; i<k; i++){
		if((uint8_t)EM[i]==0x00) break;
	}

	i++;	//Fixme: is the last i++ in the for loop still executed?
	if((k-i)<=0)return -1;
	int retLen = k-(i);

	*res = (char*)os_malloc(retLen);
	for(int j =0; i<k; i++, j++){
		(*res)[j] = EM[i];
	}

	os_free(EM);
	mpz_clear(c);
	mpz_clear(m);
	return retLen;
}




/*
int PKCS1::RSAES_PKCS1_v1_5_Encrypt(char** res, char* message, int mLen, RSAkey& key){
	int retLen=0;
	int k = getLengthInOctet(key.Modulus);
	if(mLen > (k-11)) return -1;
	//TODO: allocate the memory for the result dynamically or request the user to allocate?
	char* EM = (char*)os_malloc(k);
	k--;
	EM[k] = 0x00;
	k--;
	EM[k] = 0x02;
	k--;
	while(k>mLen){
		EM[k] = random(1,255);
		k--;
	}
	EM[k] = 0x00;
	k--;
	while(k){
		EM[k] = message[mLen-1-k];
		k--;
	}
	EM[0] = message[mLen-1];

	mpz_t m;
	mpz_t c;
	mpz_init(m);
	mpz_init(c);
	this->OS2IP(m,EM,getLengthInOctet(key.Modulus));
	this->RSAEP(c,m,key);

	retLen= this->getLengthInOctet(c);
	*res= (char*)os_malloc(retLen);

	this->I2OSP(*res,c,retLen);

	os_free(EM);
	mpz_clear(m);
	mpz_clear(c);
	return retLen;
}
 */





/*
 int PKCS1::RSAES_PKCS1_v1_5_Decrypt(char** res, char* ciphertext, int cLen, RSAkey& key){
	int k = this->getLengthInOctet(key.Modulus);
	if((cLen!=k)||(k<11)) return -1;

	mpz_t c;
	mpz_init(c);
	this->OS2IP(c,ciphertext,cLen);
	mpz_t m;
	mpz_init(m);
	this->RSADP(m,c,key);

	char* EM = (char*)os_malloc(k);
	this->I2OSP(EM,m,k);
	k--;
	k--; //to skip the first 0
	while(k){
		if((uint8_t)EM[k]==0) break;
		k--;
	}
	*res  = (char*)os_malloc(k);
	int retLen=k;
	k--;

	for(int i =0; i<retLen; i++){
		*(res[i]) = EM[k--];
	}

	os_free(EM);
	mpz_clear(c);
	mpz_clear(m);
	return retLen;
}

 */
