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
 * PKCS1.h
 *
 *  Created on: 23 Apr 2017
 *      Author: felix mitterer
 *		E-mail: felix.mitterer@technikum-wien.at
 */

#ifndef PKCS1_PKCS1_H_
#define PKCS1_PKCS1_H_

#include <Arduino.h>
#include "mini-gmp.h"
#include "RSAkey.h"

#define DEBUG_PKCS 1


class PKCS1 {
private:

public:
	PKCS1();
	virtual ~PKCS1();
	/*
	 * This method returns the expected Length in octets of the given BigInteger
	 * @param: a BigInteger (represented in mpz_t format)
	 * @retrun: the expected length (or digits) in octet format (base256)
	 */
	int getLengthInOctet(const mpz_t num);

	/*
	 * this method takes a BigInteger (nonnegative) and converts it to an octet array (means conversion to base 256)
	 * @param: char pointer which holds the resulting octet array
	 * @param: x is the BigInteger to be converted
	 * @param: xLen is the intended length (stuffed with 0 at the front if needed)
	 */
	bool I2OSP(char* res, const mpz_t x, int xLen);

	/*
	 * this method converts an octet array to a BigInteger
	 * @param: returns a BigInteger represented as mpz_t vairable
	 * @param: pointer to the octet array
	 * @param: length of the array
	 */
	bool  OS2IP(mpz_t res, char* x, int xLen);

	/*
	 * this method is the RSAEncryption primitive. It applies RSA on a given message with a given Key (exponent & modulus)
	 * @param: the ciphertext
	 * @param: message to be encrypted (represented in mpz_t format)
	 * @param: RSA key representation
	 */
	bool RSAEP(mpz_t res, const mpz_t message, RSAkey& key);

	/*
	 * this method is the RSADecryption primitive. It decrypts the given ciphertext with a given Key
	 * @param the decrypted message
	 * @param: ciphertext to be decrypted (represented in mpz_t format)
	 * @param: RSA key representation
	 */
	bool RSADP(mpz_t res, const mpz_t ciphertext, RSAkey& key);

	/*
	 * this method implements the PKCS1 encryption scheme for ENCRYPTION
	 * it Encrypts a given message with the given Key according to the PKCS1 Encryption Scheme
	 * @param: the ciphertext (represented as an octet array) make shure it is enough allocated
	 * @param: message to be encrypted (represented as an octet array in base256 or in other words, a char array)
	 * @param: length of the message octet array
	 * @param: RSA key representation
	 * @return: length of the result
	 */
	int RSAES_PKCS1_v1_5_Encrypt(char** res, char* message, int mLen, RSAkey& key);

	/*
	 * this method implements the PKCS1 encryption scheme for DECRYPTION
	 * it Decrypts a given ciphertext with the given Key according to the PKCS1 Encryption Scheme
	 * @param: the message (represented as an octet array)
	 * @param: ciphertext to be decrypted (represented as an octet array in base256 or in other words, a char array)
	 * @param: length of the ciphertext octet array
	 * @param: RSA key representation
	 * @return: length of the result
	 */
	int RSAES_PKCS1_v1_5_Decrypt(char** res, char* ciphertext, int cLen, RSAkey& key);

	//TODO:
	void RSAES_OAEP_Encrypt();
	//TODO:
	void RSAES_OAEP_Decrypt();
};

#endif /* PKCS1_PKCS1_H_ */
