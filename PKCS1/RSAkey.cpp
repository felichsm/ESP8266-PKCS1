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
 * RSAkey.cpp
 *
 *  Created on: 23 Apr 2017
 *      Author: felix mitterer
 *		E-mail: felix.mitterer@technikum-wien.at
 */

#include "RSAkey.h"

RSAkey::RSAkey(const mpz_t Exponent, const mpz_t Modulus) {
	mpz_init(this->Exponent);
	mpz_init(this->Modulus);
	mpz_set(this->Exponent,Exponent);
	mpz_set(this->Modulus,Modulus);
}

RSAkey::~RSAkey() {
	// TODO Auto-generated destructor stub
	mpz_clear(this->Exponent);
	mpz_clear(this->Modulus);
}


mpz_t* RSAkey::getModulus(){
	return &this->Modulus;
}

mpz_t* RSAkey::getExponent(){
	return &this->Exponent;
}
