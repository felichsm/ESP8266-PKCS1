# ESP8266-PKCS1
A PKCS1 implementation for the ESP8266 microcontroller

This Project is a PKCS1 implementation for the ESP8266 Microcontroller
It Contains a RSA implementation based on the GNU MP Library ported to the ESP8266 Microcontroller

It is is programmed in the Sloeber IDE (version 4.1).
If you want to integrate it in your Arduino Project, you can do so by adding the PKCS1 folder as a Library to your Project.

What is working so far: (compared to the standard: https://www.emc.com/emc-plus/rsa-labs/standards-initiatives/pkcs-rsa-cryptography-standard.htm)

KEY TYPES (only in first representation)
- RSA PUBLIC KEY
- RSA PRIVATE KEY

DATA CONVERSION PRIMITIVES:
- I2OSP
- OS2IP

CRYPTOGRAPHIC PRIMITIVES:
  ENCRYPTION AND DECRYPTION PRIMITIVES
  - RSAEP
  - RSADP 
  
ENCRYPTION SCHEMES
  RSAES-PKCS1-V1_5 
  - Encryption operation
  - Decryption operation 

What is not implemented so far:
every thing else like:
- SIGNATURE AND VERIFICATION PRIMITIVES
- RSAES-OAEP
- RSASSA-PSS
- RSASSA-PKCS1-V1_5 

(this should however not make any difficulties, since RSA and all conversion primitives are implemented)

It was tested with a WeMos D1 mini ESP8266 module
It was tested with a few keys against a python implementation.

Time consumed by the PKCS1 calculation depends strongly on the ciphertext to decrypt or the message to encrypt and also on the size of the Key.
Messured times were around 16,17Seconds at a CPU frequency of 80MHz and half the time for 160MHz. 
The Message for this test was 32Byte long and Encrypted with a 2048 Bit Key.
