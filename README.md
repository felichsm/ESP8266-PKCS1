# ESP8266-PKCS1
A PKCS1 implementation for the ESP8266 microcontroller

This Project is a PKCS1 implementation for the ESP8266 Microcontroller
It Contains a RSA implementation based on the GNU MP Library ported to the ESP8266 Microcontroller

It is is programmed in the Sloeber IDE (version 4.1).
If you want to integrate it in your Arduino Project, you can do so by adding the PKCS1 folder as a Library to your Project.

It was tested with a WeMos D1 mini ESP8266 module
It was tested with a few keys against a python implementation.

Time consumed by the PKCS1 calculation depends strongly on the ciphertext to decrypt or the message to encrypt and also on the size of the Key.
Messured times were around 16,17Seconds at a CPU frequency of 80MHz and half the time for 160MHz. 
The Message for this test was 32Byte long and Encrypted with a 2048 Bit Key.
