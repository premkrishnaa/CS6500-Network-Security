Steps to run : 

1. Run 'make'
	<!--

	 Note: make file compiles using '-L/usr/local/lib' currently
	 	   But if needed, change it to '-L/usr/local/ssl/lib' or leave it empty,
	 	   according to the path where openssl is installed

	-->

2.  Users are present in users.txt
	Run './lab2 CreateKeys users.txt' to create the RSA key pairs for users in users.txt
	Run './lab2 CreateMail SecType Sender Receiver EmailInputFile EmailOutputFile DigestAlg EncryAlg'
	, where the terms are same as mentioned in the PS to create a mail
	Run './lab2 ReadMail SecType Sender Receiver SecureInputFile PlainTextOutputFile DigestAlg EncryAlg'
	, where the terms are same as mentioned in the PS to read a mail

3. In case of AUIN and COAI modes, success will be printed on the terminal. We can also check the correctness using
   'diff EmailInputFile PlainTextOutputFile' after successive CreateMail and ReadMail

4. Modify make clean accordingly to remove temporary files in between testing

5. Script file is 'script.log'
   Run 'scriptreplay --timing=time.txt script.log' to see the way in which I have tested

<!-- 

The program works correctly to the limit of my testing and there are no bugs/errors (tested with 100KB input file)
The correctness might be limited by the size of the input file due to memory constraints,
since memory management (eg: freeing heap memory) has been done only to a certain degree.

** Referred to "http://doctrina.org/Base64-With-OpenSSL-C-API.html" for doing base64 encoding and decoding parts

-->