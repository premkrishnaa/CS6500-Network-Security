import os

enc = ["./myenc -i input10KB.txt -o output.bin -p Enc -m CBC -k 128 -a AES > results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m CBC -k 128 -a AES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m CBC -k 192 -a AES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m CBC -k 192 -a AES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m ECB -k 128 -a AES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m ECB -k 128 -a AES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m ECB -k 192 -a AES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m ECB -k 192 -a AES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m CTR -k 128 -a AES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m CTR -k 128 -a AES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m CTR -k 192 -a AES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m CTR -k 192 -a AES >> results.txt",	   
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m CBC -k 56 -a DES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m CBC -k 56 -a DES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m ECB -k 56 -a DES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m ECB -k 56 -a DES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m CBC -k 112 -a 3DES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m CBC -k 112 -a 3DES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m CBC -k 168 -a 3DES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m CBC -k 168 -a 3DES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m ECB -k 112 -a 3DES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m ECB -k 112 -a 3DES >> results.txt",
	   "./myenc -i input10KB.txt -o output.bin -p Enc -m ECB -k 168 -a 3DES >> results.txt",
	   "./myenc -i input100KB.txt -o output.bin -p Enc -m ECB -k 168 -a 3DES >> results.txt",
		]

dec = ["./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 128 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 128 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 192 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 192 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 128 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 128 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 192 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 192 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CTR -k 128 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CTR -k 128 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CTR -k 192 -a AES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CTR -k 192 -a AES >> results.txt",	   
	   "./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 56 -a DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 56 -a DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 56 -a DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 56 -a DES >> results.txt",	   
	   "./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 112 -a 3DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 112 -a 3DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 168 -a 3DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m CBC -k 168 -a 3DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 112 -a 3DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 112 -a 3DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 168 -a 3DES >> results.txt",
	   "./myenc -i output.bin -o out1.txt -p Dec -m ECB -k 168 -a 3DES >> results.txt",
		]

# print(len(enc),len(dec))

for i in range(len(enc)):
	os.system(enc[i])
	os.system(dec[i])
	print("diff "+str(i))
	if(i%2==0):
		os.system("diff out1.txt input10KB.txt")
	else:
		os.system("diff out1.txt input100KB.txt")

os.system("rm out1.txt output.bin")