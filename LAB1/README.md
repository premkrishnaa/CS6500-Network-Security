Steps to run : 

1. Run 'make'
	<!--

	 Note: make file compiles using '-L/usr/local/lib' currently
	 	   But if needed, change it to '-L/usr/local/ssl/lib' or leave it empty,
	 	   according to the path where openssl is installed

	-->

2. Run
   './myenc -o <oper> -a <alg> -m <mode> -k <keysize> -i <inpfile> -o <outfile>'

   by replacing required values in the respective placeholders
   <!-- Note: CTR mode is available for AES alone (using inbuilt openssl library) -->


The time taken for encrypting/decrypting the file is given in microseconds
Use 'diff' to verify the decrypted file with original input file
The two files used for testing are 'input10KB.txt' and 'input100KB.txt'
One assumption used is that the input for encryption doesnt contain multiple eofs
Results used for report are stored in 'results-report.txt'
Report file is 'CS6500_Assignment_1_Report.pdf'

3. Run 'python run.py' to generate a new results file 'results.txt' 
   This also automatically checks the 'diff' using 'os.system' command
   Upon normal execution you will just see a series of diff [i] on screen


<!-- The program works correctly to the limit of my testing and there are no bugs/errors -->