# DailyGrades #
Enter and store grades for user defined goals

The main purpose of this project is for me to demo some of my skills with C++, relational databases, and secure password storage.
DailyGrades allows users to define goals and grade themself on on the goals everyday (or whatever days they choose to give themself grades). 

## Features: ##
* User sign up and login
* Create new goals
* Delete goals (and their corresponding grades)
* List goals
* Input a single grade for a goal on a date
* Input grades for all goals for a date (for convenience)
* Modify a grade
* Display all grades within a range of dates

## Details ##
DailyGrades is a C++ console application that connects to a local MySQL database in order to store and retrieve: usernames, hash code for user passwords, 
salt values for hash uniqueness, user goals, grades for user goals, and the dates the grades apply to. The CryptoPP library is used for a hash function. 
The data definition language for the tables can be found in Daily_Grades_DDL.sql, and the database relational diagram can be found in RelationalDiagram.JPG.
Of course, the most interesting file to look at is dgmain.cpp as this is where the bulk of the work for this project went into.

One of the exciting parts of the project is the secure storage of passwords in the database. Passwords are not stored as plaintext. Instead, the hash
of the password combined with salt and pepper values is stored. The hash function I used is SHA256 from the CryptoPP library. The process for secure password 
storage is as follows: when a new user is created, they enter their new password. At this time, a random string is generated and used as the salt value. 
The password is concatenated with the salt value and then concatenated again with a constant pepper value. This string is the input to the SHA256 hash function. 
The hashed value is stored in the database in a row with the username and the salt value that was generated. When a user tries to log in, the user types in
their username and password. The salt value is retrieved from the database for that user, and the password is combined with the salt and pepper and then hashed.
If that hash is the same as the hash stored in the database, the login is successful.

If this was a more serious project, I would have done a few things to make password storage even more secure. First, the pepper value would be a secret.
The whole point of a pepper value is that it is a secret value to be combined with the password before the hash. In this project, the pepper can easily
be found in my source code. Second, I would have used a slower hash function than SHA256 and used multiple iterations of that function. A slower hash function 
and more iterations would mean an attacker has to spend more time to discover passwords.

The program is fairly resilient to bad user input. However, when entering a date, a user could input any string with exactly 10 characters and the program 
will accept it as a valid date. This bad date would not be able to end up in the database because MySQL would prevent it, and a user would be able to change this back to a valid date at any time. Having a bad date would prevent input and modification of grades until the date is made valid again by the user, by logging out and back in, or by exiting the program. I could have included a more rigorous date checking system, but I felt it was outside the scope of what I wanted from this project. I 
would have implemented better date checking by using conversions between Julian and Gregorian dates.

## Build Information ##
Currently this project only runs on 64 bit windows. I may create a version to run on Linux in the near future, but for now, here is what I did to build the project:
I used Microsoft Visual Studio 2019 with their default C++ compiler. In order to use the CryptoPP library you need to first download it by going to
https://cryptopp.com/#download. The download will include the file: cryptlib.vcxproj. Open this file in Visual Studio and build cryptlib with the following
project properies: Configuration: Release, Platform: x64, C/C++->Code Generation->Runtime Library: Multi-threaded DLL (/MD). Now create a Visual Studio project for Daily Grades. Configure it in the same way as the cryptlib project. Add my dgmain.cpp file to the
source files in the project. If you haven't already, download the MySQL Server 8.0 and MySQL Connector C++ 8.0. Go back to the project properties settings
and input the correct information to be able to use the CryptoPP and MySQL libraries. Here is what my settings looks like:
 <AdditionalIncludeDirectories>C:\coding\Cpp\cryptopp860;C:\Program Files\MySQL\Connector C++ 8.0\include\mysql;C:\Program Files\MySQL\MySQL Server 8.0\include;
 %(AdditionalIncludeDirectories)</AdditionalIncludeDirectories>
 <AdditionalLibraryDirectories>C:\coding\Cpp\cryptopp860\x64\Output\Release;C:\Program Files\MySQL\Connector C++ 8.0\lib64\vs14;
 C:\Program Files\MySQL\MySQL Server 8.0\lib;%(AdditionalLibraryDirectories)</AdditionalLibraryDirectories>
 <AdditionalDependencies>cryptlib.lib;mysqlcppconn.lib;libmysql.lib;%(AdditionalDependencies)</AdditionalDependencies>
 In your file system copy 4 .dll files from the "Connector C++ 8.0\lib64" folder to the folder where dgmain.cpp is and again where your project executable file is.
 For me, those folders are: "C:\coding\Cpp\DailyGradesFinal\DailyGradesFinal" and "C:\coding\Cpp\DailyGradesFinal\x64\Release".
 The dll files are: libcrypto-1_1-x64.dll, libssl-1_1-x64.dll, mysqlcppconn8-2-vs14.dll, and mysqlcppconn-9-vs12.dll.
 Now create the database daily_grades in MySQL shell or workbench. Run the DDL I included on github to create the proper tables. 
 Almost done. Now delete the - #include "password.h" - line in dgmain.cpp as that was only included to hide my password.
 Finally, adjust the connection line of code in main (below) so that it has your database name (if it isn't daily_grades), username, and password.
 std::shared_ptr<sql::Connection> con(driver->connect("tcp://127.0.0.1:3306/daily_grades", "root", get_password()) );
