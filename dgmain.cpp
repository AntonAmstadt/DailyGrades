//CryptoPP files
#include "cryptlib.h"
#include "shake.h"
#include "filters.h"
#include "hex.h"
#include "files.h"

//MySQL c++ connectivity
#include "jdbc.h"

//contains get_password() - a function to return my MYSQL password
#include "password.h"

#include <iostream>
#include <sstream>
#include <vector>
#include <string>
#include <random>
#include <ctime>
#include <ios>
#include <limits>


//return a string of the current date in the form: YYYY-MM-DD
//this function is windows-specific due to localtime_s
std::string get_date() {
	time_t now = time(0);
	tm t{};
	localtime_s(&t, &now);
	std::string cur_date{ std::to_string(1900 + t.tm_year) };
	cur_date += "-";
	cur_date += std::to_string(1 + t.tm_mon);
	cur_date += "-";
	cur_date += std::to_string(t.tm_mday);
	return cur_date;
}

//returns 0 if user doesn't exist in login_info, returns non-zero otherwise
int check_user_exists(sql::SQLString user, std::shared_ptr<sql::Connection> con) {
	try {
		std::unique_ptr<sql::PreparedStatement> stmnt(con->prepareStatement(
			"SELECT count(*) FROM login_info WHERE username = ?"
		));
		stmnt->setString(1, user);
		std::unique_ptr<sql::ResultSet> rs(stmnt->executeQuery());
		int user_count{ 0 };
		if (rs->next())
			user_count = rs->getInt(1);
		return user_count;
	}
	catch (sql::SQLException& e) {
		std::cerr << "error in check_user_exists: " << e.what() << '\n';
		return -1;
	}
}

//returns 0 if user and goal doesn't exist in user_goal, returns non-zero otherwise
int check_user_goal_exists(sql::SQLString user, sql::SQLString goal, std::shared_ptr<sql::Connection> con) {
	try {
		std::unique_ptr<sql::PreparedStatement> stmnt(con->prepareStatement(
			"SELECT count(*) FROM user_goals WHERE username = ? AND goal = ?;"
		));
		stmnt->setString(1, user);
		stmnt->setString(2, goal);
		std::unique_ptr<sql::ResultSet> rs(stmnt->executeQuery());
		int user_goal_count{ 0 };
		if (rs->next())
			user_goal_count = rs->getInt(1);
		return user_goal_count;
	}
	catch (sql::SQLException& e) {
		std::cerr << "error in check_user_goal_exists: " << e.what() << '\n';
		return -1;
	}
}

//uses CryptoPP library to return the hash of the password
std::string get_hash(std::string password) {
	std::string digest;
	std::string hashPassword;

	CryptoPP::SHAKE256 hash;
	hash.Update((const CryptoPP::byte*)password.data(), password.size());
	digest.resize(hash.DigestSize());
	hash.Final((CryptoPP::byte*)&digest[0]);
	CryptoPP::HexEncoder encoder(new CryptoPP::StringSink(hashPassword));
	CryptoPP::StringSource s(digest, true, new CryptoPP::Redirector(encoder));
	return hashPassword;
}

//returns true if login is successful. else return false
bool login(std::string user, std::string pass, std::string pepper, std::shared_ptr<sql::Connection> con) {
	if (check_user_exists(user, con)) {
		try {
			std::unique_ptr<sql::PreparedStatement> stmnt(con->prepareStatement(
				"SELECT * FROM login_info WHERE username = ?;"
			));
			stmnt->setString(1, user);
			std::unique_ptr<sql::ResultSet> rs(stmnt->executeQuery());
			if (rs->next()) {
				std::string tablePH = rs->getString("passwordHash");
				std::string tableSalt = rs->getString("salt");
				pass += tableSalt;
				pass += pepper;
				if (tablePH == get_hash(pass))
					return true;
			}
			return false;
		}
		catch (sql::SQLException& e) {
			std::cerr << "Error in login: " << e.what() << '\n';
			return false;
		}
	 }
	else {
		std::cout << "user: " << user << " not found in database\n";
		return false;
	}
}

//generate the random salt string that is used to make the hashes unique 
std::string generate_salt() {
	std::string validchars{ "0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ" };
	std::random_device rd;
	std::mt19937 gen(rd());
	std::uniform_int_distribution<> dist(0, validchars.size());
	std::string salt{};
	for (int i = 0; i < 49; i++)
		salt += validchars[dist(gen)];
	return salt;
}

//add new user to login_info table
//returns true if user created successfully, else return false
bool create_user(std::string new_user, std::string password, std::string pepper, std::shared_ptr<sql::Connection> con) {
	if (check_user_exists(new_user, con)) {
		std::cout << "create_user tried to create a user that already exists\n";
		return false;
	}
	else {
		std::string salt = generate_salt(); 
		std::cout << "in create_user: salt = " << salt << '\n';
		std::cout << "in create_user: password = " << password << '\n';
		password += salt;
		std::cout << "in create_user: password += salt = " << password << '\n';
		password += pepper;
		std::cout << "in create_user: password += pepper = " << password << '\n';
		std::string password_hash = get_hash(password);
		std::cout << "in create_user: password_hash = " << password_hash << '\n';

		try {
			std::unique_ptr<sql::PreparedStatement> stmnt(con->prepareStatement(
				"INSERT INTO login_info (username, passwordHash, salt) VALUES ( ? , ? , ? );"
			));
			stmnt->setString(1, new_user);
			stmnt->setString(2, password_hash);
			stmnt->setString(3, salt);
			stmnt->executeUpdate();
			return true;
		}
		catch (sql::SQLException& e) {
			std::cerr << "Error in create_user: " << e.what() << '\n';
			return false;
		}
	}
}

// returns true if goal created successfully, else return false
bool create_new_goal(std::string user, std::string new_goal, std::shared_ptr<sql::Connection> con) {
	if (!check_user_exists(user, con)) {
		std::cerr << "create_new_goal tried to create a goal for a non-existent user. User: " << user << '\n';
		return false;
	}
	try {
		std::unique_ptr<sql::PreparedStatement> ps(con->prepareStatement(
			"SELECT count(*) FROM user_goals WHERE username = ? AND goal = ?;"
		));
		ps->setString(1, user);
		ps->setString(2, new_goal);
		std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
		if (rs->next()) {
			int count = rs->getInt(1);
			if (count) {
				std::cerr << "create_new_goal tried to create a goal that already exists for the user\n";
				return false;
			}
		}

		std::unique_ptr<sql::PreparedStatement> stmnt(con->prepareStatement(
			"INSERT INTO user_goals (username, goal) VALUES ( ? , ? );"
		));
		stmnt->setString(1, user);
		stmnt->setString(2, new_goal);
		stmnt->executeUpdate();
		return true;
	}
	catch (sql::SQLException& e) {
		std::cerr << "Error in create_new_goal: " << e.what() << '\n';
		return false;
	}
}

// list all goals for the current user
void list_goals(std::string user, std::shared_ptr<sql::Connection> con) {
	if (!check_user_exists(user, con)) {
		std::cerr << "list_goals called for a non-existent user. User: " << user << '\n';
		return;
	}
	try {
		std::unique_ptr<sql::PreparedStatement> ps(con->prepareStatement(
			"SELECT * FROM user_goals WHERE username = ?;"
		));
		ps->setString(1, user);
		std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
		std::cout << "Listing goals for user: " << user << '\n';
		std::cout << "------------------------------\n";
		while (rs->next()) {
			std::cout << rs->getString("goal") << '\n';
		}
		std::cout << "------------------------------\n";
	}
	catch (sql::SQLException& e) {
		std::cerr << "Error in list_goals: " << e.what() << '\n';
	}
}

//return true if goal deleted successfully, else return false
bool delete_goal(std::string user, std::string goal, std::shared_ptr<sql::Connection> con) {
	if (!check_user_goal_exists(user, goal, con)) {
		std::cout << "delete_goal tried to delete non-existent goal. user: " << user << " non-existent goal: " << goal << '\n';
		return false;
	}
	try {
		std::unique_ptr<sql::PreparedStatement> ps(con->prepareStatement(
			"DELETE FROM user_goals WHERE username = ? AND goal = ?;"
		));
		ps->setString(1, user);
		ps->setString(2, goal);
		ps->executeUpdate();
		return true;
	}
	catch (sql::SQLException& e) {
		std::cerr << "Error in delete_goal: " << e.what() << '\n';
		return false;
	}
}

// returns an int that evaluates to true if the grade exists, else return 0 (false)
int check_grade_exists(std::string user, std::string goal, std::string date, std::shared_ptr<sql::Connection> con) {
	try {
		std::shared_ptr<sql::PreparedStatement> ps(con->prepareStatement(
			"SELECT count(*) FROM goal_grades WHERE username = ? AND goal = ? AND cur_date = ?;"
		));
		ps->setString(1, user);
		ps->setString(2, goal);
		ps->setString(3, date);
		std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
		if (rs->next()) {
			int count = rs->getInt(1);
			return count;
		}
	}
	catch (sql::SQLException &e) {
		std::cerr << "Error in check_grade_exists: " << e.what() << '\n';
		return 0;
	}
}

//return true if grade successfully modified
bool modify_grade(std::string user, std::string goal, std::string date, std::string new_grade, std::shared_ptr<sql::Connection> con) {
	if (!check_grade_exists(user, goal, date, con)) {
		std::cout << "modify_grade tried to modify a grade that doesn't exist\n";
		return false;
	}
	try {
		std::unique_ptr<sql::PreparedStatement> ps(con->prepareStatement(
			"UPDATE goal_grades SET grade = ? WHERE username = ? AND goal = ? AND cur_date = ?;"
		));
		ps->setString(1, new_grade);
		ps->setString(2, user);
		ps->setString(3, goal);
		ps->setString(4, date);
		ps->executeUpdate();
		return true;
	}
	catch (sql::SQLException& e) {
		std::cerr << "Error in modify_grade: " << e.what() << '\n';
		return false;
	}
}

//return true if the grade is valid, else return false
bool valid_grade(std::string grade) {
	if (grade == "A" || grade == "B" || grade == "C" || grade == "D" || grade == "F")
		return true;
	return false;
}

//used to validate, then return the active date to adjust grades for
//currently doesn't do much data validation
std::string validate_date(std::string date) {
	if (date.size() != 10) {
		std::cout << "invalid date size in set_active_date. size:" << date.size() << " setting date as current date\n";
		return get_date();
	}
	return date;
}

//returns true if grade successfully created
bool create_new_grade(std::string user, std::string goal, std::string date, std::string grade, std::shared_ptr<sql::Connection> con) {
	if (!check_user_goal_exists(user, goal, con)) {
		std::cerr << "create_new_grade tried to create a goal for a non-existent goal. User: " << user << " goal: " << goal << '\n';
		return false;
	}
	try {
		if (check_grade_exists(user, goal, date, con)) {
			std::cout << "create_new_grade tried to create a grade that already exists (use modify a grade instead)\n";
			return false;
		}

		std::unique_ptr<sql::PreparedStatement> stmnt(con->prepareStatement(
			"INSERT INTO goal_grades (username, goal, cur_date, grade) VALUES ( ? , ? , ? , ?);"
		));
		stmnt->setString(1, user);
		stmnt->setString(2, goal);
		stmnt->setString(3, date);
		stmnt->setString(4, grade);
		stmnt->executeUpdate();
		return true;
	}
	catch (sql::SQLException& e) {
		std::cerr << "Error in create_new_grade: " << e.what() << '\n';
		return false;
	}
}

// prompt the user to input a grade for each goal for the active date
// user overwrites any existing grades for that day
// returns true if successful, false if fails
bool input_all_grades(std::string user, std::string active_date, std::shared_ptr<sql::Connection> con) {
	if (!check_user_exists(user, con)) {
		std::cerr << "input_all_grades called for a non-existent user. User: " << user << '\n';
		return false;
	}
	try {
		std::unique_ptr<sql::PreparedStatement> ps(con->prepareStatement(
			"SELECT * FROM user_goals WHERE username = ?;"
		));
		ps->setString(1, user);
		std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
		std::vector<std::string> goalvec{};
		while (rs->next()) {
			goalvec.push_back(rs->getString("goal"));
		}
		std::string grade{};
		for (std::string g : goalvec) {
			std::cout << "Enter grade for goal - " << g << " - grade: ";
			std::getline(std::cin, grade);
			while (!valid_grade(grade)) {
				std::cout << "invalid grade. enter again (grade can be - [A,B,C,D,F], case-sensitive: ";
				std::getline(std::cin, grade);
			}
			if (check_grade_exists(user, g, active_date, con)) {
				if (!modify_grade(user, g, active_date, grade, con)) {
					std::cout << "modify_grade failed inside input_all_grades\n";
					return false;
				}
			}
			else {
				if (!create_new_grade(user, g, active_date, grade, con)) {
					std::cout << "create_new_grade failed inside input_all_grades\n";
					return false;
				}
			}
			
		}
		return true;
	}
	catch (sql::SQLException& e) {
		std::cerr << "Error in input_all_grades: " << e.what() << '\n';
		return false;
	}
}

//list grades for all goals of a user within a specified range of dates
void list_grades(std::string user, std::string start_date, std::string end_date, std::shared_ptr<sql::Connection> con) {
	if (!check_user_exists(user, con)) {
		std::cerr << "list_grades called for a non-existent user. User: " << user << '\n';
		return;
	}
	try {
		std::unique_ptr<sql::PreparedStatement> ps(con->prepareStatement(
			"SELECT * FROM goal_grades WHERE username = ? AND cur_date BETWEEN CAST(? AS DATE) AND CAST(? AS DATE) ORDER BY cur_date ASC, goal ASC;"
		));
		ps->setString(1, user);
		ps->setString(2, start_date);
		ps->setString(3, end_date);
		std::unique_ptr<sql::ResultSet> rs(ps->executeQuery());
		std::cout << "Listing all grades for user: " << user << " in range: " << start_date << " to " << end_date << '\n';
		std::cout << "----------------------\n";
		while (rs->next()) {
			std::cout << rs->getString("cur_date") << " " << rs->getString("goal") << ": " << rs->getString("grade") << '\n';
		}
		std::cout << "----------------------\n";
	}
	catch (sql::SQLException &e) {
		std::cerr << "Error in list_grades: " << e.what() << '\n';
	}
}

void display_user_options(std::string current_user, std::string active_date) {
	std::cout << "Info - user: " << current_user << " active date: " << active_date << " Available options: \n";
	std::cout << "0. exit program\n1. log out \n2. list goals\n3. add a new goal\n4. delete a goal\n5. input a grade (for active date)\n"
		<< "6. input grades for all goals (for active date)\n7. modify a grade (for active date)\n8. change active date\n"
		<< "9. display all grades within date range\n10. display this help message again\n";
}

// connect to database, control flow of program, get user input 
int main(int argc, char* argv[]){
	std::string current_date {get_date()};
	const std::string pepper{ "nhfiem534" };
	bool running{ true };
	std::string grade{};
	std::string goal{};
	std::string start_date{};
	std::string end_date{};
	try {
		sql::mysql::MySQL_Driver* driver = sql::mysql::get_mysql_driver_instance();
		std::shared_ptr<sql::Connection> con(driver->connect("tcp://127.0.0.1:3306/daily_grades", "root", get_password()) );
		while (running) {
			std::string active_date{ current_date }; //active_date is the day where grade modifications are made
			bool login_success{ false };
			bool running_user{ true };
			bool fail{ false };
			std::string current_user{};
			std::string password{};
			int input;
			std::cout << "Welcome to Daily Grades! Enter 1 to login, 2 to create a new user, 0 to quit: ";
			std::cin >> input;
			std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n'); //clear input buffer
			switch (input) {
			case 0:
				running = false;
				break;
			case 1: 
				while (!login_success) {
					std::cout << "Enter username or enter 0 to return home: ";
					std::getline(std::cin, current_user);
					if (current_user == "0") {
						login_success = true;
						fail = true;
					}
					else if (check_user_exists(current_user, con)) {
						std::cout << "Enter password: ";
						std::getline(std::cin, password);
						if (login(current_user, password, pepper, con)) {
							login_success = true;
							std::cout << "login successful\n";
						}
						else {
							std::cout << "incorrect password\n";
						}
					}
					else {
						std::cout << "user: " << current_user << " doesn't exist in database.\n";
					}
				}
				if (!fail) {
					display_user_options(current_user, active_date);
					while (running_user) {
						std::cout << "Enter input number: ";
						std::cin >> input;
						std::cin.ignore(std::numeric_limits<std::streamsize>::max(), '\n');
						switch (input) {
						case 0:
							con->close();
							return 0;
							break;
						case 1:
							running_user = false;
							break;
						case 2:
							list_goals(current_user, con);
							break;
						case 3:
							std::cout << "Enter the name of the new goal: ";
							std::getline(std::cin, goal);
							if (create_new_goal(current_user, goal, con))
								std::cout << "goal: " << goal << " added successfully\n";
							break;
						case 4:
							std::cout << "Enter name of the goal to be deleted: ";
							std::getline(std::cin, goal);
							if (delete_goal(current_user, goal, con))
								std::cout << "goal deleted successfully\n"; 
							break;
						case 5:
							std::cout << "Choose goal: ";
							std::getline(std::cin, goal);
							std::cout << "Enter grade [A,B,C,D,F], case-sensitive: ";
							std::getline(std::cin, grade);
							while (!valid_grade(grade)) {
								std::cout << "invalid grade. enter again (grade can be - [A,B,C,D,F], case-sensitive: ";
								std::getline(std::cin, grade);
							}
							if (create_new_grade(current_user, goal, active_date, grade, con)) {
								std::cout << "grade input successful\n";
							}
							break;
						case 6:
							std::cout << "input all grades for date: " << active_date << '\n';
							if (input_all_grades(current_user, active_date, con))
								std::cout << "grades entered successfully\n";
							break;
						case 7:
							std::cout << "Choose goal: ";
							std::getline(std::cin, goal);
							std::cout << "Enter grade [A,B,C,D,F], case-sensitive: ";
							std::getline(std::cin, grade);
							while (!valid_grade(grade)) {
								std::cout << "invalid grade. enter again (grade can be - [A,B,C,D,F], case-sensitive: ";
								std::getline(std::cin, grade);
							}
							if (modify_grade(current_user, goal, active_date, grade, con)) {
								std::cout << "grade modification successful\n";
							}
							break;
						case 8:
							std::cout << "Enter new date in the format: YYYY-MM-DD :";
							std::getline(std::cin, active_date);
							active_date = validate_date(active_date);
							break;
						case 9:
							std::cout << "Enter the beginning of the date range in the format YYYY-MM-DD : ";
							std::getline(std::cin, start_date);
							start_date = validate_date(start_date);
							std::cout << "Enter the end of the date range in the format YYYY-MM-DD : ";
							std::getline(std::cin, end_date);
							end_date = validate_date(end_date);
							list_grades(current_user, start_date, end_date, con);
							break;
						case 10:
							display_user_options(current_user, active_date);
							break;
						default:
							std::cout << "unrecognized input. Enter 10 for help message\n";
						}
					}
				}
				break;
			case 2:
				std::cout << "Enter new username: ";
				std::getline(std::cin, current_user);
				std::cout << "Enter password: ";
				std::getline(std::cin, password);
				if (create_user(current_user, password, pepper, con)) {
					std::cout << "user created successfully\n";
				}
				break;
			default:
				std::cout << "unrecognized input\n";
				break;
			}
		}
		con->close();
	}
	catch (sql::SQLException& e) {
		std::cerr << "ERROR: in main, exception details: " << e.what() << '\n';
	}

    return 0;
}