CREATE TABLE login_info (
username VARCHAR(50) NOT NULL,
passwordHash VARCHAR(200) NOT NULL,
salt VARCHAR (50) NOT NULL,
CONSTRAINT PRIMARY KEY (username)
);

CREATE TABLE user_goals (
username VARCHAR(50) NOT NULL,
goal VARCHAR(50) NOT NULL,
CONSTRAINT PRIMARY KEY (username, goal),
CONSTRAINT `user_goals_login_info_fk` FOREIGN KEY (username) REFERENCES login_info (username)
ON DELETE CASCADE
ON UPDATE CASCADE
);

CREATE TABLE goal_grades (
username VARCHAR(50) NOT NULL,
goal VARCHAR(50) NOT NULL,
cur_date DATE NOT NULL,
grade CHAR(1) NOT NULL, 
CONSTRAINT PRIMARY KEY (username, goal, cur_date),
CONSTRAINT `goal_grades_user_goals_fk` FOREIGN KEY (username, goal) REFERENCES user_goals (username, goal)
ON DELETE CASCADE
ON UPDATE CASCADE
);
