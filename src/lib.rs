pub mod ru_pws_mng_modules;

use ru_pws_mng_modules::hashing_functions::{hash_checker, hashing_function};
use clap::{Arg, Command};
use rusqlite::{params, Connection};

fn conn() -> Connection {
    Connection::open("sqlite.db").unwrap()
}

pub fn table_creation() {
    let query = "CREATE TABLE IF NOT EXISTS users (
        user_id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL UNIQUE,
        hashed_password BLOB NOT NULL,
        salt BLOB NOT NULL
    );

    CREATE TABLE IF NOT EXISTS passwords (
        password_id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER,
        website TEXT NOT NULL,
        password TEXT NOT NULL,
        UNIQUE(user_id, website),
        FOREIGN KEY (user_id) REFERENCES users(user_id) ON DELETE CASCADE ON UPDATE CASCADE
    );";

    let result = conn().execute_batch(query);

    match result {
        Ok(_) => println!("Tables created"),
        Err(err) => eprintln!("Error creating tables: {err}")
    }
}

fn user_creation(username: &str, password: &str) {
    let (hashed_password, salt) = match hashing_function(password) {
        Ok((hash, salt)) => (hash, salt),
        Err(err) => {
            eprintln!("Error hashing password: {err}");
            return;
        }
    };

    let result = conn().execute(
        "INSERT INTO users (username, hashed_password, salt) VALUES (?1, ?2, ?3);",
        params![&username, &hashed_password, &salt]
    );

    match result {
        Ok(_) => println!("User created"),
        Err(err) => eprintln!("Error creating user: {err}")
    }
}

fn get_user_info(username: &str) -> Option<(i32, [u8; 64], [u8; 64])> {
    let curr_con = conn();
    let mut querry_result = curr_con.prepare("SELECT user_id, hashed_password, salt FROM users WHERE username = ?1").unwrap();
    let user_info = querry_result.query_row([username], |row| {
        let user_id: i32 = row.get(0)?;
        let hashed_password: [u8; 64] = row.get(1)?;
        let salt: [u8; 64] = row.get(2)?;
        Ok((user_id, hashed_password.into(), salt.into()))
    });

    match user_info {
        Ok(info) => Some(info),
        Err(_) => None,
    }
}

fn save_password(username: &str, user_password: &str, website: &str, password: &str) {
    let (user_id, hashed_password, salt) = match get_user_info(username) {
        Some(info) => info,
        None => {
            println!("User {username} not found");
            return;
        }
    };

    if !hash_checker(user_password, &hashed_password, &salt) {
        eprintln!("Incorrect password");
        return;
    };

    let result = conn().execute(
        "INSERT INTO passwords (user_id, website, password) VALUES (?1, ?2, ?3);",
        params![&user_id, &website, &password]
    );

    match result {
        Ok(_) => println!("User {username} saved a password for {website}"),
        Err(err) => eprintln!("Error saving password: {err}")
    }
}

fn get_password(username: &str, password: &str, website: &str) {
    let (user_id, password_hash, salt) = match get_user_info(username) {
        Some(info) => info,
        None => {
            eprintln!("User {username} not found");
            return;
        }
    };

    if !hash_checker(password, &password_hash, &salt) {
        eprintln!("Incorrect password");
        return;
    }

    let curr_con = conn();

    let result = curr_con.prepare("SELECT password FROM passwords WHERE user_id = ?1 AND website = ?2;");
    match result {
        Ok(mut res) => {
            let pass_result = res.query_row(params![user_id, website], |row| {
                let password: String = row.get(0)?;
                Ok(password)
            });

            match pass_result {
                Ok(password) => println!("Password for {username} on {website} is {password}"),
                Err(_) => eprintln!("Password for {username} on {website} not found")
            }
        }
        Err(err) => eprintln!("Error preparing statement: {err}"),
    }
}

fn change_user_password(username: &str, password: &str, new_password: &str) {
    let (_, password_hash, salt) = match get_user_info(username) {
        Some(info) => info,
        None => {
            eprintln!("User {username} not found");
            return;
        }
    };

    if !hash_checker(password, &password_hash, &salt) {
        eprintln!("Incorrect password");
        return;
    };

    let curr_conn = conn();

    let (password_hash, salt) = match hashing_function(new_password) {
        Ok((hash, salt)) => (hash, salt),
        Err(err) => {
            eprintln!("Error hashing password: {err}");
            return;
        }
    };

    let result = curr_conn.execute(
        "UPDATE users SET hashed_password = ?1, salt = ?2 WHERE username = ?3;", 
        params![&password_hash, &salt, &username]
    );

    match result {
        Ok(_) => println!("Password for user {username} updated successfully"),
        Err(err) => eprintln!("Error updating password: {err}"),
    }
}

fn delete_user(username: &str, password: &str) {
    let (user_id, password_hash, salt) = match get_user_info(username) {
        Some(info) => info,
        None => {
            eprintln!("User {username} not found");
            return;
        }
    };

    if !hash_checker(password, &password_hash, &salt) {
        eprintln!("Incorrect password");
        return;
    };

    let curr_conn = conn();

    let result = curr_conn.execute(
        "DELETE FROM users WHERE user_id = ?1",
        params![user_id]
    );

    match result {
        Ok(_) => println!("User {username} deleted successfully"),
        Err(err) => eprintln!("Error deleting user: {err}")
    }
}

pub fn run() {
    let matches = Command::new("Rust password manager")
        .version("0.1.0")
        .author("Simeon Hristov")
        .about("A password manager written in Rust")
        .subcommand(Command::new("save")
            .about("Save a password")
            .arg(Arg::new("username").required(true).index(1))
            .arg(Arg::new("password").required(true).index(2))
            .arg(Arg::new("website").required(true).index(3))
            .arg(Arg::new("new_password").required(true).index(4)))
        .subcommand(Command::new("create")
            .about("Create a new user account")
            .arg(Arg::new("username").required(true).index(1))
            .arg(Arg::new("password").required(true).index(2)))
        .subcommand(Command::new("get")
            .about("Get a stored password")
            .arg(Arg::new("username").required(true).index(1))
            .arg(Arg::new("password").required(true).index(2))
            .arg(Arg::new("website").required(true).index(3)))
        .subcommand(Command::new("change_user_password")
            .about("Changing the main user password")
            .arg(Arg::new("username").required(true).index(1))
            .arg(Arg::new("password").required(true).index(2))
            .arg(Arg::new("new_password").required(true).index(3)))
        .subcommand(Command::new("delete_user")
            .about("Delete user")
            .arg(Arg::new("username").required(true).index(1))
            .arg(Arg::new("password").required(true).index(2)))
        .get_matches();

    match matches.subcommand() {
        Some(("save", save_matches)) => {
            let username = save_matches.get_one::<String>("username").unwrap().as_str();
            let password = save_matches.get_one::<String>("password").unwrap().as_str();
            let website = save_matches.get_one::<String>("website").unwrap().as_str();
            let new_password = save_matches.get_one::<String>("new_password").unwrap().as_str();

            save_password(username, password, website, new_password);
        }
        Some(("create", create_matches)) => {
            let username = create_matches.get_one::<String>("username").unwrap().as_str();
            let password = create_matches.get_one::<String>("password").unwrap().as_str();

            user_creation(username, password);
        }
        Some(("get", get_matches)) => {
            let username = get_matches.get_one::<String>("username").unwrap().as_str();
            let password = get_matches.get_one::<String>("password").unwrap().as_str();
            let website = get_matches.get_one::<String>("website").unwrap().as_str();

            get_password(username, password, website);
        }
        Some(("change_user_password", change_user_password_matches)) => {
            let username = change_user_password_matches.get_one::<String>("username").unwrap().as_str();
            let password = change_user_password_matches.get_one::<String>("password").unwrap().as_str();
            let new_password = change_user_password_matches.get_one::<String>("new_password").unwrap().as_str();

            change_user_password(username, password, new_password);
        }
        Some(("delete_user", delete_user_matches)) => {
            let username = delete_user_matches.get_one::<String>("username").unwrap().as_str();
            let password = delete_user_matches.get_one::<String>("password").unwrap().as_str();

            delete_user(username, password);
        }
        _ => println!("Invalid command. Use 'save' or 'info'.")
    }
}