pub mod ru_pws_mng_modules;
use ring::error::Unspecified;

use rusqlite::{params, Connection, Result};

fn conn() -> Connection {
    Connection::open_in_memory().unwrap()
}

fn table_creation() {
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
        FOREIGN KEY (user_id) REFERENCES users(user_id)
    );";

    let result = conn().execute(query, ());

    match result {
        Ok(_) => println!("Tables created"),
        Err(err) => eprintln!("Error creating tables: {}", err)
    }
}

fn user_creation(username: &str, password: &str) {
    let (hashed_password, salt) = match ru_pws_mng_modules::hashing_functions::hashing_function(password) {
        Ok((hash, salt)) => (hash, salt),
        Err(err) => {
            eprintln!("Error hashing password: {}", err);
            return;
        }
    };

    let result = conn().execute("INSERT INTO users (username, hashed_password, salt) VALUES (?1, ?2);", (&username, &hashed_password, &salt));

    match result {
        Ok(_) => println!("User created"),
        Err(err) => eprintln!("Error creating user: {}", err)
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