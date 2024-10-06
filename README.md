# URL Shortening Application

This is a simple PHP-based URL shortening application that allows users to shorten long URLs and optionally provide a custom short key. The application includes CSRF protection and utilizes a MySQL database for storing the URLs.

## Features

- Shorten long URLs
- Custom short key option
- CSRF protection
- Simple routing system
- Database interaction using prepared statements

## Requirements

- PHP 7.0 or higher
- MySQL
- Apache or Nginx server
- Composer (optional for autoloading)

## Installation

1. Clone this repository or download the code files.
2. Create a MySQL database and import the provided SQL script to create the necessary table.

### Database Setup

```sql
CREATE TABLE `urls` (
  `id` INT NOT NULL AUTO_INCREMENT,
  `original_url` VARCHAR(2048) NOT NULL,
  `short_key` VARCHAR(6) NOT NULL UNIQUE,
  PRIMARY KEY (`id`)
);
```

3. Update the database connection settings in the PHP file:

```php
$servername = "localhost"; // your server name
$username = "your_username"; // your database username
$password = "your_password"; // your database password
$dbname = "your_database"; // your database name
```

4. Ensure the server is set up to run PHP files.

## Usage

1. Access the application in your web browser.
2. Enter a long URL into the input field.
3. Optionally, enter a custom short URL.
4. Click the "Shorten" button to generate the shortened URL.
5. The application will display the shortened URL, which can be clicked to redirect to the original URL.

### API Endpoints

- **GET `/`**: Displays the main form for URL shortening.
- **POST `/shorten`**: Accepts a long URL and an optional custom short key to create a shortened URL.
- **GET `/shortKey`**: Redirects to the original URL corresponding to the provided short key.
