## _Topic - ATM Manegment System_

## Overview

The Virtual ATM Machine System is a web application built using Flask and SQLAlchemy, designed to simulate basic ATM functionalities. Users can register, log in, withdraw, deposit, and transfer funds securely. The application includes an admin panel for managing user transactions and viewing transaction history.

## Features

- **User Registration**: Users can create an account with a unique username, password, transaction PIN, and VID (a unique identifier).
- **User Authentication**: Secure login and session management.
- **Withdrawals**: Users can withdraw funds while validating their transaction PIN.
- **Deposits**: Users can deposit funds into their account with PIN validation.
- **Transfers**: Users can transfer funds to other users using their unique VID.
- **Transaction History**: Users can view their past transactions.
- **Admin Dashboard**: Admin users can view all transactions across the system.

## Technologies Used

- **Flask**: A micro web framework for Python.
- **SQLAlchemy**: ORM for managing database operations.
- **SQLite**: Lightweight database for storing user and transaction data.
- **Werkzeug**: For secure password hashing and validation.
- **Pytz**: For timezone management (Indian Standard Time).
- **HTML/CSS**: For the front-end user interface.

### **Steps to run the application**
    1.Download the repository and open the folder in command prompt
    2.Run the command pip install -r requirements.txt, now let it install
    3.To start the webapp now run "Flask run"
    4.Now go to the given IP address.
