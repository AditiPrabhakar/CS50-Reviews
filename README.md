# CS50 Reviews
CS50 Reviews Website is an interactive web application designed to allow users to share and explore reviews related to CS50x or any other CS50 course. This project aims to create a vibrant community where users can rate and discuss their experiences with the course, provide feedback, and connect with others.

The website is built with a user-friendly interface, ensuring seamless navigation through various features such as user authentication, posting reviews, viewing others' reviews, and interacting with them through upvotes and downvotes. It also includes a dedicated FAQs page and links to CS50x lectures and other CS50 courses.

The project is built using Flask for the backend, HTML, CSS, and Bootstrap for the frontend, and SQL for the database. Sessions and cookies are implemented to ensure a secure and personalized user experience.

## Features

1. **User Authentication**:
    - Users can log in or sign up securely.
    - Validation is implemented to handle edge cases, ensuring accurate and secure data handling.
    - Sessions and cookies are used to maintain user login states.

2. **Create Reviews**:
    - Users can write and submit reviews related to CS50.
    - The interface is designed to be intuitive, encouraging users to share their thoughts.

3. **View Reviews**:
    - Users can browse reviews posted by others.
    - Reviews are displayed with details like the number of upvotes and downvotes.

4. **Upvote/Downvote System**:
    - Users can engage with reviews by upvoting or downvoting them.
    - The interaction system is dynamic and responsive.
    - User can either upvote or downvote a particular review.

5. **User Dashboard**:
    - Users can view their profile and statistics, including the number of reviews they've posted, total upvotes, and total downvotes they've received.

6. **FAQs Page**:
    - A dedicated FAQs page modeled after the official Harvard CS50 FAQ page.
    - Includes links to CS50x lectures and other CS50 courses for users' reference.

7. **Validation**:
    - Robust validation mechanisms to handle edge cases during login, signup, and review posting.
    - Ensures clean and accurate data input.

## File Descriptions

### 1. **app.py**
   - The main Flask application file that defines the routes and logic for the website.
   - Manages user authentication, session handling, and database queries.
   - Implements the backend functionality for creating, viewing, and interacting with reviews.

### 2. **templates/**
   - Contains all the HTML files for the website's pages:
     - `index.html`: Starting page of the website where users can login or sign up.
     - `home.html`: The homepage with navigation links, user stats, and a welcoming interface.
     - `login.html`: Login page for user authentication.
     - `signup.html`: Sign-up page for new users.
     - `post-review.html`: Page for creating a review.
     - `showreviews.html`: Displays all user-submitted reviews.
     - `failure.html`: To return error messages and error codes for validation checking.
     - `faqs.html`: Contains the FAQs page and links to CS50 resources.

### 3. **static/**
   - Contains CSS file:
     - `styles.css`: Custom styles for the website, ensuring a visually appealing and responsive layout.

### 4. **reviews.db**
   - SQLite database storing user data, reviews, and vote counts.
   - Tables include `users`, `reviews`, and `votes` with relationships to ensure data integrity.
     - **Schema**:
    ```sql

    CREATE TABLE users (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        username TEXT NOT NULL,
        hash TEXT NOT NULL,
        reviews_count INT DEFAULT 0,
        total_upvotes INT DEFAULT 0,
        total_downvotes INT DEFAULT 0
    );

    CREATE TABLE reviews (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        username TEXT NOT NULL,
        review TEXT NOT NULL,
        upvotes INT DEFAULT 0,
        downvotes INT DEFAULT 0
    );

    CREATE TABLE votes (
        id INTEGER PRIMARY KEY AUTOINCREMENT,
        user_id INTEGER NOT NULL,
        review_id INTEGER NOT NULL,
        vote_type TEXT NOT NULL
    );
    ```

### 5. **README.md**
   - This file, documenting the project, its functionality, and design decisions.

## Design Choices

### User Authentication
- **Decision**: Implemented sessions and cookies for secure login/logout functionality.
- **Reason**: To ensure users' data and session integrity without exposing sensitive information.

### FAQs Page
- **Decision**: Cloned the official Harvard CS50 FAQ page layout.
- **Reason**: To provide a familiar and reliable resource for users while adding relevant links to CS50 courses.

### Validation
- **Decision**: Included edge case handling for inputs during login and sign-up.
- **Reason**: To prevent invalid or malicious inputs and ensure data consistency in the database.

### Reviews Layout
- **Decision**: Designed reviews to display upvotes, downvotes.
- **Reason**: To enhance user engagement and provide clear review metrics.

### Upvote/Downvote System
- **Decision**: Allowed users to interact dynamically with reviews.
- **Reason**: To foster community engagement and prioritize valuable feedback.

## Final Thoughts

This project has been a rewarding experience, allowing me to explore various aspects of web development, from backend logic to frontend design. By integrating user authentication, interactive review features, and a FAQs page, I aimed to create a platform that is both functional and engaging.

I welcome any feedback on this project and hope it adds value to the CS50 community!
