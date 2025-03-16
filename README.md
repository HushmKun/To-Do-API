# ToDo API

This project is a simple REST API for managing ToDo items, built using Django Rest Framework (DRF). It provides endpoints for creating, listing, retrieving, updating, and deleting ToDo items.  User authentication is required for most operations.

[Repo Link](https://github.com/HushmKun/To-Do-API)

## Features

*   **User Authentication:** Uses SimpleJWT authentication system.
*   **User Modification:** User can Modify his data and/or change password.
*   **ToDo Management:**
    *   Create ToDo items.
    *   List ToDo items (with pagination, filtering, searching, and ordering).
    *   Retrieve a specific ToDo item.
    *   Update ToDo items.
    *   Delete ToDo items.
*   **Permissions:** Only authenticated users can create, view, update, or delete their own ToDo items.  Users cannot access ToDo items belonging to other users.
*   **Filtering:**  ToDo items can be filtered by `status` (e.g., "todo", "in_progress", "done").
*   **Searching:**  ToDo items can be searched by `title`.
*   **Ordering:**  ToDo items can be ordered by `title` or `created_at`.
*   **Pagination:** Lists of ToDo items are paginated to improve performance and usability.

## Technologies Used

*   **Python:** Programming language.
*   **Django:** High-level Python web framework.
*   **Django Rest Framework (DRF):**  A powerful toolkit for building Web APIs.
*   **django-filter:** Provides support for filtering REST framework list views.

## Setup and Installation

1.  **Clone the repository:**

2.  **Create a virtual environment (recommended):**

    ```bash
    python3 -m venv venv
    source venv/bin/activate  # On Linux/macOS
    venv\Scripts\activate  # On Windows
    ```

3.  **Install dependencies:**

    ```bash
    pip install -r requirements.txt
    ```

4.  **Apply migrations:**

    ```bash
    python manage.py migrate
    ```

5.  **Create a superuser (for admin access):**

    ```bash
    python manage.py createsuperuser
    ```

6.  **Run the development server:**

    ```bash
    python manage.py runserver
    ```

    The API will be available at `http://localhost:8000/`.

## API Endpoints

*   **User Registration:** `POST /api/v1/users/register/` (Requires: `first_name`, `last_name`, `DoB`, `email`, `password`, `password2`)
*   **User Login:** `POST /api/v1/users/login/` (Requires: `email`, `password`)
*   **User Refresh:** `POST /api/v1/users/refresh/` (Requires authentication)
*   **Change Password:** `POST /api/v1/users/change_password/` (Requires authentication, requires `password`, `password2`)
*   **Password Reset Email:** `POST /api/v1/users/send_reset/` (Requires: `email`)
*   **Password Reset:** `POST /api/v1/users/reset_password/<uid>/<token>/` (Requires: `password`, `password2`) - The GET request renders password reset page.
*   **Profile:** `GET /api/v1/users/profile/`, `PATCH /api/v1/users/profile/` (Requires authentication)

*   **ToDo List/Create:** `GET /api/v1/todos/`, `POST /api/v1/todos/` (Requires authentication)
    *   `GET` parameters: `status` (filter by status), `search` (search by title), `ordering` (e.g., `title`, `-created_at`), `page`, `page_size`.
*   **ToDo Detail/Update/Delete:** `GET /api/v1/todos/<pk>/`, `PUT /api/v1/todos/<pk>/`, `DELETE /api/todos/<pk>/` (Requires authentication)

## Authentication

Most API endpoints require authentication using JWT (JSON Web Tokens).

1.  **Obtain a JWT token:** 
    *   Log in using the `POST /api/v1/users/login/`.
    *   The response will contain an `access` & `refresh` token.

2.  **Include the JWT token in the `Authorization` header of your requests:**

    ```
    Authorization: Bearer <your_access_token>
    ```

## Running Tests

1.  **Install the requirments:**

    ```bash
    pip install -r requirements.txt
    ```

2.  **Run the tests:**
    ```bash
    python manage.py test
    ```