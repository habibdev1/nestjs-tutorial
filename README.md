# NestJS Microservices E-commerce Platform

This project is a robust, scalable, and maintainable e-commerce backend built with NestJS, demonstrating a microservices architecture within a monorepo setup. It showcases advanced features such as multi-tenancy, role-based access control (RBAC), JWT authentication, Redis caching, and an API Gateway for centralized request handling.

## Features

*   **User Authentication & Authorization**:
    *   User Registration and Login
    *   One-Time Password (OTP) based Login
    *   Account Lock/Unlock mechanism
    *   Session Control, Refresh Tokens, and Logout
    *   Role-Based Access Control (RBAC)
*   **Multi-Tenancy**: Tenant-specific data isolation using MongoDB, ensuring each tenant's data is logically separated.
*   **Product Management**: Comprehensive CRUD (Create, Read, Update, Delete) operations for products.
*   **Tenant Management**: CRUD operations for managing tenants within the system.
*   **Redis Caching**: Implemented for improved performance and responsiveness, with tenant-aware caching strategies.
*   **API Gateway**: A single entry point for all client requests, responsible for routing, security (authentication/authorization), and request validation.
*   **Email Notifications**: Integration for sending email notifications for events like OTP and account lock.
*   **Swagger API Documentation**: Automatically generated API documentation for easy exploration and testing of endpoints.

## Technologies Used

*   **NestJS**: A progressive Node.js framework for building efficient, reliable and scalable server-side applications.
*   **TypeScript**: A typed superset of JavaScript that compiles to plain JavaScript.
*   **Microservices**: Architectural style with inter-service communication over TCP.
*   **MongoDB**: A NoSQL document database used for persistent data storage, supporting multi-tenancy.
*   **Redis**: An in-memory data structure store, used as a database, cache, and message broker.
*   **JWT (JSON Web Tokens)**: For secure authentication and authorization.
*   **Swagger**: For interactive API documentation.
*   **Mongoose**: MongoDB object modeling for Node.js.

## Project Structure

The project is organized as a monorepo, containing multiple applications (`apps/`) and shared libraries (`libs/`).

*   **`apps/`**: Contains individual microservices:
    *   `api-gateway`: The public-facing entry point, handling all incoming HTTP requests, authentication, authorization, and routing to appropriate microservices.
    *   `auth-service`: Manages user authentication, registration, login (including OTP), session management, and account security.
    *   `product-service`: Handles all business logic related to products, including CRUD operations and product-specific data.
    *   `tenant-service`: Manages tenant-related operations, including tenant registration and details.
    *   `user-service`: (If distinct from `auth-service`, handles user profile management or specific user-related data not directly part of authentication).
*   **`libs/`**: Contains shared libraries and modules used across different microservices to promote code reusability and maintainability:
    *   `auth-lib`: Provides authentication strategies (JWT), guards (AuthGuard, RolesGuard), and decorators.
    *   `common-lib`: Houses common utilities, DTOs, response structures, and API decorators (e.g., `ApiTenantHeader`).
    *   `database-lib`: Manages database connections, especially tailored for multi-tenancy to provide tenant-specific MongoDB connections.
    *   `email-lib`: Handles email sending functionalities and templates (e.g., for OTP, welcome emails).
    *   `logger-lib`: Provides a centralized logging mechanism.
    *   `redis-lib`: Encapsulates Redis caching logic and interactions.

## Getting Started

### Prerequisites

Before you begin, ensure you have the following installed:

*   **Node.js**: (LTS version recommended)
*   **npm** or **Yarn**: Package manager
*   **MongoDB**: Running instance (e.g., via Docker, or local installation)
*   **Redis**: Running instance (e.g., via Docker, or local installation)
*   **Docker** (Optional, but recommended for easy setup of MongoDB and Redis)

### Installation

1.  **Clone the repository:**
    ```bash
    git clone git@github.com:habibdev1/nestjs-tutorial.git
    cd nestjs-tutorial
    ```
2.  **Install dependencies:**
    ```bash
    npm install
    # or
    yarn install
    ```

### Environment Variables

Create a `.env` file in the root directory of the project based on the `.env.example` (if available, otherwise refer to the `step2-environment.md` file for required variables). Key environment variables will include database connection strings, Redis connection details, JWT secrets, and email service credentials.

### Running the Application

This project can be run as a set of individual microservices. A convenient `run-all.sh` script is provided in the `tools/` directory to start all services simultaneously.

1.  **Start all microservices (recommended):**
    ```bash
    ./tools/run-all.sh
    ```
2.  **Alternatively, run services individually:**
    ```bash
    # Example for API Gateway
    npm start api-gateway

    # Example for Auth Service
    npm start auth-service
    ```
    You would need to start all dependent services for the application to function correctly.

The `api-gateway` will typically run on `http://localhost:3000` (or configured port).

## API Documentation

Once the application is running, you can access the Swagger UI for API documentation at:
`http://localhost:3000/api-docs` (adjust port if different).

## Contribution

Contributions are welcome! Please ensure your code adheres to the existing architectural patterns and coding standards.

## License

This project is licensed under the MIT License.
