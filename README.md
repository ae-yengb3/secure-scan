# SecureScanX Backend README

## Introduction

This is the backend for the SecureScanX web application. It is a Django-based application that provides a RESTful API for user authentication, vulnerability scanning, and an AI-powered security assistant. It uses Django Channels for real-time WebSocket communication to provide live updates to the frontend.

## Features

* **User Authentication:** JWT-based authentication for secure access to the API.
* **Vulnerability Scanning:** Integrates with OWASP ZAP to perform active and spider scans on target URLs.
* **Leak Scanning:** Scans for data leaks associated with a domain.
* **Hybrid Scanning:** Combines vulnerability and leak scanning for comprehensive security analysis.
* **Real-time Scan Updates:** Uses WebSockets to provide real-time scan progress updates to the frontend.
* **AI Security Assistant:** An AI-powered assistant that can answer questions about security vulnerabilities and provide remediation advice.
* **Vulnerability Management:** Allows users to mark vulnerabilities as resolved or as false positives.

## Technologies Used

The backend is built with the following technologies:

* Django
* Django REST Framework
* Django Channels
* djangorestframework-simplejwt
* OWASP ZAP
* google-genai
* Daphne

A full list of dependencies can be found in `requirements.txt`.

## API Endpoints

The following API endpoints are available:

* `POST /secure/create/user/`: Create a new user.
* `POST /secure/login/`: Obtain a JWT token pair for authentication.
* `POST /secure/token/refresh/`: Refresh an expired JWT access token.
* `GET /secure/me/`: Get the details of the currently authenticated user.
* `POST /secure/start/scan/`: Start a new security scan.
* `GET /secure/scans/`: Get a list of all scans for the authenticated user.
* `GET /secure/reports/`: Get a summary of all scan reports for the authenticated user.
* `POST /secure/mark-resolved/`: Mark a vulnerability as resolved.
* `POST /secure/mark-false-positive/`: Mark a vulnerability as a false positive.

## WebSockets

The application uses Django Channels to provide real-time communication between the backend and the frontend. The WebSocket consumer is located at `secure/consumers.py` and handles incoming WebSocket connections. It authenticates users using a JWT token passed as a query parameter in the WebSocket URL. Once a connection is established, the backend can send real-time updates about scan progress to the client.

## Scanning Engine

The scanning engine is implemented in `secure/zap.py`. It uses the `zaproxy` library to interact with an OWASP ZAP instance. It can perform both spider and active scans. The results of the scans are saved to the database. The leak scanning functionality uses the DeHashed API to search for data leaks associated with a given domain.

## AI Assistant

The AI assistant is powered by the Google Generative AI API. It takes a user's message, selected vulnerabilities, and conversation history as input and provides a detailed, formatted response.

## Database Models

The application uses the following database models, defined in `secure/models.py`:

* **User:** A custom user model that stores user information, including email, password, full name, and location.
* **Scan:** Stores information about a security scan, including the target URL, the user who initiated the scan, the scan progress, and start/end times.
* **ScanResult:** Stores the results of a security scan, including the alert name, risk level, description, solution, and other details.

## Setup and Running

To run the backend, you will need to have Python and the dependencies listed in `requirements.txt` installed. You will also need to have an instance of OWASP ZAP running. The `run.md` file provides an example command for starting the Daphne server.
