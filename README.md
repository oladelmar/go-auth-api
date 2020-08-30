# Simple Auth Service

## Description

A simple auth service written in Go
(Test task, first task written in Go language)

# API Endpoints

## Create tokens [POST /api/v1/auth/tokens]

- Request:
  Content-type: application/json

  - Body

  {
  "user_id": {user id}
  }

* Response: 200

  - Body

    {
    "\_id": {Mongo ID},
    "user_id": {Proveded user id},
    "access_token": {JWT},
    "refresh_token": {base64 encoded JWT}
    }

## Refresh Access Token [PUT /api/v1/auth/tokens]

- Request:
  Content-type: application/json

  - Body

    {
    "access_token": {JWT},
    "refresh_token": {base64 encoded JWT}
    }

* Response: 200

  - Body

    {
    "\_id": {Mongo ID},
    "user_id": {Proveded user id},
    "access_token": {JWT},
    "refresh_token": {base64 encoded JWT}
    }

## Delete Refresh Token [DELETE /api/v1/auth/tokens/{base64_encoded_refresh_token}]

- Response: 204

## Delete All Refresh Tokens for User [DELETE /api/v1/auth/tokens/users/{user_id}]

- Response: 204
