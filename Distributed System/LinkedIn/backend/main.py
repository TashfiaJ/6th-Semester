from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel, EmailStr
from bcrypt import checkpw, gensalt, hashpw
import jwt

app = FastAPI()

# Temporary data store to simulate user registration
fake_user_db = {}


# Step 2: Create a Pydantic model for the user registration request
class UserRegistrationRequest(BaseModel):
    email: EmailStr
    password: str


# Step 3: Define the /register route to handle user registration
@app.post("/register/", status_code=201)
def register_user(user_data: UserRegistrationRequest):
    email = user_data.email
    password = user_data.password

    # Check if the email is already registered
    if email in fake_user_db:
        raise HTTPException(status_code=400, detail="Email already registered")

    # Store the user in the temporary database (you should use a real database in production)
    fake_user_db[email] = {"email": email, "password": password}

    # Return a success message
    return {"message": "User registered successfully"}

# Step 4: Create a Pydantic model for the user login request
class UserLoginRequest(BaseModel):
    email: EmailStr
    password: str


# Step 5: Define the /login route to handle user login and JWT generation
@app.post("/login/", status_code=200)
def login_user(user_data: UserLoginRequest):
    email = user_data.email
    password = user_data.password.encode("utf-8")  # Encode the password to bytes

    # Check if the email exists in the database
    if email not in fake_user_db:
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Retrieve the hashed password from the database
    hashed_password = fake_user_db[email]["password"]

    # Verify the provided password with the hashed password
    if not checkpw(password, hashed_password):
        raise HTTPException(status_code=401, detail="Invalid credentials")

    # Generate a JWT token (you can customize the payload and expiration time as needed)
    jwt_payload = {"email": email}
    jwt_token = jwt.encode(jwt_payload, "your-secret-key", algorithm="HS256")

    # Return the JWT token
    return {"token": jwt_token}
