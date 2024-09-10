from fastapi import APIRouter, HTTPException, Depends
from app.models import User
from app.database import users_collection
from app.auth.schemas import UserCreate, UserResponse
from passlib.hash import bcrypt

router = APIRouter()

@router.post("/register", response_model=UserResponse)
async def register(user: UserCreate):
    existing_user = await users_collection.find_one({"email": user.email})
    if existing_user:
        raise HTTPException(status_code=400, detail="User already exists")
    
    hashed_password = bcrypt.hash(user.password)
    user_data = {"email": user.email, "password": hashed_password}
    new_user = await users_collection.insert_one(user_data)
    created_user = await users_collection.find_one({"_id": new_user.inserted_id})
    return UserResponse(email=created_user["email"])

@router.post("/login")
async def login(user: UserCreate):
    existing_user = await users_collection.find_one({"email": user.email})
    if not existing_user or not bcrypt.verify(user.password, existing_user["password"]):
        raise HTTPException(status_code=400, detail="Invalid credentials")
    
    return {"message": "Login successful"}
