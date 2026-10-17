"""Pydantic v2 data models for Vulnify user management, authentication, and health."""

import re
from typing import Literal
from pydantic import BaseModel, Field, field_validator

EMAIL_REGEX = re.compile(r"^[a-zA-Z0-9_.+-]+@[a-zA-Z0-9-]+\.[a-zA-Z0-9-.]+$")


class RegisterRequest(BaseModel):
    name: str = Field(..., min_length=1, max_length=100, description="User full name")
    email: str = Field(..., min_length=3, max_length=255, description="Unique user email address")
    password: str = Field(
        ...,
        min_length=8,
        max_length=128,
        description="Password (minimum 8 characters)",
    )

    @field_validator("name")
    @classmethod
    def validate_name(cls, v: str) -> str:
        cleaned = v.strip()
        if not cleaned:
            raise ValueError("Name cannot be empty or whitespace only.")
        return cleaned

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format.")
        return cleaned


class LoginRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255, description="Registered user email address")
    password: str = Field(..., min_length=1, max_length=128, description="User password")

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format.")
        return cleaned


class UserResponse(BaseModel):
    id: str
    email: str
    name: str
    role: Literal["user", "admin"]


class RoleUpdateRequest(BaseModel):
    email: str = Field(..., min_length=3, max_length=255)
    role: Literal["user", "admin"]

    @field_validator("email")
    @classmethod
    def validate_email(cls, v: str) -> str:
        cleaned = v.strip().lower()
        if not EMAIL_REGEX.match(cleaned):
            raise ValueError("Invalid email format.")
        return cleaned


class HealthResponse(BaseModel):
    status: str = "healthy"
