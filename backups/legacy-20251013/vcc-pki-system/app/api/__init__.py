# VCC PKI System - API Package
# Centralized API router management

from fastapi import APIRouter
from app.api.auth import router as auth_router

# Main API router
api_router = APIRouter(prefix="/api")

# Include all sub-routers
api_router.include_router(auth_router, tags=["Authentication"])

__all__ = ["api_router"]