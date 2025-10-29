# VCC PKI System - API Router Configuration
# Main API router with all endpoints including TSA

from fastapi import APIRouter
from app.api.v1 import certificates, users, auth, health, tsa

# Create main API router
api_router = APIRouter(prefix="/api/v1")

# Include all endpoint routers
api_router.include_router(auth.router)
api_router.include_router(certificates.router) 
api_router.include_router(users.router)
api_router.include_router(health.router)
api_router.include_router(tsa.router)  # New TSA endpoints

__all__ = ["api_router"]