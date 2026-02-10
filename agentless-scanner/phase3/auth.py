import asyncio
from winrt.windows.security.credentials.ui import UserConsentVerifier, UserConsentVerificationResult

async def authenticate_user():
    # Trigger Windows Hello (Face, Fingerprint, or PIN)
    result = await UserConsentVerifier.request_verification_async(
        "Authenticate to start the application"
    )

    if result == UserConsentVerificationResult.VERIFIED:
        print("Access Granted!")
    else:
        print("Access Denied or Canceled.")
        exit(1)

if __name__ == "__main__":
    try:
        asyncio.run(authenticate_user())
    except Exception as e:
        print(f"Error: {e}")