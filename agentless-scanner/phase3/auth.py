import asyncio
from winrt.windows.security.credentials.ui import UserConsentVerifier, UserConsentVerificationResult


async def verify_windows_hello(prompt: str) -> bool:
    result = await UserConsentVerifier.request_verification_async(prompt)
    return result == UserConsentVerificationResult.VERIFIED


def verify_windows_hello_sync(prompt: str) -> bool:
    try:
        asyncio.get_running_loop()
    except RuntimeError:
        return asyncio.run(verify_windows_hello(prompt))

    loop = asyncio.new_event_loop()
    try:
        return loop.run_until_complete(verify_windows_hello(prompt))
    finally:
        loop.close()


if __name__ == "__main__":
    ok = verify_windows_hello_sync("Authenticate to start the vulnerability scan")
    raise SystemExit(0 if ok else 1)