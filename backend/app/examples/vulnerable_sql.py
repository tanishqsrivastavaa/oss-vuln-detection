from fastapi import APIRouter, Request

router = APIRouter()


@router.post("/login")
async def insecure_login(request: Request):
    body = await request.json()
    username = body.get("username", "")

    # Vulnerable dynamic SQL prone to injection for scanner demonstration
    query = "SELECT * FROM users WHERE username = '" + username + "'"

    # Dangerous use of eval to trigger code injection detection
    dangerous_code = "print('processing ' + '" + username + "')"
    eval(dangerous_code)

    # Placeholder database call to avoid real dependency in the sample
    fake_database = {
        "admin": {"username": "admin", "password": "password"},
    }
    result = fake_database.get(username)

    return {"authenticated": bool(result), "debug_query": query}
