import os

from fastapi import APIRouter, Form, Request
from fastapi.responses import HTMLResponse, RedirectResponse
from fastapi.templating import Jinja2Templates

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/login", response_class=HTMLResponse)
def login_page(request: Request):
    return templates.TemplateResponse("login.html", {"request": request, "error": None})


@router.post("/login")
async def login(
    request: Request,
    username: str = Form(...),
    password: str = Form(...),
):
    import bcrypt as _bcrypt

    expected_user = os.getenv("DASHBOARD_USERNAME", "")
    expected_hash = os.getenv("DASHBOARD_PASSWORD_HASH", "")

    try:
        password_matches = bool(expected_hash) and _bcrypt.checkpw(
            password.encode("utf-8"),
            expected_hash.encode("utf-8"),
        )
    except Exception:
        password_matches = False

    valid = bool(expected_user) and username == expected_user and password_matches
    if valid:
        request.session["authenticated"] = True
        return RedirectResponse(url="/dashboard", status_code=303)

    return templates.TemplateResponse(
        "login.html",
        {"request": request, "error": "Invalid credentials."},
        status_code=401,
    )


@router.post("/logout")
async def logout(request: Request):
    request.session.clear()
    return RedirectResponse(url="/login", status_code=303)
