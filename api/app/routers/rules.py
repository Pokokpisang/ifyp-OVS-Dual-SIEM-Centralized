from fastapi import APIRouter, Request
from fastapi.templating import Jinja2Templates
from fastapi.responses import HTMLResponse, RedirectResponse
from ..detection.engine.rule_loader import RuleLoader

router = APIRouter()
templates = Jinja2Templates(directory="templates")


@router.get("/rules", include_in_schema=False)
def redirect_rules():
    """Legacy path — detection rules moved under /detection/rules."""
    return RedirectResponse(url="/detection/rules", status_code=302)


@router.get("/detection/rules", response_class=HTMLResponse)
def view_rules(request: Request):
    loader = RuleLoader()
    yaml_rules = loader.load_rules_from_directory(loader.rules_path, include_disabled=True)
    yaml_rules.sort(key=lambda r: (r.mitre.get("tactic", {}).get("id", ""), r.id))
    return templates.TemplateResponse("rules.html", {"request": request, "yaml_rules": yaml_rules})
