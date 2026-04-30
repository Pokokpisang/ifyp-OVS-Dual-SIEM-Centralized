import sys
import os
from sqlalchemy import create_engine, inspect

engine = create_engine("sqlite:////home/pokokpisang/Desktop/FYP/ifyp/prototype/agent/api/siem.db")
inspector = inspect(engine)
print(inspector.get_table_names())
