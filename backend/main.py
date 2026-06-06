import os
from datetime import datetime, timedelta
from typing import Optional, List
from fastapi import FastAPI, HTTPException, Depends, Query, status
from fastapi.security import OAuth2PasswordBearer, OAuth2PasswordRequestForm
from pydantic import BaseModel, EmailStr
import pymysql
from fastapi.middleware.cors import CORSMiddleware
import jwt
import bcrypt

app = FastAPI(title="Employee Management API")

# Allow frontend to access the API
app.add_middleware(
    CORSMiddleware,
    allow_origins=["*"],
    allow_credentials=True,
    allow_methods=["*"],
    allow_headers=["*"],
)

# Database connection configuration (use env vars)
DB_HOST = os.getenv("DB_HOST", "localhost")
DB_USER = os.getenv("DB_USER", "root")
DB_PASSWORD = os.getenv("DB_PASSWORD", "")
DB_NAME = os.getenv("DB_NAME", "employee_db")

def get_db():
    conn = pymysql.connect(
        host=DB_HOST,
        user=DB_USER,
        password=DB_PASSWORD,
        database=DB_NAME,
        cursorclass=pymysql.cursors.DictCursor
    )
    try:
        yield conn
    finally:
        conn.close()

# --- Security & JWT Config ---
SECRET_KEY = os.getenv("JWT_SECRET", "supersecretkey")
ALGORITHM = "HS256"
ACCESS_TOKEN_EXPIRE_MINUTES = 60

oauth2_scheme = OAuth2PasswordBearer(tokenUrl="token")

def verify_password(plain_password: str, hashed_password: str):
    try:
        return bcrypt.checkpw(plain_password.encode('utf-8'), hashed_password.encode('utf-8'))
    except Exception:
        # Fallback for plain-text passwords manually inserted into the database
        return plain_password == hashed_password

def get_password_hash(password: str):
    return bcrypt.hashpw(password.encode('utf-8'), bcrypt.gensalt()).decode('utf-8')

def create_access_token(data: dict, expires_delta: Optional[timedelta] = None):
    to_encode = data.copy()
    if expires_delta:
        expire = datetime.utcnow() + expires_delta
    else:
        expire = datetime.utcnow() + timedelta(minutes=15)
    to_encode.update({"exp": expire})
    return jwt.encode(to_encode, SECRET_KEY, algorithm=ALGORITHM)

async def get_current_user(token: str = Depends(oauth2_scheme), db = Depends(get_db)):
    credentials_exception = HTTPException(
        status_code=status.HTTP_401_UNAUTHORIZED,
        detail="Could not validate credentials",
        headers={"WWW-Authenticate": "Bearer"},
    )
    try:
        payload = jwt.decode(token, SECRET_KEY, algorithms=[ALGORITHM])
        username: str = payload.get("sub")
        role: str = payload.get("role")
        if username is None or role is None:
            raise credentials_exception
    except jwt.PyJWTError:
        raise credentials_exception
        
    with db.cursor() as cursor:
        table = "Admin" if role == "Admin" else "Users"
        cursor.execute(f"SELECT * FROM {table} WHERE Username = %s", (username,))
        user = cursor.fetchone()
        if user is None:
            raise credentials_exception
            
    return {"username": username, "role": role}

def require_admin(current_user: dict = Depends(get_current_user)):
    if current_user["role"] != "Admin":
        raise HTTPException(status_code=403, detail="Not enough permissions")
    return current_user

# --- Pydantic Models ---
class EmployeeBase(BaseModel):
    Name: str
    Email: EmailStr
    Department: str
    Salary: Optional[float] = None

class EmployeeCreate(EmployeeBase):
    Salary: float

class EmployeeUpdate(EmployeeBase):
    Salary: float

class EmployeeResponse(EmployeeBase):
    EmployeeId: int
    CreatedDate: datetime

class PaginatedEmployeeResponse(BaseModel):
    data: List[EmployeeResponse]
    total: int
    page: int
    limit: int

class Token(BaseModel):
    access_token: str
    token_type: str
    role: str

# --- Authentication Endpoint ---
@app.post("/token", response_model=Token)
async def login_for_access_token(form_data: OAuth2PasswordRequestForm = Depends(), db = Depends(get_db)):
    with db.cursor() as cursor:
        cursor.execute("SELECT *, 'Admin' as Role FROM Admin WHERE Username = %s", (form_data.username,))
        user = cursor.fetchone()
        if not user:
            cursor.execute("SELECT *, 'User' as Role FROM Users WHERE Username = %s", (form_data.username,))
            user = cursor.fetchone()
            
    if not user or not verify_password(form_data.password, user['PasswordHash']):
        raise HTTPException(
            status_code=status.HTTP_401_UNAUTHORIZED,
            detail="Incorrect username or password",
            headers={"WWW-Authenticate": "Bearer"},
        )
        
    access_token_expires = timedelta(minutes=ACCESS_TOKEN_EXPIRE_MINUTES)
    access_token = create_access_token(
        data={"sub": user["Username"], "role": user["Role"]}, expires_delta=access_token_expires
    )
    return {"access_token": access_token, "token_type": "bearer", "role": user["Role"]}


# --- API Endpoints ---
@app.post("/employees/", status_code=201)
def add_employee(emp: EmployeeCreate, db = Depends(get_db), current_user = Depends(require_admin)):
    try:
        with db.cursor() as cursor:
            sql = "INSERT INTO Employee (Name, Email, Department, Salary) VALUES (%s, %s, %s, %s)"
            cursor.execute(sql, (emp.Name, emp.Email, emp.Department, emp.Salary))
        db.commit()
        return {"message": "Employee created successfully"}
    except pymysql.MySQLError as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")

@app.get("/employees/", response_model=PaginatedEmployeeResponse)
def list_employees(
    search: Optional[str] = None,
    sort_by: Optional[str] = Query("EmployeeId", pattern="^(EmployeeId|Name|Salary)$"),
    order: Optional[str] = Query("asc", pattern="^(asc|desc)$"),
    page: int = Query(1, ge=1),
    limit: int = Query(10, ge=1, le=100),
    db = Depends(get_db),
    current_user = Depends(get_current_user)
):
    offset = (page - 1) * limit
    
    query = "SELECT * FROM Employee"
    count_query = "SELECT COUNT(*) as total FROM Employee"
    params = []
    
    if search:
        search_term = f"%{search}%"
        query += " WHERE Name LIKE %s OR Department LIKE %s OR Email LIKE %s"
        count_query += " WHERE Name LIKE %s OR Department LIKE %s OR Email LIKE %s"
        params.extend([search_term, search_term, search_term])
        
    query += f" ORDER BY {sort_by} {order.upper()} LIMIT %s OFFSET %s"
    params.extend([limit, offset])
    
    with db.cursor() as cursor:
        cursor.execute(count_query, params[:-2] if search else [])
        total = cursor.fetchone()['total']
        
        cursor.execute(query, params)
        data = cursor.fetchall()
        
    # RBAC: Hide salary for regular users
    if current_user["role"] == "User":
        for emp in data:
            emp["Salary"] = None
            
    return {"data": data, "total": total, "page": page, "limit": limit}

@app.get("/employees/{emp_id}")
def get_employee(emp_id: int, db = Depends(get_db), current_user = Depends(get_current_user)):
    with db.cursor() as cursor:
        cursor.execute("SELECT * FROM Employee WHERE EmployeeId = %s", (emp_id,))
        result = cursor.fetchone()
        if not result:
            raise HTTPException(status_code=404, detail="Employee not found")
            
        if current_user["role"] == "User":
            result["Salary"] = None
            
        return result

@app.put("/employees/{emp_id}")
def update_employee(emp_id: int, emp: EmployeeUpdate, db = Depends(get_db), current_user = Depends(require_admin)):
    try:
        with db.cursor() as cursor:
            sql = "UPDATE Employee SET Name=%s, Email=%s, Department=%s, Salary=%s WHERE EmployeeId=%s"
            affected_rows = cursor.execute(sql, (emp.Name, emp.Email, emp.Department, emp.Salary, emp_id))
            if affected_rows == 0:
                raise HTTPException(status_code=404, detail="Employee not found")
        db.commit()
        return {"message": "Employee updated successfully"}
    except pymysql.MySQLError as e:
        raise HTTPException(status_code=400, detail=f"Database error: {e}")

@app.delete("/employees/{emp_id}", status_code=204)
def delete_employee(emp_id: int, db = Depends(get_db), current_user = Depends(require_admin)):
    with db.cursor() as cursor:
        affected_rows = cursor.execute("DELETE FROM Employee WHERE EmployeeId = %s", (emp_id,))
        if affected_rows == 0:
            raise HTTPException(status_code=404, detail="Employee not found")
    db.commit()

if __name__ == "__main__":
    import uvicorn
    uvicorn.run("main:app", host="0.0.0.0", port=8000, reload=True)
