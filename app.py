import streamlit as st
import sqlite3
import hashlib
from PIL import Image
import pytesseract
from PyPDF2 import PdfReader
import os
from openai import OpenAI
# from dotenv import load_dotenv

# load_dotenv()

# Configuration
UPLOAD_FOLDER = "uploads"
DB_PATH = "medical_reports.db"
USER_DB_PATH = "user_credentials.db"
NVIDIA_API_BASE_URL = "https://integrate.api.nvidia.com/v1"
# NVIDIA_API_KEY = "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"

# Create necessary directories
os.makedirs(UPLOAD_FOLDER, exist_ok=True)

# Initialize the OpenAI Client
client = OpenAI(
    base_url=NVIDIA_API_BASE_URL,
    api_key=NVIDIA_API_KEY
)

# Initialize databases
def initialize_user_database():
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS users (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            name TEXT NOT NULL,
            email TEXT UNIQUE NOT NULL,
            password TEXT NOT NULL
        )
    ''')
    conn.commit()
    conn.close()


def extract_text_pdf(pdf_path):
    try:
        reader = PdfReader(pdf_path)
        if reader.is_encrypted:
            reader.decrypt("")
        text = ""
        for page in reader.pages:
            text += page.extract_text() or "[Unable to extract text from this page.]\n"
        return text.strip()
    except Exception as e:
        raise Exception(f"PDF text extraction error: {e}")

def extract_text_image(image_path):
    try:
        image = Image.open(image_path)
        text = pytesseract.image_to_string(image)
        return text.strip()
    except Exception as e:
        raise Exception(f"Image text extraction error: {e}")

def extract_text(file_path):
    if file_path.endswith(".pdf"):
        return extract_text_pdf(file_path)
    return extract_text_image(file_path)

def simplify_text(text):
    prompt = (
        f"Here is a medical report:\n{text}\n\n"
        "1. Summarize the report in simple language.\n"
        "2. Identify the potential health problem(s).\n"
        "3. Provide general health tips related to the problem(s).\n"
        "4. Suggest home remedies if applicable."
    )
    try:
        completion = client.chat.completions.create(
            model="meta/llama-3.1-405b-instruct",
            messages=[{"role": "user", "content": prompt}],
            temperature=0.2,
            top_p=0.7,
            max_tokens=1024,
            stream=True
        )
        response = "".join(chunk.choices[0].delta.content for chunk in completion if chunk.choices[0].delta.content)
        return response
    except Exception as e:
        raise Exception(f"LLM API error: {e}")
    
def save_to_database(file_path, extracted_text, summary):
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute(
        "INSERT INTO reports (file_path, extracted_text, summary) VALUES (?, ?, ?)",
        (file_path, extracted_text, summary)
    )
    conn.commit()
    conn.close()

def process_report(file):
    try:
        file_path = os.path.join(UPLOAD_FOLDER, file.name)
        with open(file_path, "wb") as f:
            f.write(file.getbuffer())

        extracted_text = extract_text(file_path)
        if not extracted_text:
            return "Error: Could not extract text. Please upload a valid report."
        
        summary = simplify_text(extracted_text)
        save_to_database(file_path, extracted_text, summary)
        return summary
    except Exception as e:
        return f"An error occurred: {str(e)}"
    


def initialize_report_database():
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute('''
        CREATE TABLE IF NOT EXISTS reports (
            id INTEGER PRIMARY KEY AUTOINCREMENT,
            file_path TEXT NOT NULL,
            extracted_text TEXT NOT NULL,
            summary TEXT NOT NULL,
            timestamp DATETIME DEFAULT CURRENT_TIMESTAMP
        )
    ''')
    conn.commit()
    conn.close()

def save_user(name, email, password):
    """Save a new user's credentials."""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    try:
        hashed_password = hashlib.sha256(password.encode()).hexdigest()
        cursor.execute("INSERT INTO users (name, email, password) VALUES (?, ?, ?)", (name, email, hashed_password))
        conn.commit()
    except sqlite3.IntegrityError:
        st.error("Email already exists. Please log in.")
    conn.close()

def authenticate_user(email, password):
    """Authenticate user credentials."""
    conn = sqlite3.connect(USER_DB_PATH)
    cursor = conn.cursor()
    hashed_password = hashlib.sha256(password.encode()).hexdigest()
    cursor.execute("SELECT * FROM users WHERE email = ? AND password = ?", (email, hashed_password))
    user = cursor.fetchone()
    conn.close()
    return user

# Initialize databases
initialize_user_database()
initialize_report_database()

# Streamlit app
st.set_page_config(page_title="Medical Report Simplifier", layout="wide")

# Authentication
if "logged_in" not in st.session_state:
    st.session_state.logged_in = False

if not st.session_state.logged_in:
    st.title("Login or Sign Up")

    # Tabs for login and sign-up
    tab1, tab2 = st.tabs(["Login", "Sign Up"])

  # Login tab
    with tab1:
        st.subheader("Login")
        login_email = st.text_input("Email", placeholder="Enter your email", key="login_email")
        login_password = st.text_input("Password", type="password", placeholder="Enter your password", key="login_password")
        if st.button("Log In", key="login_button"):
            user = authenticate_user(login_email, login_password)
            if user:
                st.session_state.logged_in = True
                st.session_state.user = user  # Store user info in session
                st.success(f"Welcome back, {user[1]}!")
            else:
                st.error("Invalid email or password.")

# Sign-Up tab
    with tab2:
        st.subheader("Sign Up")
        sign_up_name = st.text_input("Full Name", placeholder="Enter your full name", key="sign_up_name")
        sign_up_email = st.text_input("Email", placeholder="Enter your email", key="sign_up_email")
        sign_up_password = st.text_input("Password", type="password", placeholder="Create a password", key="sign_up_password")
        if st.button("Sign Up", key="sign_up_button"):
            if sign_up_name and sign_up_email and sign_up_password:
                save_user(sign_up_name, sign_up_email, sign_up_password)
                st.success("Sign up successful! You can now log in.")
            else:
                st.error("Please fill out all fields.")


# Main Application
if st.session_state.logged_in:
    st.sidebar.title(f"Welcome, {st.session_state.user[1]}!")
    if st.sidebar.button("Log Out"):
        st.session_state.logged_in = False
        st.experimental_rerun()

    st.title("Medical Report Simplifier")
    st.write("Upload a medical report (PDF or image) to get a simplified summary.")

    # File Upload
    uploaded_file = st.file_uploader("Upload Medical Report", type=["pdf", "jpg", "png"])
    
    if uploaded_file:
        with st.spinner("Processing your report..."):
            # Save the uploaded file temporarily
            file_path = os.path.join(UPLOAD_FOLDER, uploaded_file.name)
            with open(file_path, "wb") as f:
                f.write(uploaded_file.getbuffer())
            
            # Process the report and get the summary
            try:
                summary = process_report(uploaded_file)  # Call your function to process the report
                st.success("Report processed successfully!")
                st.write("### Summary")
                st.write(summary)  # Display the generated summary
            except Exception as e:
                st.error(f"An error occurred: {e}")

    
    # Sidebar for saved reports
    st.sidebar.title("Saved Reports")
    st.sidebar.write("Click on a report to view details:")
    
    conn = sqlite3.connect(DB_PATH)
    cursor = conn.cursor()
    cursor.execute("SELECT id, file_path, summary, timestamp FROM reports ORDER BY timestamp DESC")
    rows = cursor.fetchall()

    if rows:
        for report_id, file_path, summary, timestamp in rows:
            if st.sidebar.button(f"Report {report_id} - {os.path.basename(file_path)}"):
                st.subheader(f"Report {report_id}")
                st.write(f"**File Name:** {os.path.basename(file_path)}")
                st.write(f"**Summary:** {summary}")
                st.write(f"**Timestamp:** {timestamp}")
    else:
        st.sidebar.write("No saved reports yet.")

    conn.close()
