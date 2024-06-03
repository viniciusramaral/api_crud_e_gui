import tkinter as tk
from tkinter import ttk, messagebox, filedialog
import requests
from cryptography.fernet import Fernet
import base64

ENCRYPTION_KEY = b'_u75tDBKx0sKZzzq5VHzQBgE0d4RQZqDNTmAvKqEKOs='

# URLs da API
BASE_URL = 'http://127.0.0.1:5000'
REGISTER_URL = f'{BASE_URL}/register'
LOGIN_URL = f'{BASE_URL}/login'
REPORTS_URL = f'{BASE_URL}/reports'

# Variável global para armazenar o token de autenticação
token = None

#Criptografar elementos
def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted_data).decode('utf-8')

#Registrar usuários
def register_user(first_name, last_name, email, password):
    data = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'password': password
    }
    response = requests.post(REGISTER_URL, json=data)
    return handle_response(response)

#Login de usuário
def login_user(email, password):
    data = {
        'email': email,
        'password': password
    }
    response = requests.post(LOGIN_URL, json=data)
    return handle_response(response)

#Criar relatório
def create_report(token, latitude, longitude, pollutant_type, pollutant_image):
    headers = {'Authorization': f'Bearer {token}'}
    data = {
        'latitude': encrypt_data(str(latitude), ENCRYPTION_KEY),
        'longitude': encrypt_data(str(longitude), ENCRYPTION_KEY),
        'pollutant_type': encrypt_data(pollutant_type, ENCRYPTION_KEY),
        'pollutant_image': encrypt_data(pollutant_image, ENCRYPTION_KEY)
    }
    response = requests.post(REPORTS_URL, json=data, headers=headers)
    return handle_response(response)

#Gerenciar acessos e respostas
def handle_response(response):
    try:
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')  # HTTP error
        messagebox.showerror("HTTP Error", f"HTTP error occurred: {http_err}")
    except requests.exceptions.RequestException as req_err:
        print(f'Request error occurred: {req_err}')  # Request error
        messagebox.showerror("Request Error", f"Request error occurred: {req_err}")
    except ValueError:
        print(f'Response content is not valid JSON: {response.text}')
        messagebox.showerror("Invalid Response", f"Response content is not valid JSON: {response.text}")
    return None

#Registrar
def register():
    first_name = entry_first_name.get()
    last_name = entry_last_name.get()
    email = entry_email.get()
    password = entry_password.get()
    registration_response = register_user(first_name, last_name, email, password)
    messagebox.showinfo("Registration", str(registration_response))

#Login
def login():
    global token
    email = entry_email_login.get()
    password = entry_password_login.get()
    login_response = login_user(email, password)
    if login_response and 'access_token' in login_response:
        token = login_response['access_token']
        messagebox.showinfo("Login", "Login successful")
        tab_control.select(tab_report)
    else:
        messagebox.showerror("Login", "Failed to log in")

#Enviar relatório
def submit_report():
    if not token:
        messagebox.showerror("Authentication", "Please login first")
        return
    
    latitude = entry_latitude.get()
    longitude = entry_longitude.get()
    pollutant_type = entry_pollutant_type.get()
    pollutant_image = entry_pollutant_image.get()

    report_response = create_report(token, latitude, longitude, pollutant_type, pollutant_image)
    messagebox.showinfo("Report", str(report_response))

#Carregar imagem
def browse_image():
    filename = filedialog.askopenfilename()
    entry_pollutant_image.delete(0, tk.END)
    entry_pollutant_image.insert(0, filename)

#Carregar relatório
def get_reports(token):
    headers = {'Authorization': f'Bearer {token}'}
    response = requests.get(REPORTS_URL, headers=headers)
    return handle_response(response)

#Exibir relatórios
def show_reports():
    global token
    if not token:
        messagebox.showerror("Authentication", "Please login first")
        return

    reports = get_reports(token)
    if reports:
        report_list.delete(0, tk.END)
        for report in reports:
            report_list.insert(tk.END, f"Latitude: {report['latitude']}, Longitude: {report['longitude']}, Type: {report['pollutant_type']}")


#Aqui inicia-se a abertura da janela de interface com o usuário
app = tk.Tk()
app.title("Environmental Report System")

# Top frame with logo
top_frame = tk.Frame(app)
top_frame.pack(side=tk.TOP, fill=tk.X)
logo_image = tk.PhotoImage(file="logo.png")  # Replace "logo.png" with your logo file
label_logo = tk.Label(top_frame, image=logo_image)
label_logo.pack(pady=10)

# Tab control
tab_control = ttk.Notebook(app)
tab_control.pack(expand=1, fill="both")

# Login Tab
tab_login = ttk.Frame(tab_control)
tab_control.add(tab_login, text="Login")
label_email_login = tk.Label(tab_login, text="Email")
label_email_login.pack(pady=5)
entry_email_login = tk.Entry(tab_login)
entry_email_login.pack(pady=5)

label_password_login = tk.Label(tab_login, text="Password")
label_password_login.pack(pady=5)
entry_password_login = tk.Entry(tab_login, show="*")
entry_password_login.pack(pady=5)

button_login = tk.Button(tab_login, text="Login", command=login)
button_login.pack(pady=20)

# Report Tab
tab_report = ttk.Frame(tab_control)
tab_control.add(tab_report, text="Report")

label_latitude = tk.Label(tab_report, text="Latitude")
label_latitude.grid(row=0, column=0, pady=5)
entry_latitude = tk.Entry(tab_report)
entry_latitude.grid(row=0, column=1, pady=5)

label_longitude = tk.Label(tab_report, text="Longitude")
label_longitude.grid(row=1, column=0, pady=5)
entry_longitude = tk.Entry(tab_report)
entry_longitude.grid(row=1, column=1, pady=5)

label_pollutant_type = tk.Label(tab_report, text="Pollutant Type")
label_pollutant_type.grid(row=2, column=0, pady=5)
entry_pollutant_type = tk.Entry(tab_report)
entry_pollutant_type.grid(row=2, column=1, pady=5)

label_pollutant_image = tk.Label(tab_report, text="Pollutant Image")
label_pollutant_image.grid(row=3, column=0, pady=5)
entry_pollutant_image = tk.Entry(tab_report)
entry_pollutant_image.grid(row=3, column=1, pady=5)

button_browse = tk.Button(tab_report, text="Browse", command=browse_image)
button_browse.grid(row=3, column=2, pady=5)

button_submit_report = tk.Button(tab_report, text="Submit Report", command=submit_report)
button_submit_report.grid(row=4, column=0, columnspan=3, pady=20)

tab_report_list = ttk.Frame(tab_control)
tab_control.add(tab_report_list, text="Report List")

report_list = tk.Listbox(tab_report_list, width=100, height=20)
report_list.pack(pady=10, padx=10)

button_show_reports = tk.Button(tab_report_list, text="Show Reports", command=show_reports)
button_show_reports.pack(pady=10)

# Registration Tab
tab_register = ttk.Frame(tab_control)
tab_control.add(tab_register, text="Register")
label_first_name = tk.Label(tab_register, text="First Name")
label_first_name.pack(pady=5)
entry_first_name = tk.Entry(tab_register)
entry_first_name.pack(pady=5)

label_last_name = tk.Label(tab_register, text="Last Name")
label_last_name.pack(pady=5)
entry_last_name = tk.Entry(tab_register)
entry_last_name.pack(pady=5)

label_email = tk.Label(tab_register, text="Email")
label_email.pack(pady=5)
entry_email = tk.Entry(tab_register)
entry_email.pack(pady=5)

label_password = tk.Label(tab_register, text="Password")
label_password.pack(pady=5)
entry_password = tk.Entry(tab_register, show="*")
entry_password.pack(pady=5)

button_register = tk.Button(tab_register, text="Register", command=register)
button_register.pack(pady=20)

app.mainloop()