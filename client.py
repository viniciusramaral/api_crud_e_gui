#=====================================================
#=====================================================
#Client feito somente para testes de conexão com a API
#=====================================================
#=====================================================


import requests
from cryptography.fernet import Fernet
import base64

# Substitua pela chave de criptografia usada no servidor
ENCRYPTION_KEY = b'_u75tDBKx0sKZzzq5VHzQBgE0d4RQZqDNTmAvKqEKOs='

# URLs da API
BASE_URL = 'http://127.0.0.1:5000'
REGISTER_URL = f'{BASE_URL}/register'
LOGIN_URL = f'{BASE_URL}/login'
REPORTS_URL = f'{BASE_URL}/reports'

def encrypt_data(data, key):
    f = Fernet(key)
    encrypted_data = f.encrypt(data.encode('utf-8'))
    return base64.b64encode(encrypted_data).decode('utf-8')

def register_user(first_name, last_name, email, password):
    data = {
        'first_name': first_name,
        'last_name': last_name,
        'email': email,
        'password': password
    }
    response = requests.post(REGISTER_URL, json=data)
    return handle_response(response)

def login_user(email, password):
    data = {
        'email': email,
        'password': password
    }
    response = requests.post(LOGIN_URL, json=data)
    return handle_response(response)

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

def handle_response(response):
    try:
        response.raise_for_status()
        return response.json()
    except requests.exceptions.HTTPError as http_err:
        print(f'HTTP error occurred: {http_err}')  # HTTP error
    except requests.exceptions.RequestException as req_err:
        print(f'Request error occurred: {req_err}')  # Request error
    except ValueError:
        print(f'Response content is not valid JSON: {response.text}')
    return None

if __name__ == '__main__':
    # Exemplo de uso
    first_name = 'John'
    last_name = 'Doe'
    email = 'john.doe@example.com'
    password = 'securepassword'

    # Registrar usuário
    print("Registering user...")
    registration_response = register_user(first_name, last_name, email, password)
    print("Registration response:", registration_response)

    # Logar usuário
    print("\nLogging in...")
    login_response = login_user(email, password)
    print("Login response:", login_response)

    if login_response and 'access_token' in login_response:
        token = login_response['access_token']
        
        # Criar relatório
        print("\nCreating report...")
        latitude = 37.7749
        longitude = -122.4194
        pollutant_type = 'CO2'
        pollutant_image = base64.b64encode(b'This is a test image').decode('utf-8')  # Example image in base64

        report_response = create_report(token, latitude, longitude, pollutant_type, pollutant_image)
        print("Report response:", report_response)
    else:
        print("Failed to log in.")
