#=====================================================
#=====================================================
#Os views contém as rotas de acesso e controle
#de permissões do sistema
#=====================================================
#=====================================================
from flask import request, jsonify
from app import app, db
from models import User, Report
from utils import decrypt_data, pad_base64
from flask_jwt_extended import create_access_token, jwt_required, get_jwt_identity
from werkzeug.security import generate_password_hash, check_password_hash
import base64

# Substitua por sua própria chave gerada
ENCRYPTION_KEY = b'_u75tDBKx0sKZzzq5VHzQBgE0d4RQZqDNTmAvKqEKOs='

@app.route('/register', methods=['POST'])
def register():
    data = request.get_json()
    hashed_password = generate_password_hash(data['password'], method='pbkdf2:sha256')
    new_user = User(first_name=data['first_name'], last_name=data['last_name'], email=data['email'], password=hashed_password)
    db.session.add(new_user)
    db.session.commit()
    return jsonify({'message': 'User created successfully'}), 201

@app.route('/login', methods=['POST'])
def login():
    data = request.get_json()
    user = User.query.filter_by(email=data['email']).first()
    if user and check_password_hash(user.password, data['password']):
        access_token = create_access_token(identity=user.id)
        return jsonify(access_token=access_token)
    else:
        return jsonify({'message': 'Invalid credentials'}), 401

@app.route('/reports', methods=['POST'])
@jwt_required()
def create_report():
    data = request.get_json()
    user_id = get_jwt_identity()
    
    decrypted_latitude = float(decrypt_data(base64.b64decode(pad_base64(data['latitude'])), ENCRYPTION_KEY))
    decrypted_longitude = float(decrypt_data(base64.b64decode(pad_base64(data['longitude'])), ENCRYPTION_KEY))
    decrypted_pollutant_type = decrypt_data(base64.b64decode(pad_base64(data['pollutant_type'])), ENCRYPTION_KEY)
    decrypted_pollutant_image = decrypt_data(base64.b64decode(pad_base64(data['pollutant_image'])), ENCRYPTION_KEY)
    
    new_report = Report(user_id=user_id, latitude=decrypted_latitude, longitude=decrypted_longitude, 
                        pollutant_type=decrypted_pollutant_type, pollutant_image=decrypted_pollutant_image)
    db.session.add(new_report)
    db.session.commit()
    return jsonify({'message': 'Report created successfully'}), 201

@app.route('/reports', methods=['GET'])
@jwt_required()
def get_reports():
    user_id = get_jwt_identity()
    reports = Report.query.filter_by(user_id=user_id).all()
    output = []
    for report in reports:
        report_data = {
            'id': report.id,
            'timestamp': report.timestamp,
            'latitude': report.latitude,
            'longitude': report.longitude,
            'pollutant_type': report.pollutant_type,
            'pollutant_image': report.pollutant_image
        }
        output.append(report_data)
    return jsonify(output)

@app.route('/reports/<report_id>', methods=['PUT'])
@jwt_required()
def update_report(report_id):
    data = request.get_json()
    user_id = get_jwt_identity()
    report = Report.query.filter_by(id=report_id, user_id=user_id).first()
    if not report:
        return jsonify({'message': 'Report not found'}), 404
    
    report.latitude = float(decrypt_data(base64.b64decode(pad_base64(data['latitude'])), ENCRYPTION_KEY))
    report.longitude = float(decrypt_data(base64.b64decode(pad_base64(data['longitude'])), ENCRYPTION_KEY))
    report.pollutant_type = decrypt_data(base64.b64decode(pad_base64(data['pollutant_type'])), ENCRYPTION_KEY)
    report.pollutant_image = decrypt_data(base64.b64decode(pad_base64(data['pollutant_image'])), ENCRYPTION_KEY)
    
    db.session.commit()
    return jsonify({'message': 'Report updated successfully'})

@app.route('/reports/<report_id>', methods=['DELETE'])
@jwt_required()
def delete_report(report_id):
    user_id = get_jwt_identity()
    report = Report.query.filter_by(id=report_id, user_id=user_id).first()
    if not report:
        return jsonify({'message': 'Report not found'}), 404
    
    db.session.delete(report)
    db.session.commit()
    return jsonify({'message': 'Report deleted successfully'})
