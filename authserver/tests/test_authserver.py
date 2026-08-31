import pytest 
from authserver.app import app 
from werkzeug.utils import import_string

@pytest.fixture
def client():    
    app.config['TESTING'] = True  # Enable testing mode
    app.config.from_object(import_string('authserver.config.TestingConfig')())
    with app.test_client() as client:
        yield client

def test_non_existent_route(client):
    """Test for a non-existent route."""
    response = client.post('/non-existent', headers={ 'Authorization': 'Bearer xyz', 'HBNS-APP-ID': 'test_consumer', 'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 404

def test_missing_authorization_headers(client):
    """Test missing authorization headers"""
    response = client.post('/generate', json={ "aud":[], "projects": [] }, headers={ 'HBNS-APP-ID': 'test_consumer', 'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 400
    response = client.post('/refresh', headers={ 'HBNS-APP-ID': 'test_consumer', 'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 400
    response = client.post('/revoke', headers={ 'HBNS-APP-ID': 'test_consumer', 'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 400

def test_missing_required_headers(client):
    """Test missing required headers"""
    response = client.post('/generate', json={ "aud":[], "projects": [] }, headers={ 'Authorization': 'Basic asdasdad:asdasdasd', 'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 400
    response = client.post('/refresh', headers={ 'Authorization': 'Bearer xyz',  'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 400
    response = client.post('/revoke', headers={ 'Authorization': 'Bearer xyz', 'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 400
    
    response = client.post('/generate', json={ "aud":[], "projects": [] }, headers={ 'Authorization': 'Basic asdasdad:asdasdasd', 'HBNS-APP-ID': 'test_consumer' })
    assert response.status_code == 400 
    response = client.post('/refresh', headers={ 'Authorization': 'Bearer xyz', 'HBNS-APP-ID': 'test_consumer'})
    assert response.status_code == 400 
    response = client.post('/revoke', headers={ 'Authorization': 'Bearer xyz', 'HBNS-APP-ID': 'test_consumer'})
    assert response.status_code == 400

def test_generate(client, mocker):
    mock_db = mocker.patch("authserver.app.db")
    mock_db.find_account_by_username.return_value = { 'username': 'userx', 'password': 'pwdx', 'projects': ['testproject'], 'authorize_clients': ['test_consumer'], 'is_admin': False, 'approved_aud': [ 'test_aud' ] }    
    response = client.post('/generate', json={ "aud":[], "projects": [] }, headers={ 'Authorization': 'Basic dXNlcng6cHdkeA==', 'HBNS-APP-ID': 'test_consumer', 'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 200

def test_generate_with_aud(client, mocker):
    mock_db = mocker.patch("authserver.app.db")
    mock_db.find_account_by_username.return_value = { 'username': 'userx', 'password': 'pwdx', 'projects': ['testproject'], 'authorize_clients': ['test_consumer'], 'is_admin': False, 'approved_aud': [ 'test_aud' ] }    
    response = client.post('/generate', json={ "aud":[  'test_aud' ], "projects": [] }, headers={ 'Authorization': 'Basic dXNlcng6cHdkeA==', 'HBNS-APP-ID': 'test_consumer', 'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 200

def test_generate_with_custom_claims(client, mocker):
    mock_db = mocker.patch("authserver.app.db")
    mock_db.find_account_by_username.return_value = { 'username': 'userx', 'password': 'pwdx', 'projects': ['testproject'], 'authorize_clients': ['test_consumer'], 'is_admin': False, 'approved_aud': [ 'test_aud' ] }    
    response = client.post('/generate', json={ "aud":[  'test_aud' ], "projects": [], 'custom_claims': { 'claim1': 'val1' } }, headers={ 'Authorization': 'Basic dXNlcng6cHdkeA==', 'HBNS-APP-ID': 'test_consumer', 'HBNS-TRACE-ID': 'trace123'})
    assert response.status_code == 200


def test_refresh(client, mocker):
    mock_db = mocker.patch("authserver.app.db")
    mock_db.get_refresh_token.return_value = { 'refresh_token': 'xxx.xxx.xxx', 'username': 'userx', 'used': True, 'revoked': False, 'client_id': 'test_consumer', 'uuid': '13057763-575b-407f-b110-5483e471c0d4'  }
    mock_header_util = mocker.patch("authserver.app.header_util.authenticate_bearer")
    mock_header_util.return_value = {
        "aud": [ "test_aud" ], 
        "sub": "userx", 
        'iss': 'authservice', 
        'jti': '37e1b0ca-9b1f-40e3-a12d-43200491d10f', 
        'iat': 1788141261, 
        'exp': 1788314061, 
        'nbf': 1788141261,
        'admin': False,
        'projects': ['testproject' ]
    }

    response = client.post('/refresh', headers={ 'Authorization': 'Bearer eyJhbGciOiJSUzI1NiIsInR5cCI6IkpXVCJ9.eyJzdWIiOiJ0b290bGVzIiwiYXVkIjpbInByb2plY3RzZXJ2aWNlIiwiY3JvY2hldGVkbHkiXSwiaXNzIjoiYXV0aHNlcnZpY2UiLCJqdGkiOiIzN2UxYjBjYS05YjFmLTQwZTMtYTEyZC00MzIwMDQ5MWQxMGYiLCJpYXQiOjE3ODgxNDEyNjEsImV4cCI6MTc4ODMxNDA2MSwibmJmIjoxNzg4MTQxMjYxLCJwcm9qZWN0cyI6WyJjcm9jaGV0ZWRseSJdLCJhZG1pbiI6ZmFsc2UsImZvb051bSI6MTIzLCJmb29TdHIiOiJibGFoIn0.Yv4fO8d1bgh29nPfXretxD5S3nkY6v1VEI88eEEShEQ5932ZR-Mbs2SeKt55t_sae_GGQPDktAa7x_Pz4hvDb4OAjwNm6evpuOZGShQ6AtQf7GXIBKbCMEwh0jd5As_4GUjS2Tm0pvzS9-BpfRtcHjOA43L6X52bWR3LGhCx8ab2MRYeITVIShamcNjjWZwlJK6Je3MBwzbqmUOI2AIbnn5Tjl0DCvXXdToPhm33FSozCxDkn7vsmhdzwhf28XIL6vDjo9DMhlNmTN_fFsoIeS-DB9KZDYkH_zkt-OHiKXTa9Uah4EfyRGv7Rsd5QSPxSx1FmpHeT2TZhEzwP3sX1JGx3mfgAmUDxHSbeE5NietRaV5vQyLHmJCuErjHKdvsD3HYGRcMaRaIR38FiDz0xs5wk_y1J5fXDI2Uh9aXd9m-WrnU58LQmeY-4JJE0Pn8CxdWyfbIRfLa56ZfIpF-QlVTq2cUy5sgEiSVAy9y6DuGZJ8W3MeEopcHveFNIG-2', 'HBNS-APP-ID': 'test_consumer', 'HBNS-TRACE-ID': 'trace123'} )
    assert response.status_code == 401
