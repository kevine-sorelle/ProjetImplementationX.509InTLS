import pytest
from src.app import app

@pytest.fixture
def client():
    app.config['TESTING'] = True
    with app.app_context():
        with app.test_client() as client:
            yield client

def test_index(client):
    # Arrange
    # Act
    response = client.get('/')
    # Assert
    assert response.status_code == 200
    assert b'Certificate Validator' in response.data
    assert b'form' in response.data.lower()

def test_validate_certificate(client):
    # Arrange
    test_data = {
        'hostname': 'google.com',
        'port': 443,
        'validators': ['signature', 'key', 'issuer', 'date', 'revocation', 'extension']
    }
    # Act
    response = client.post('/', data=test_data, follow_redirects=True)
    # Assert
    assert response.status_code == 200
    assert b'Validation Results' in response.data

def test_generate_certificate(client):
    # Arrange
    test_data = {
        'hostname': 'google.com',
        'port': 443,
        'validators': ['signature', 'key', 'issuer', 'date', 'revocation', 'extension']
    }
    # Act
    response = client.post('/generator', data=test_data, follow_redirects=True)
    # Assert
    assert response.status_code == 200
    assert b'Certificate Generator' in response.data

def test_download_certificate(client):
    # Arrange
    test_data = {
        'hostname': 'google.com',
        'port': 443,
        'validators': ['signature', 'key', 'issuer', 'date', 'revocation', 'extension']
    }
    # Act
    response = client.post('/download', data=test_data, follow_redirects=True)
    # Assert
    assert response.status_code == 200
    assert b'certificate' in response.data.lower()

def test_tests(client):
    # Arrange
    test_data = {
        'hostname': 'google.com',
        'port': 443,
        'validators': ['signature', 'key', 'issuer', 'date', 'revocation', 'extension']
    }
    # Act
    response = client.post('/tests', data=test_data, follow_redirects=True)
    # Assert
    assert response.status_code == 200
    assert b'Certificate Validator' in response.data








