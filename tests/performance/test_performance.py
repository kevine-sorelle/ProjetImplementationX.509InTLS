import pytest
from src.app import app  # Importing the Flask app

@pytest.fixture
def client():
    # Fixture pour le client de test
    app.config['TESTING'] = True
    with app.app_context():
        with app.test_client() as client:
            yield client

def test_index_get_performance(client):
    response = client.get('/')
    assert response.status_code == 200

def test_index_post_performance(benchmark, client):
    # Test de la performance de la fonction index avec le client de test
    test_data = {
        'hostname': 'facebook.com',
        'port': 443,
        'validators': ['signature', 'key', 'issuer', 'date', 'revocation', 'extension', 'algorithm', 'subject']
    }

    def do_request():
        return client.post('/', data=test_data, follow_redirects=True)
    
    benchmark(do_request)
    response = client.post('/', data=test_data)
    assert response.status_code == 200

def test_index_get_performance_with_data(client):
    response = client.get('/')
    assert response.status_code == 200
    assert b'Certificate Validator' in response.data  # Updated assertion to match actual content

def test_generator_get_performance(client):
    response = client.get('/generator')
    assert response.status_code == 200

def test_generator_post_performance(benchmark, client):
    test_data = {
        'hostname': 'facebook.com',
        'port': 443,
        'validators': ['SignatureValidator', 'KeyValidator', 'IssuerValidator', 'DateValidator', 'RevocationValidator', 'ExtensionValidator', 'AlgorithmValidator']
    }

    def do_request():
        return client.post('/generator', data=test_data, follow_redirects=True)
    
    response = benchmark(do_request)
    assert response.status_code == 200

def test_download_get_performance(client):
    response = client.get('/download')
    assert response.status_code == 200

    
    
    
    










