import requests
import json

# Test the Flask API endpoints
BASE_URL = "http://localhost:5000"

def test_home():
    print("Testing home endpoint...")
    response = requests.get(f"{BASE_URL}/")
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    print()

def test_routes():
    print("Testing routes endpoint...")
    response = requests.get(f"{BASE_URL}/routes")
    print(f"Status: {response.status_code}")
    print(f"Response: {json.dumps(response.json(), indent=2)}")
    print()

def test_register():
    print("Testing register endpoint...")
    data = {
        "name": "Test User",
        "email": "test@example.com",
        "password": "password123"
    }
    response = requests.post(f"{BASE_URL}/register", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    print()

def test_login():
    print("Testing login endpoint...")
    data = {
        "email": "test@example.com",
        "password": "password123"
    }
    response = requests.post(f"{BASE_URL}/login", json=data)
    print(f"Status: {response.status_code}")
    print(f"Response: {response.text}")
    print()

if __name__ == "__main__":
    print("Testing Flask API endpoints...")
    print("=" * 50)
    
    test_home()
    test_routes()
    test_register()
    test_login()
    
    print("Testing complete!") 