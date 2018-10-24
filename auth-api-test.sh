docker build -t auth-check .
docker run -d --name auth-check -p 8002:8080 auth-check
newman run tests_auth_check.postman_collection.json 
docker stop auth-check 
docker rm auth-check 
docker rmi auth-check
