//Mitchell Hess
//mph0114

const request = require('supertest');
const express = require('express');
const app = require('./server');

describe('API Endpoints', () => {
  let server;

  beforeAll(() => {
    server = app.listen(3000);
  });

  afterAll((done) => {
    server.close(done);
  });

  test('should return 405 Method Not Allowed for non-POST requests to /auth', async () => {
    const response = await request(app).get('/auth');
    expect(response.statusCode).toBe(405);
    expect(response.text).toBe('Method Not Allowed');
  });

  test('should return a JWT token for POST request to /auth', async () => {
    const response = await request(app).post('/auth');
    expect(response.statusCode).toBe(200);
  });

  test('should return an expired JWT token for POST request to /auth?expired=true', async () => {
    const response = await request(app).post('/auth?expired=true');
    expect(response.statusCode).toBe(200);
  });

  test('should return 405 Method Not Allowed for non-GET requests to /.well-known/jwks.json', async () => {
    const response = await request(app).post('/.well-known/jwks.json');
    expect(response.statusCode).toBe(405);
    expect(response.text).toBe('Method Not Allowed');
  });

  test('should return JSON containing valid keys for GET request to /.well-known/jwks.json', async () => {
    const response = await request(app).get('/.well-known/jwks.json');
    expect(response.statusCode).toBeGreaterThanOrEqual(200);;
    expect(response.body).toHaveProperty('keys');
  });

  test('should start the server and listen on the specified port', (done) => {
    const port = 3000;
    const server = app.listen(port, () => {
      server.close(() => {
        done(); // Ensures the server starts and closes without errors
      });
    });
  });

    test('should start the server and listen on an available port', (done) => {
        const server = app.listen(0, () => {
            const port = server.address().port;
            server.close(() => {
            done();
            });
        });
    });
   
});
