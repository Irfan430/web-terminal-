/**
 * Test suite for Web Dashboard Server
 */

const request = require('supertest');
const { app, server, io } = require('../web/server');

describe('CyberToolkit Web Server', () => {
    afterAll((done) => {
        server.close(done);
    });

    describe('API Endpoints', () => {
        test('GET /api/status should return system status', async () => {
            const response = await request(app)
                .get('/api/status')
                .expect(200);

            expect(response.body).toHaveProperty('timestamp');
            expect(response.body).toHaveProperty('server', 'online');
            expect(response.body).toHaveProperty('activeScans');
            expect(response.body).toHaveProperty('connectedClients');
        });

        test('GET /api/reports should return reports list', async () => {
            const response = await request(app)
                .get('/api/reports')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
        });

        test('GET /api/scans should return active scans', async () => {
            const response = await request(app)
                .get('/api/scans')
                .expect(200);

            expect(Array.isArray(response.body)).toBe(true);
        });

        test('POST /api/scan should start new scan', async () => {
            const scanData = {
                target: 'test.example.com',
                scanType: 'vulnerability'
            };

            const response = await request(app)
                .post('/api/scan')
                .send(scanData)
                .expect(200);

            expect(response.body).toHaveProperty('scanId');
            expect(response.body).toHaveProperty('message');
        });

        test('POST /api/scan should validate required fields', async () => {
            const response = await request(app)
                .post('/api/scan')
                .send({})
                .expect(400);

            expect(response.body).toHaveProperty('error');
        });

        test('GET /api/stats should return dashboard statistics', async () => {
            const response = await request(app)
                .get('/api/stats')
                .expect(200);

            expect(response.body).toHaveProperty('totalScans');
            expect(response.body).toHaveProperty('highRiskTargets');
            expect(response.body).toHaveProperty('mediumRiskTargets');
            expect(response.body).toHaveProperty('lowRiskTargets');
        });
    });

    describe('Error Handling', () => {
        test('Should handle non-existent routes', async () => {
            await request(app)
                .get('/api/nonexistent')
                .expect(404);
        });

        test('Should handle invalid scan types', async () => {
            const response = await request(app)
                .post('/api/scan')
                .send({
                    target: 'test.com',
                    scanType: 'invalid_type'
                })
                .expect(200); // Server accepts but will handle gracefully

            expect(response.body).toHaveProperty('scanId');
        });
    });

    describe('Security', () => {
        test('Should have CORS enabled', async () => {
            const response = await request(app)
                .get('/api/status')
                .expect(200);

            expect(response.headers).toHaveProperty('access-control-allow-origin');
        });

        test('Should handle malformed JSON', async () => {
            await request(app)
                .post('/api/scan')
                .send('invalid json')
                .type('json')
                .expect(400);
        });
    });
});

describe('Socket.io Integration', () => {
    let clientSocket;

    beforeAll((done) => {
        // Start server if not already running
        if (!server.listening) {
            server.listen(() => {
                const port = server.address().port;
                clientSocket = require('socket.io-client')(`http://localhost:${port}`);
                clientSocket.on('connect', done);
            });
        } else {
            const port = server.address().port;
            clientSocket = require('socket.io-client')(`http://localhost:${port}`);
            clientSocket.on('connect', done);
        }
    });

    afterAll(() => {
        if (clientSocket) {
            clientSocket.close();
        }
    });

    test('Should connect to socket server', (done) => {
        expect(clientSocket.connected).toBe(true);
        done();
    });

    test('Should receive active scans on connection', (done) => {
        clientSocket.on('activeScans', (scans) => {
            expect(Array.isArray(scans)).toBe(true);
            done();
        });
    });

    test('Should handle scan events', (done) => {
        clientSocket.on('scanStarted', (scan) => {
            expect(scan).toHaveProperty('id');
            expect(scan).toHaveProperty('target');
            expect(scan).toHaveProperty('scanType');
            done();
        });

        // Trigger a scan to test event
        request(app)
            .post('/api/scan')
            .send({
                target: 'socket-test.com',
                scanType: 'vulnerability'
            })
            .end(() => {}); // Don't wait for response
    });
});

describe('File Operations', () => {
    test('Should serve static files', async () => {
        await request(app)
            .get('/')
            .expect(200)
            .expect('Content-Type', /html/);
    });

    test('Should handle non-existent reports', async () => {
        await request(app)
            .get('/api/reports/nonexistent.json')
            .expect(404);
    });
});

describe('Performance', () => {
    test('API endpoints should respond quickly', async () => {
        const start = Date.now();
        await request(app).get('/api/status');
        const duration = Date.now() - start;
        
        expect(duration).toBeLessThan(1000); // Should respond within 1 second
    });

    test('Should handle multiple concurrent requests', async () => {
        const requests = Array(10).fill().map(() => 
            request(app).get('/api/status')
        );

        const responses = await Promise.all(requests);
        
        responses.forEach(response => {
            expect(response.status).toBe(200);
        });
    });
});

describe('Health Checks', () => {
    test('Health endpoint should be available', async () => {
        const response = await request(app)
            .get('/api/status')
            .expect(200);

        expect(response.body.server).toBe('online');
    });

    test('Should report system metrics', async () => {
        const response = await request(app)
            .get('/api/status')
            .expect(200);

        expect(response.body).toHaveProperty('uptime');
        expect(response.body).toHaveProperty('memory');
        expect(typeof response.body.uptime).toBe('number');
    });
});