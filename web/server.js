/**
 * CyberToolkit Web Dashboard Server
 * Express.js + Socket.io for real-time security monitoring
 */

const express = require('express');
const http = require('http');
const socketIo = require('socket.io');
const fs = require('fs').promises;
const path = require('path');
const cors = require('cors');
const winston = require('winston');
const { spawn } = require('child_process');

// Initialize Express app
const app = express();
const server = http.createServer(app);
const io = socketIo(server, {
    cors: {
        origin: "*",
        methods: ["GET", "POST"]
    }
});

// Configuration
const PORT = process.env.WEB_PORT || 3000;
const REPORTS_DIR = path.join(__dirname, '..', 'reports');
const LOGS_DIR = path.join(__dirname, '..', 'logs');

// Setup Winston logger
const logger = winston.createLogger({
    level: 'info',
    format: winston.format.combine(
        winston.format.timestamp(),
        winston.format.printf(({ timestamp, level, message }) => {
            return `${timestamp} [${level.toUpperCase()}] 🌐 ${message}`;
        })
    ),
    transports: [
        new winston.transports.Console(),
        new winston.transports.File({ 
            filename: path.join(LOGS_DIR, 'web_dashboard.log') 
        })
    ]
});

// Middleware
app.use(cors());
app.use(express.json());
app.use(express.static(path.join(__dirname, 'public')));

// Store active scans and connections
const activeScans = new Map();
const connectedClients = new Set();

/**
 * API Routes
 */

// Dashboard main page
app.get('/', (req, res) => {
    res.sendFile(path.join(__dirname, 'public', 'index.html'));
});

// Get system status
app.get('/api/status', async (req, res) => {
    try {
        const status = {
            timestamp: new Date().toISOString(),
            server: 'online',
            activeScans: activeScans.size,
            connectedClients: connectedClients.size,
            uptime: process.uptime(),
            memory: process.memoryUsage(),
            reports: await getReportsCount(),
            recentActivity: await getRecentActivity()
        };
        
        res.json(status);
        logger.info(`Status requested - Active scans: ${status.activeScans}, Clients: ${status.connectedClients}`);
    } catch (error) {
        logger.error(`Status endpoint error: ${error.message}`);
        res.status(500).json({ error: 'Failed to get system status' });
    }
});

// Get scan reports
app.get('/api/reports', async (req, res) => {
    try {
        const reports = await getScanReports();
        res.json(reports);
        logger.info(`Reports requested - Found ${reports.length} reports`);
    } catch (error) {
        logger.error(`Reports endpoint error: ${error.message}`);
        res.status(500).json({ error: 'Failed to get reports' });
    }
});

// Get specific report
app.get('/api/reports/:filename', async (req, res) => {
    try {
        const filename = req.params.filename;
        const reportPath = path.join(REPORTS_DIR, filename);
        
        const data = await fs.readFile(reportPath, 'utf8');
        const report = JSON.parse(data);
        
        res.json(report);
        logger.info(`Report requested: ${filename}`);
    } catch (error) {
        logger.error(`Report fetch error: ${error.message}`);
        res.status(404).json({ error: 'Report not found' });
    }
});

// Start new scan
app.post('/api/scan', async (req, res) => {
    try {
        const { target, scanType } = req.body;
        
        if (!target || !scanType) {
            return res.status(400).json({ error: 'Target and scan type required' });
        }
        
        const scanId = generateScanId();
        const scan = {
            id: scanId,
            target,
            scanType,
            status: 'starting',
            startTime: new Date().toISOString(),
            progress: 0
        };
        
        activeScans.set(scanId, scan);
        
        // Start scan process
        startScanProcess(scan);
        
        // Notify clients
        io.emit('scanStarted', scan);
        
        res.json({ scanId, message: 'Scan started successfully' });
        logger.info(`Scan started: ${scanType} on ${target} (ID: ${scanId})`);
        
    } catch (error) {
        logger.error(`Scan start error: ${error.message}`);
        res.status(500).json({ error: 'Failed to start scan' });
    }
});

// Get active scans
app.get('/api/scans', (req, res) => {
    const scans = Array.from(activeScans.values());
    res.json(scans);
});

// Stop scan
app.delete('/api/scans/:id', (req, res) => {
    const scanId = req.params.id;
    
    if (activeScans.has(scanId)) {
        const scan = activeScans.get(scanId);
        scan.status = 'stopped';
        scan.endTime = new Date().toISOString();
        
        // Notify clients
        io.emit('scanStopped', scan);
        
        // Remove from active scans
        activeScans.delete(scanId);
        
        res.json({ message: 'Scan stopped successfully' });
        logger.info(`Scan stopped: ${scanId}`);
    } else {
        res.status(404).json({ error: 'Scan not found' });
    }
});

// Get dashboard statistics
app.get('/api/stats', async (req, res) => {
    try {
        const stats = await getDashboardStats();
        res.json(stats);
    } catch (error) {
        logger.error(`Stats endpoint error: ${error.message}`);
        res.status(500).json({ error: 'Failed to get statistics' });
    }
});

/**
 * Socket.io Events
 */

io.on('connection', (socket) => {
    connectedClients.add(socket.id);
    logger.info(`Client connected: ${socket.id} (Total: ${connectedClients.size})`);
    
    // Send current active scans to new client
    socket.emit('activeScans', Array.from(activeScans.values()));
    
    // Handle client disconnect
    socket.on('disconnect', () => {
        connectedClients.delete(socket.id);
        logger.info(`Client disconnected: ${socket.id} (Total: ${connectedClients.size})`);
    });
    
    // Handle scan progress requests
    socket.on('getScanProgress', (scanId) => {
        if (activeScans.has(scanId)) {
            socket.emit('scanProgress', activeScans.get(scanId));
        }
    });
    
    // Handle real-time log requests
    socket.on('subscribeToLogs', () => {
        socket.join('logs');
        logger.info(`Client subscribed to logs: ${socket.id}`);
    });
    
    socket.on('unsubscribeFromLogs', () => {
        socket.leave('logs');
        logger.info(`Client unsubscribed from logs: ${socket.id}`);
    });
});

/**
 * Helper Functions
 */

function generateScanId() {
    return 'scan_' + Date.now() + '_' + Math.random().toString(36).substr(2, 9);
}

async function startScanProcess(scan) {
    try {
        // Map scan types to CLI commands
        const scanCommands = {
            'vulnerability': ['python3', '../cli.py', 'scan', scan.target],
            'brute_force': ['python3', '../scans/brute_force.py', scan.target],
            'phishing': ['python3', '../scans/phishing.py', scan.target],
            'ai_risk': ['python3', '../ml/predict.py', scan.target]
        };
        
        const command = scanCommands[scan.scanType];
        if (!command) {
            throw new Error(`Unknown scan type: ${scan.scanType}`);
        }
        
        scan.status = 'running';
        scan.progress = 10;
        io.emit('scanProgress', scan);
        
        // Simulate scan progress
        const progressInterval = setInterval(() => {
            if (scan.status === 'running' && scan.progress < 90) {
                scan.progress += Math.random() * 20;
                scan.progress = Math.min(scan.progress, 90);
                io.emit('scanProgress', scan);
            }
        }, 2000);
        
        // Simulate scan completion after random time
        setTimeout(() => {
            clearInterval(progressInterval);
            
            scan.status = 'completed';
            scan.progress = 100;
            scan.endTime = new Date().toISOString();
            scan.duration = new Date(scan.endTime) - new Date(scan.startTime);
            
            // Generate mock results
            scan.results = generateMockResults(scan.scanType, scan.target);
            
            io.emit('scanCompleted', scan);
            
            // Remove from active scans after a delay
            setTimeout(() => {
                activeScans.delete(scan.id);
            }, 5000);
            
            logger.info(`Scan completed: ${scan.id}`);
            
        }, Math.random() * 10000 + 5000); // 5-15 seconds
        
    } catch (error) {
        logger.error(`Scan process error: ${error.message}`);
        scan.status = 'failed';
        scan.error = error.message;
        scan.endTime = new Date().toISOString();
        io.emit('scanFailed', scan);
        
        setTimeout(() => {
            activeScans.delete(scan.id);
        }, 5000);
    }
}

function generateMockResults(scanType, target) {
    const baseResults = {
        target,
        timestamp: new Date().toISOString(),
        scanType
    };
    
    switch (scanType) {
        case 'vulnerability':
            return {
                ...baseResults,
                openPorts: [22, 80, 443, 3306],
                vulnerabilities: [
                    { severity: 'high', description: 'Outdated SSH version detected' },
                    { severity: 'medium', description: 'Missing security headers' },
                    { severity: 'low', description: 'Directory listing enabled' }
                ],
                riskScore: 7.2
            };
            
        case 'brute_force':
            return {
                ...baseResults,
                attempts: 15,
                successfulLogins: Math.random() > 0.7 ? 1 : 0,
                riskScore: Math.random() > 0.7 ? 8.5 : 3.2
            };
            
        case 'phishing':
            return {
                ...baseResults,
                emailsSent: 1,
                deliveryStatus: 'success',
                trainingValue: 8.5
            };
            
        case 'ai_risk':
            return {
                ...baseResults,
                riskScore: Math.random() * 10,
                riskFactors: ['open_ports', 'outdated_services'],
                confidence: 0.85
            };
            
        default:
            return baseResults;
    }
}

async function getScanReports() {
    try {
        const files = await fs.readdir(REPORTS_DIR);
        const reports = [];
        
        for (const file of files.filter(f => f.endsWith('.json'))) {
            try {
                const filePath = path.join(REPORTS_DIR, file);
                const stats = await fs.stat(filePath);
                const data = await fs.readFile(filePath, 'utf8');
                const content = JSON.parse(data);
                
                reports.push({
                    filename: file,
                    size: stats.size,
                    created: stats.birthtime.toISOString(),
                    modified: stats.mtime.toISOString(),
                    target: content.target || 'unknown',
                    scanType: content.scan_type || content.scanType || 'unknown',
                    riskScore: content.risk_score || content.riskScore || 0
                });
            } catch (err) {
                logger.warn(`Failed to parse report ${file}: ${err.message}`);
            }
        }
        
        return reports.sort((a, b) => new Date(b.created) - new Date(a.created));
        
    } catch (error) {
        logger.error(`Failed to get scan reports: ${error.message}`);
        return [];
    }
}

async function getReportsCount() {
    try {
        const files = await fs.readdir(REPORTS_DIR);
        return files.filter(f => f.endsWith('.json')).length;
    } catch (error) {
        return 0;
    }
}

async function getRecentActivity() {
    try {
        const reports = await getScanReports();
        return reports.slice(0, 5).map(r => ({
            time: r.created,
            action: `${r.scanType} scan completed`,
            target: r.target,
            riskScore: r.riskScore
        }));
    } catch (error) {
        return [];
    }
}

async function getDashboardStats() {
    try {
        const reports = await getScanReports();
        
        const stats = {
            totalScans: reports.length,
            highRiskTargets: reports.filter(r => r.riskScore >= 8).length,
            mediumRiskTargets: reports.filter(r => r.riskScore >= 5 && r.riskScore < 8).length,
            lowRiskTargets: reports.filter(r => r.riskScore < 5).length,
            scanTypes: {},
            recentScans: reports.slice(0, 10),
            averageRisk: reports.length > 0 ? 
                reports.reduce((sum, r) => sum + (r.riskScore || 0), 0) / reports.length : 0
        };
        
        // Count scan types
        reports.forEach(r => {
            const type = r.scanType || 'unknown';
            stats.scanTypes[type] = (stats.scanTypes[type] || 0) + 1;
        });
        
        return stats;
        
    } catch (error) {
        logger.error(`Failed to get dashboard stats: ${error.message}`);
        return {
            totalScans: 0,
            highRiskTargets: 0,
            mediumRiskTargets: 0,
            lowRiskTargets: 0,
            scanTypes: {},
            recentScans: [],
            averageRisk: 0
        };
    }
}

// Watch for new reports and notify clients
async function watchReports() {
    try {
        const chokidar = require('chokidar');
        const watcher = chokidar.watch(REPORTS_DIR, {
            ignored: /^\./, 
            persistent: true
        });
        
        watcher.on('add', (filePath) => {
            if (path.extname(filePath) === '.json') {
                logger.info(`New report detected: ${path.basename(filePath)}`);
                io.emit('newReport', {
                    filename: path.basename(filePath),
                    timestamp: new Date().toISOString()
                });
            }
        });
        
        logger.info('Report watcher started');
        
    } catch (error) {
        logger.warn('File watching not available - install chokidar for real-time updates');
    }
}

// Error handling
app.use((err, req, res, next) => {
    logger.error(`Express error: ${err.message}`);
    res.status(500).json({ error: 'Internal server error' });
});

// Graceful shutdown
process.on('SIGTERM', () => {
    logger.info('SIGTERM received, shutting down gracefully');
    server.close(() => {
        logger.info('Server closed');
        process.exit(0);
    });
});

process.on('SIGINT', () => {
    logger.info('SIGINT received, shutting down gracefully');
    server.close(() => {
        logger.info('Server closed');
        process.exit(0);
    });
});

// Start server
server.listen(PORT, () => {
    logger.info(`🌐 CyberToolkit Dashboard running on http://localhost:${PORT}`);
    logger.info(`📊 Dashboard features: Real-time scans, Reports, Statistics`);
    logger.info(`🔗 Socket.io enabled for real-time updates`);
    
    // Start report watching
    watchReports();
});

module.exports = { app, server, io };