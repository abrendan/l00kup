const express = require('express');
const dns = require('dns').promises;
const path = require('path');
const whois = require('whois');

const app = express();
const port = 3000;

// Middleware to parse incoming requests with JSON payloads
app.use(express.json());

// Serve static files from 'public' directory
app.use(express.static('public'));

// Endpoint for performing reverse domain lookup
app.post('/reverseLookup', async (req, res) => {
    try {
        const { domain } = req.body;
        const ips = await dns.lookup(domain);
        const reverseResult = await dns.reverse(ips.address);
        res.json({ success: true, domain, ips: ips.address, reverseResult });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Lookup failed', error: error.message });
    }
});

// Endpoint for performing reverse domain lookup by IP
app.post('/reverseLookupByIP', async (req, res) => {
    try {
        const { ip } = req.body;
        const reverseResult = await dns.reverse(ip);
        res.json({ success: true, ip, reverseResult });
    } catch (error) {
        console.error(error);
        res.status(500).json({ success: false, message: 'Reverse lookup failed', error: error.message });
    }
});

app.post('/whoisLookup', (req, res) => {
    const { domain } = req.body;
    whois.lookup(domain, (err, data) => {
        if (err) {
            console.error(err);
            res.status(500).json({ success: false, message: 'WHOIS lookup failed', error: err.message });
        } else {
            res.json({ success: true, domain, whois: data });
        }
    });
});

app.listen(port, () => {
    console.log(`Server running at http://localhost:${port}`);
});