const fs = require('fs');
const http = require('http');

const boundary = '----WebKitFormBoundary7MA4YWxkTrZu0gW';
const filePath = 'test_emails.csv';
const fileContent = fs.readFileSync(filePath);

let postData = `--${boundary}\r\n`;
postData += `Content-Disposition: form-data; name="list"; filename="test_emails.csv"\r\n`;
postData += `Content-Type: text/csv\r\n\r\n`;

const footer = `\r\n--${boundary}--\r\n`;

const req = http.request({
    hostname: 'localhost',
    port: 3000,
    path: '/api/upload',
    method: 'POST',
    headers: {
        'Content-Type': `multipart/form-data; boundary=${boundary}`,
        'Content-Length': Buffer.byteLength(postData) + fileContent.length + Buffer.byteLength(footer)
    }
}, (res) => {
    let data = '';
    res.on('data', d => data += d);
    res.on('end', () => {
        const result = JSON.parse(data);
        console.log("Upload result:", result);
        if(result.error) return;
        
        const jobId = result.jobId;
        const interval = setInterval(() => {
            http.get(`http://localhost:3000/api/progress/${jobId}`, (pRes) => {
                let pData = '';
                pRes.on('data', d => pData += d);
                pRes.on('end', () => {
                    const prog = JSON.parse(pData);
                    console.log("Progress:", prog);
                    if(prog.status === 'complete') {
                        clearInterval(interval);
                        http.get('http://localhost:3000/api/credits', (cRes) => {
                            let cData = '';
                            cRes.on('data', d => cData += d);
                            cRes.on('end', () => {
                                console.log("Final Credits:", JSON.parse(cData));
                            });
                        });
                    }
                });
            });
        }, 500);
    });
});

req.on('error', (e) => {
    console.error("E2E Test Failed (Server might not be running):", e.message);
});

req.write(postData);
req.write(fileContent);
req.write(footer);
req.end();
