const fs = require('fs');
async function runTest() {
    const fetch = (await import('node-fetch')).default;
    const FormData = require('form-data');
    
    const formData = new FormData();
    formData.append('list', fs.createReadStream('test_emails.txt'));

    console.log("Uploading file...");
    const res = await fetch('http://localhost:3000/api/upload', {
        method: 'POST',
        body: formData
    });
    
    const data = await res.json();
    console.log("Upload response:", data);
    
    if(data.jobId) {
        console.log("Waiting for job to finish...");
        let done = false;
        while(!done) {
            await new Promise(r => setTimeout(r, 1000));
            const prog = await fetch('http://localhost:3000/api/progress/' + data.jobId);
            const progData = await prog.json();
            console.log("Progress:", progData.processed, "/", progData.total, "Status:", progData.status);
            if (progData.status === 'complete' || progData.status === 'out_of_credits') {
                done = true;
            }
        }
    }
}
runTest().catch(console.error);
