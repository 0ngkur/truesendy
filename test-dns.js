const dns = require('dns').promises;

async function test() {
  try {
    const r1 = await dns.resolveMx('gmail.com');
    console.log('Default DNS:', r1);
  } catch (e) {
    console.log('Default DNS Error:', e.message);
  }
  
  require('dns').setServers(['8.8.8.8', '1.1.1.1']);
  
  try {
    const r2 = await dns.resolveMx('gmail.com');
    console.log('Google DNS:', r2);
  } catch (e) {
    console.log('Google DNS Error:', e.message);
  }
}
test();
