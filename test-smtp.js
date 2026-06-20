const net = require('net');

const socket = new net.Socket();
socket.connect(25, 'gmail-smtp-in.l.google.com');

socket.on('data', data => {
  const line = data.toString();
  console.log('S:', line.trim());
  if (/^220/.test(line)) {
    console.log('C: EHLO localhost');
    socket.write('EHLO localhost\r\n');
  } else if (/^250.*mx.google.com at your service/.test(line) || (/^250/.test(line) && line.includes('8BITMIME'))) {
    console.log('C: MAIL FROM:<>');
    socket.write('MAIL FROM:<>\r\n');
  } else if (/^250 2.1.0 OK/.test(line)) {
    console.log('C: RCPT TO:<ikhtheir@gmail.com>');
    socket.write('RCPT TO:<ikhtheir@gmail.com>\r\n');
  } else if (/^250 2.1.5 OK/.test(line) || /^5/.test(line) || /^4/.test(line)) {
    console.log('Ending test.');
    socket.write('QUIT\r\n');
    socket.destroy();
  }
});
