const { exec } = require('child_process');

function scanLocalNetwork() {
  return new Promise((resolve, reject) => {
    console.log("[~] Querying local ARP cache for neighboring devices...");
    
    // 'arp -a' is standard across Windows, Linux, and macOS
    exec('arp -a', (error, stdout, stderr) => {
      if (error) {
        return reject(new Error("Unable to execute local network scan: " + error.message));
      }

      const devices = [];
      const lines = stdout.split('\n');

      // Regular expression to extract IP addresses from the ARP output
      const ipRegex = /(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})/;

      lines.forEach(line => {
        const match = line.match(ipRegex);
        if (match) {
          const ip = match[1];
          
          // Ignore standard broadcast/multicast addresses
          if (!ip.startsWith('224.') && !ip.startsWith('255.') && !ip.endsWith('.255')) {
            devices.push({
              id: ip,
              name: `LAN-Device [${ip}]`,
              type: "Local Infrastructure",
              threatLevel: "Normal"
            });
          }
        }
      });

      console.log(`[+] Discovered ${devices.length} active local network nodes.`);
      resolve(devices);
    });
  });
}

module.exports = { scanLocalNetwork };