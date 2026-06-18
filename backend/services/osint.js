const dns = require('dns').promises;

async function conductReconnaissance(targetDomain) {
  console.log(`[+] Initiating OSINT sweep for target: ${targetDomain}`);
  const entities = [];
  const relationships = [];

  try {
    // 1. Fetch Certificate Transparency Logs via crt.sh
    console.log(`[~] Querying Certificate Transparency logs...`);
    const response = await fetch(`https://crt.sh/?q=%.${targetDomain}&output=json`);
    
    if (!response.ok) throw new Error("Failed to connect to crt.sh");
    
    const data = await response.json();
    
    // Extract unique subdomains from the messy certificate data
    const subdomains = [...new Set(data.map(cert => cert.name_value.toLowerCase()))]
      .filter(domain => !domain.includes('*')); // Remove wildcards

    console.log(`[+] Discovered ${subdomains.length} unique subdomains.`);

    // 2. Add the primary target node
    entities.push({ id: targetDomain, type: "Primary Target", threatLevel: "Elevated" });

    // 3. Resolve IPs for a subset to avoid spamming DNS (limit to first 10 for testing)
    const targetsToResolve = subdomains.slice(0, 10);
    
    for (const subdomain of targetsToResolve) {
      // Add the subdomain entity
      entities.push({ id: subdomain, type: "Subdomain", threatLevel: "Unknown" });
      
      // Link subdomain to primary target
      relationships.push({ source: targetDomain, target: subdomain, type: "OWNS" });

      try {
        // Active Recon: Resolve the IP address
        const { address } = await dns.lookup(subdomain);
        
        // Add the IP entity
        entities.push({ id: address, type: "Infrastructure", threatLevel: "Unknown" });
        
        // Link the IP to the subdomain
        relationships.push({ source: subdomain, target: address, type: "RESOLVES_TO" });
        
        console.log(`  -> Resolved: ${subdomain} [${address}]`);
      } catch (dnsError) {
        console.log(`  -> Unresolved: ${subdomain} (Offline/Hidden)`);
      }
    }

    return { entities, relationships };

  } catch (error) {
    console.error("[-] Reconnaissance failed:", error.message);
    return { entities: [], relationships: [] };
  }
}

module.exports = { conductReconnaissance };