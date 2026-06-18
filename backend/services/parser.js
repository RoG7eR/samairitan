function parseIntelligenceLog(rawLog) {
  const entities = [];
  const relationships = [];

  // Match IPs and Domains
  const ipMatch = rawLog.match(/\b(?:[0-9]{1,3}\.){3}[0-9]{1,3}\b/);
  const domainMatch = rawLog.match(/(?:[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?\.)+[a-z0-9][a-z0-9-]{0,61}[a-z0-9]/i);

  if (ipMatch && domainMatch) {
    const targetIp = ipMatch[0];
    const domain = domainMatch[0];

    // Create Domain Node
    entities.push({
      id: domain,
      type: "Domain",
      threatLevel: "Elevated"
    });

    // Create IP Node
    entities.push({
      id: targetIp,
      type: "Infrastructure",
      threatLevel: "Unknown"
    });

    // Create Relationship
    relationships.push({
      source: domain,
      target: targetIp,
      type: "RESOLVES_TO"
    });
  }

  return { entities, relationships };
}

module.exports = { parseIntelligenceLog };