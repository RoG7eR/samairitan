const express = require('express');
const router = express.Router();
const driver = require('../config/db');
const { conductReconnaissance } = require('../services/osint'); // Import the OSINT engine
const { scanLocalNetwork } = require('../services/localScanner');

router.get('/api/v1/network', async (req, res) => {
  const session = driver.session();
  
  try {
    // Cypher query to pull everything out of the database
    const cypherQuery = `
      MATCH (n:Asset)
      OPTIONAL MATCH (n)-[r]->(m:Asset)
      RETURN n, r, m
    `;
    
    const result = await session.run(cypherQuery);
    
    const nodesMap = new Map();
    const links = [];

    result.records.forEach(record => {
      const nodeA = record.get('n');
      const rel = record.get('r');
      const nodeB = record.get('m');

      // Process source node
      if (nodeA) {
        nodesMap.set(nodeA.properties.id, {
          id: nodeA.properties.id,
          name: nodeA.properties.id,
          type: nodeA.properties.type || "Unknown",
          threatLevel: nodeA.properties.threatLevel || "Unknown"
        });
      }

      // Process target node and edge relationship if it exists
      if (nodeB && rel) {
        nodesMap.set(nodeB.properties.id, {
          id: nodeB.properties.id,
          name: nodeB.properties.id,
          type: nodeB.properties.type || "Unknown",
          threatLevel: nodeB.properties.threatLevel || "Unknown"
        });

        links.push({
          source: nodeA.properties.id,
          target: nodeB.properties.id,
          type: rel.type
        });
      }
    });

    // Send data structured exactly how the frontend visualizer expects it
    res.json({
      nodes: Array.from(nodesMap.values()),
      links: links
    });

  } catch (error) {
    console.error("API Fetch Error:", error);
    res.status(500).json({ error: "Failed to fetch tactical network matrix" });
  } finally {
    await session.close();
  }
});

// --- NEW COMMAND ROUTE ---
router.post('/api/v1/sweep', async (req, res) => {
  const { target } = req.body;
  
  if (!target) {
    return res.status(400).json({ error: "Target parameter missing." });
  }

  try {
    console.log(`[API] Sweep requested for target: ${target}`);
    
    // 1. Run the live OSINT reconnaissance
    const { entities, relationships } = await conductReconnaissance(target);

    if (entities.length === 0) {
      return res.status(404).json({ message: "No intelligence extracted." });
    }

    // 2. Write the new intelligence to Neo4j
    const session = driver.session();
    
    for (const entity of entities) {
      await session.run(
        `MERGE (n:Asset {id: $id}) ON CREATE SET n.type = $type, n.threatLevel = $threatLevel`,
        { id: entity.id, type: entity.type, threatLevel: entity.threatLevel }
      );
    }

    for (const rel of relationships) {
      await session.run(
        `MATCH (source:Asset {id: $sourceId}) MATCH (target:Asset {id: $targetId})
         MERGE (source)-[r:${rel.type}]->(target)`,
        { sourceId: rel.source, targetId: rel.target }
      );
    }
    
    await session.close();

    // 3. Return success signal to the frontend
    res.json({ 
      message: "Target assimilated", 
      nodesAdded: entities.length 
    });

  } catch (error) {
    console.error("API Error during sweep:", error);
    res.status(500).json({ error: "Internal system failure during reconnaissance." });
  }
});

// --- NEW LOCAL SCAN ROUTE ---
router.post('/api/v1/local-sweep', async (req, res) => {
  try {
    console.log(`[API] Triggering proximity scan on local subnet.`);
    
    // 1. Run the local ARP sweep
    const localDevices = await scanLocalNetwork();

    const session = driver.session();
    const gatewayId = "127.0.0.1 (Local Host)";

    // 2. Ensure your master host node exists
    await session.run(
      `MERGE (g:Asset {id: $gatewayId})
       ON CREATE SET g.type = 'Control Gateway', g.threatLevel = 'Normal'`,
      { gatewayId }
    );

    // 3. Write discovered neighboring devices and connect them to the Gateway
    for (const device of localDevices) {
      // Create neighbor node
      await session.run(
        `MERGE (n:Asset {id: $id})
         ON CREATE SET n.type = $type, n.threatLevel = $threatLevel`,
        { id: device.id, type: device.type, threatLevel: device.threatLevel }
      );

      // Draw adjacency connection
      await session.run(
        `MATCH (g:Asset {id: $gatewayId})
         MATCH (n:Asset {id: $id})
         MERGE (g)-[r:LOCAL_ADJACENCY]->(n)`,
        { gatewayId, id: device.id }
      );
    }

    await session.close();
    res.json({ message: "Proximity scan successful", nodesAdded: localDevices.length });

  } catch (error) {
    console.error("Proximity scan failure:", error);
    res.status(500).json({ error: "Failed to isolate local network architecture." });
  }
});

module.exports = router;