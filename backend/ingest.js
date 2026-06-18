const driver = require('./config/db');
const { parseIntelligenceLog } = require('./services/parser');

async function processIntelligence() {
  // Simulated OSINT output
  const rawData = "Asset discovered: admin-portal.target.com resolving to IP 192.168.1.50";
  
  console.log("Ingesting raw data...");
  const { entities, relationships } = parseIntelligenceLog(rawData);

  // Open a database session
  const session = driver.session();

  try {
    // 1. Write Entities to Neo4j
    for (const entity of entities) {
      await session.run(
        `MERGE (n:Asset {id: $id})
         ON CREATE SET n.type = $type, n.threatLevel = $threatLevel`,
        {
          id: entity.id,
          type: entity.type,
          threatLevel: entity.threatLevel
        }
      );
      console.log(`Node Created/Verified: ${entity.id}`);
    }

    // 2. Write Relationships to Neo4j
    for (const rel of relationships) {
      await session.run(
        `MATCH (source:Asset {id: $sourceId})
         MATCH (target:Asset {id: $targetId})
         MERGE (source)-[r:RESOLVES_TO]->(target)`,
        {
          sourceId: rel.source,
          targetId: rel.target
        }
      );
      console.log(`Link Established: ${rel.source} -> ${rel.target}`);
    }

    console.log("Pipeline Execution Complete.");

  } catch (error) {
    console.error("System Error during ingestion:", error);
  } finally {
    // Always close the session and driver
    await session.close();
    await driver.close();
  }
}

// Run the script
processIntelligence();