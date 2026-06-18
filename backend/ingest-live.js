const driver = require('./config/db');
const { conductReconnaissance } = require('./services/osint');

async function executeLivePipeline() {
  // Use a safe, authorized target (e.g., a bug bounty scope or your own domain)
  const target = "hackerone.com"; 
  
  const { entities, relationships } = await conductReconnaissance(target);

  if (entities.length === 0) {
    console.log("[-] No intelligence gathered. Terminating pipeline.");
    process.exit(0);
  }

  console.log(`[~] Opening database channel... writing ${entities.length} nodes to Neo4j.`);
  const session = driver.session();

  try {
    // 1. Write Entities
    for (const entity of entities) {
      await session.run(
        `MERGE (n:Asset {id: $id})
         ON CREATE SET n.type = $type, n.threatLevel = $threatLevel`,
        { id: entity.id, type: entity.type, threatLevel: entity.threatLevel }
      );
    }

    // 2. Write Relationships
    for (const rel of relationships) {
      await session.run(
        `MATCH (source:Asset {id: $sourceId})
         MATCH (target:Asset {id: $targetId})
         MERGE (source)-[r:${rel.type}]->(target)`,
        { sourceId: rel.source, targetId: rel.target }
      );
    }

    console.log("[+] Live intelligence successfully assimilated into the matrix.");

  } catch (error) {
    console.error("[-] Database Error:", error);
  } finally {
    await session.close();
    await driver.close();
  }
}

executeLivePipeline();