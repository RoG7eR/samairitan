const neo4j = require('neo4j-driver');
require('dotenv').config();

const driver = neo4j.driver(
  process.env.NEO4J_URI,
  neo4j.auth.basic(process.env.NEO4J_USER, process.env.NEO4J_PASSWORD)
);

// Verify connection
async function verifyConnection() {
  try {
    await driver.verifyConnectivity();
    console.log("Database Connection: ONLINE");
  } catch (error) {
    console.error("Database Connection: FAILED", error);
  }
}

verifyConnection();

module.exports = driver;