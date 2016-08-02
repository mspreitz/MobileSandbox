# Installing
## Neo4J
Tested with version [neo4j-community-2.3.3](https://neo4j.com/download/?ref=home)

Requirements:
	* [`py2neo` Kommunikation mit Neo4J DB](http://py2neo.org/v3/)

# Running
## Neo4J
* `ulimit -n 40000` - Ensure better performance by allowing more open file descriptors
* `/bin/neo4j start` - Start the Neo4J Framework

# Usage
## Neo4J
* Start Neo4J using the commandline (see `Running > Neo4J`)
* Open the [Neo4J browser](http://localhost:7474/browser)
* Execute [Cypher requests](https://neo4j.com/docs/cypher-refcard/current/)
