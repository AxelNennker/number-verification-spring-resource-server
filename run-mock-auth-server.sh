#!/bin/bash

# Script to run the MockAuthorizationServer standalone for testing
# This allows you to test your resource server with a mock OAuth2 authorization server

set -e

# Colors for output
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
NC='\033[0m' # No Color

echo -e "${GREEN}Starting Mock Authorization Server...${NC}"

# Check if Java is installed
if ! command -v java &> /dev/null; then
    echo -e "${RED}Error: Java is not installed or not in PATH${NC}"
    exit 1
fi

# Check if Maven wrapper exists
if [ ! -f "./mvnw" ]; then
    echo -e "${RED}Error: Maven wrapper (mvnw) not found${NC}"
    echo -e "${YELLOW}Please run: mvn -N wrapper:wrapper${NC}"
    exit 1
fi

# Default port
PORT=${1:-8090}

# Check if the port is already in use (only on Linux/Mac with lsof)
if command -v lsof &> /dev/null; then
    if lsof -Pi :$PORT -sTCP:LISTEN -t >/dev/null 2>&1 ; then
        echo -e "${YELLOW}Warning: Port $PORT is already in use${NC}"
        read -p "Do you want to kill the process using this port? (y/n) " -n 1 -r
        echo
        if [[ $REPLY =~ ^[Yy]$ ]]; then
            echo "Killing process on port $PORT..."
            lsof -ti:$PORT | xargs kill -9
            sleep 2
        else
            echo -e "${RED}Exiting...${NC}"
            exit 1
        fi
    fi
fi

# Check if MockAuthServerRunner.java exists
RUNNER_FILE="src/test/java/com/telekom/camara/integration/MockAuthServerRunner.java"
if [ ! -f "$RUNNER_FILE" ]; then
    echo -e "${RED}Error: $RUNNER_FILE not found${NC}"
    echo -e "${YELLOW}Please create MockAuthServerRunner.java in src/test/java/com/telekom/camara/integration/${NC}"
    exit 1
fi

# Compile test classes
echo -e "${GREEN}Compiling test classes...${NC}"
./mvnw test-compile

# Get the classpath
echo -e "${GREEN}Getting classpath...${NC}"
CLASSPATH=$(./mvnw dependency:build-classpath -Dmdep.outputFile=/dev/stdout -q)

# Add test classes and main classes to classpath
CLASSPATH="target/test-classes:target/classes:$CLASSPATH"

# Run the server
echo -e "${GREEN}Starting server on port $PORT...${NC}"
echo ""

java -cp "$CLASSPATH" com.telekom.camara.integration.MockAuthServerRunner $PORT