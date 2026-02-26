pipeline {
    agent any
    
    environment {
        
        // To enable the SAST stage the value should be "true"
        WITH_SAST = 'true'
        
        // NVD-key - if you do not have it, just specify the empty string as the secret text in Jenkins Credentials
        NVD_API_KEY = credentials('NVD-key')
        
        // Vault settings
        VAULT_ADDR = credentials('vault-ip')
        VAULT_TOKEN = credentials('vault-token')
        
        // Network settings
        REGISTRY_HOST = credentials('registry-host-ip')
        APP_NAME = 'vulnerable-app'
        MYSQL_IMAGE = "${REGISTRY_HOST}/mysql:5.7"
        
        // Project settings
        GIT_REPO = credentials('git-repo-link')
        
        // Docker tags
        BUILD_TAG = "${APP_NAME}:${BUILD_NUMBER}"
        REGISTRY_TAG = "${REGISTRY_HOST}/${APP_NAME}:${BUILD_NUMBER}"
        REGISTRY_LATEST = "${REGISTRY_HOST}/${APP_NAME}:latest"
    }
    
    stages {
        // Step 1: Getting code from repository
        stage('Checkout Code') {
            steps {
                echo "Cloning repository: ${GIT_REPO}"
                checkout([$class: 'GitSCM', 
                         branches: [[name: '*/main']], 
                         userRemoteConfigs: [[url: "${GIT_REPO}"]]])
                
                // Checking the results
                sh '''
                    echo "Repository content:"
                    ls -la
                    echo ""
                    echo "Jenkinsfile is included:"
                    ls -la Jenkinsfile 2>/dev/null || echo "Jenkinsfile not found!"
                '''
            }
        }
        
        
        // Security Step: Static Application Security Testing (SAST) with Semgrep
        stage('SAST: Semgrep Analysis') {
            steps {
                echo "Running Semgrep SAST analysis..."
                script {
                echo "WITH_SAST = ${env.WITH_SAST}"
                if (env.WITH_SAST == 'true') {
                    try {
                        // Running Semgrep with docker-image
                        sh '''
                            echo "=== Running Semgrep SAST Scan ==="
                            
                            # Scanning source code (./src folder only)
                            docker run --rm -v "$(pwd)/src:/src:ro" \\
                                            -v "$(pwd):/results" \\
                                            -v "$(pwd)/.semgrep-rules:/semgrep-rules:ro" \\
                                semgrep/semgrep:latest \\
                                semgrep scan \\
                                --config=/semgrep-rules \\
                                --json \\
                                --output=/results/SAST_reports/semgrep-report.json \\
                                /src || true
                            
                            # Scanning source code (./src folder only) - to create a human-readable output
                            docker run --rm -v "$(pwd)/src:/src:ro" \\
                                            -v "$(pwd):/results" \\
                                            -v "$(pwd)/.semgrep-rules:/semgrep-rules:ro" \\
                                returntocorp/semgrep:latest \\
                                semgrep scan \\
                                --config=/semgrep-rules \\
                                --text \\
                                --output=/results/SAST_reports/semgrep-results.txt \\
                                /src || true
                        '''
                        
                        // Checking JSON for findings count
                        def semgrepReport = readJSON file: 'SAST_reports/semgrep-report.json'
                        def totalFindings = semgrepReport?.results?.size() ?: 0
                        
                        // Variables for severity
                        def highSeverity = 0
                        def mediumSeverity = 0
                        def lowSeverity = 0
                        
                        if (semgrepReport?.results) {
                            semgrepReport.results.each { finding ->
                                switch(finding?.extra?.severity?.toUpperCase()) {
                                    case 'ERROR':
                                    case 'HIGH':
                                        highSeverity++
                                        break
                                    case 'WARNING':
                                    case 'MEDIUM':
                                        mediumSeverity++
                                        break
                                    case 'INFO':
                                    case 'LOW':
                                        lowSeverity++
                                        break
                                }
                            }
                        }
                        
                        // Saving reports as artifacts
                        archiveArtifacts artifacts: 'SAST_reports/semgrep-report.json, SAST_reports/semgrep-results.txt', fingerprint: true
                        
                        echo "=== Semgrep Scan Results ==="
                        echo "Total findings: ${totalFindings}"
                        echo "High severity: ${highSeverity}"
                        echo "Medium severity: ${mediumSeverity}"
                        echo "Low severity: ${lowSeverity}"
                        
                        // Summary output to console
                        if (totalFindings > 0) {
                            // Show findings for decision
                            echo "⚠️  Semgrep found ${totalFindings} security issues (${highSeverity} High, ${mediumSeverity} Medium, ${lowSeverity} Low)"
                            input 'Do you accept SAST results?'
                            
                        } else {
                            echo "✅ No security issues found by Semgrep"
                        }
                        
                    } catch (Exception e) {
                        echo "❌ Semgrep scan failed or was interrupted: ${e.message}"
                        // Show error for decision
                        input 'Should we continue without SAST results?'
                    }
                } else {
                echo "⚠️ SAST stage skipped"
                }
            }
            }
        }
        
        // Step 2: Compiling Java app with security checks
        stage('Build Application with SCA check') {
            steps {
                echo "Compiling Java app with security checks..."
                script {
                    // Run Maven build with OWASP Dependency Check
                    try {
                        sh '''
                            # Run Maven with OWASP Dependency Check plugin via Docker
                            docker run --rm \\
                                -v "\$(pwd):/src" \\
                                -v "\${HOME}/.m2:/root/.m2" \\
                                -w /src \\
                                maven:3.8-openjdk-11 \\
                                mvn clean package \\
                                  org.owasp:dependency-check-maven:check \\
                                  -DnvdApiKey="\${NVD_API_KEY}" \\
                                  -DskipTests
                        '''
                        
                        // Archive dependency check reports
                        archiveArtifacts artifacts: 'SCA_reports/dependency-check-report.html, SCA_reports/dependency-check-report.json', fingerprint: true
                        
                        // Analyze dependency check results
                        echo "=== OWASP Dependency Check Results ==="
                        sh '''
                            echo "Dependency Check reports generated at:"
                            find SCA_reports/dependency-check-report -name "*.html" -o -name "*.json" 2>/dev/null || echo "No reports found"
                            
                            # Check for vulnerability count in JSON report (if exists)
                            if [ -f "SCA_reports/dependency-check-report.json" ]; then
                                echo "Analyzing dependency vulnerabilities..."
                                # Extract vulnerability counts (simplified approach)
                                VULN_COUNT=\$(grep -o '"vulnerabilities":' SCA_reports/dependency-check-report.json | wc -l || echo "0")
                                echo "Found vulnerability entries: \${VULN_COUNT}"
                            fi
                        '''
                        
                        // Provide manual review option
                        if (fileExists('SCA_reports/dependency-check-report.html')) {
                            echo "📋 OWASP Dependency Check report available for review"
                            input 'Review dependency vulnerabilities and continue?'
                        }
                        
                    } catch (Exception e) {
                        echo "⚠️  Build or dependency check failed: \${e.message}"
                        echo "Checking if at least JAR file was created..."
                        
                        // Fallback: Try to build without dependency check
                        sh '''
                            echo "Attempting standard build without dependency check..."
                            mvn clean package -DskipTests || echo "Standard build also failed"
                            
                            # Check for JAR
                            if [ -f "target/*.jar" ]; then
                                echo "JAR file created (dependency check skipped)"
                                ls -la target/*.jar
                            else
                                echo "JAR not found"
                                find . -name "*.jar" | head -5 || echo "No JAR files found"
                            fi
                        '''
                        
                        input 'Dependency check failed. Continue with build?'
                    }
                }
            }
        }
        
        // Step 3.1: Creating Docker image and tagging
        stage('Build Docker Image') {
            steps {
                script {
                    echo "Build Docker image..."
                    
                    // Build and tag
                    docker.build("${BUILD_TAG}")
                    
                    echo "Created images:"
                    sh "docker images | grep ${APP_NAME}"
                }
            }
        }
        
        // Security Step 3.2: Container Image Scanning with Trivy
        stage('Container Scan: Trivy Analysis') {
            steps {
                echo "Running Trivy container image scan..."
                script {
                    try {
                        // Create directory for reports and Trivy cache
                        sh 'mkdir -p CONTAINER_SCAN_reports'
                        sh 'mkdir -p ${HOME}/.trivy_cache || true'
                        
                        // Check when database was last updated (update once per day)
                        def shouldUpdateDB = true
                        def cacheFile = "${HOME}/.trivy_cache/db_last_update"
                        
                        sh """
                            if [ -f "${cacheFile}" ]; then
                                LAST_UPDATE=\$(cat "${cacheFile}")
                                CURRENT_TIME=\$(date +%s)
                                DAY_IN_SECONDS=86400
                                
                                if [ \$((CURRENT_TIME - LAST_UPDATE)) -lt \$DAY_IN_SECONDS ]; then
                                    echo "Trivy DB was updated less than 24 hours ago, skipping update"
                                    shouldUpdateDB=false
                                else
                                    echo "Trivy DB needs update (last update: \${LAST_UPDATE})"
                                fi
                            else
                                echo "No previous Trivy DB update timestamp found"
                            fi
                        """
                        
                        // Build Trivy command with conditional DB update
                        def updateFlags = ""
                        if (shouldUpdateDB) {
                            updateFlags = ""
                            echo "Will update Trivy vulnerability database"
                        } else {
                            updateFlags = "--skip-db-update --skip-java-db-update"
                            echo "Using cached Trivy database (no update)"
                        }
                        
                        // Run Trivy scan on the built Docker image
                        sh """
                            echo "=== Running Trivy Container Scan ==="
                            
                            # Scan the locally built image for vulnerabilities
                            docker run --rm \\
                                -v /var/run/docker.sock:/var/run/docker.sock \\
                                -v "\$(pwd)/CONTAINER_SCAN_reports:/output" \\
                                -v "${HOME}/.trivy_cache:/root/.cache/trivy" \\
                                aquasec/trivy:latest \\
                                image \\
                                --format json \\
                                --output /output/trivy-report.json \\
                                --exit-code 0 \\
                                --timeout 30m \\
                                ${updateFlags} \\
                                --cache-dir /root/.cache/trivy \\
                                ${BUILD_TAG}
                            
                            # Update timestamp if DB was updated
                            if [ "${shouldUpdateDB}" = "true" ]; then
                                date +%s > "${cacheFile}"
                                echo "Updated Trivy DB timestamp"
                            fi
                            
                            # Generate human-readable report
                            docker run --rm \\
                                -v /var/run/docker.sock:/var/run/docker.sock \\
                                -v "\$(pwd)/CONTAINER_SCAN_reports:/output" \\
                                -v "${HOME}/.trivy_cache:/root/.cache/trivy" \\
                                aquasec/trivy:latest \\
                                image \\
                                --format table \\
                                --output /output/trivy-results.txt \\
                                --exit-code 0 \\
                                --timeout 30m \\
                                ${updateFlags} \\
                                --cache-dir /root/.cache/trivy \\
                                ${BUILD_TAG}
                        
                            # Generate SBOM in CycloneDX format
                            docker run --rm \\
                                -v /var/run/docker.sock:/var/run/docker.sock \\
                                -v "\$(pwd)/CONTAINER_SCAN_reports:/output" \\
                                -v "${HOME}/.trivy_cache:/root/.cache/trivy" \\
                                aquasec/trivy:latest \\
                                image \\
                                --format cyclonedx \\
                                --output /output/sbom-cyclonedx.json \\
                                --timeout 30m \\
                                ${updateFlags} \\
                                --cache-dir /root/.cache/trivy \\
                                ${BUILD_TAG}
                        """
                        
                        // Read and analyze the JSON report
                        def trivyReport = null
                        if (fileExists('CONTAINER_SCAN_reports/trivy-report.json')) {
                            trivyReport = readJSON file: 'CONTAINER_SCAN_reports/trivy-report.json'
                        }
                        
                        def vulnerabilityCount = 0
                        def severitySummary = [CRITICAL: 0, HIGH: 0, MEDIUM: 0, LOW: 0, UNKNOWN: 0]
                        
                        // Count vulnerabilities from report
                        if (trivyReport?.Results) {
                            trivyReport.Results.each { result ->
                                if (result?.Vulnerabilities) {
                                    vulnerabilityCount += result.Vulnerabilities.size()
                                    result.Vulnerabilities.each { vuln ->
                                        def severity = vuln?.Severity?.toUpperCase() ?: "UNKNOWN"
                                        severitySummary[severity] = (severitySummary[severity] ?: 0) + 1
                                    }
                                }
                            }
                        }
                        
                        // Archive Trivy reports as artifacts
                        archiveArtifacts artifacts: 'CONTAINER_SCAN_reports/trivy-report.json, CONTAINER_SCAN_reports/trivy-results.txt, CONTAINER_SCAN_reports/sbom-cyclonedx.json,', fingerprint: true
                        
                        echo "=== Trivy Scan Results ==="
                        echo "Total vulnerabilities found: ${vulnerabilityCount}"
                        echo "Critical: ${severitySummary.CRITICAL}"
                        echo "High: ${severitySummary.HIGH}"
                        echo "Medium: ${severitySummary.MEDIUM}"
                        echo "Low: ${severitySummary.LOW}"
                        echo "Unknown: ${severitySummary.UNKNOWN}"
                        
                        // Show DB cache info
                        sh """
                            echo "=== Trivy Cache Info ==="
                            ls -la "${HOME}/.trivy_cache/" 2>/dev/null || echo "No cache directory"
                            if [ -f "${cacheFile}" ]; then
                                LAST_UPDATE=\$(cat "${cacheFile}")
                                echo "DB last updated at timestamp: \${LAST_UPDATE}"
                                echo "Human readable: \$(date -d @\${LAST_UPDATE})"
                            fi
                        """
                        
                        // Decision point based on scan results
                        if (vulnerabilityCount > 0) {
                            echo "⚠️  Trivy found ${vulnerabilityCount} vulnerabilities in container image"
                            echo "   Critical: ${severitySummary.CRITICAL}, High: ${severitySummary.HIGH}"
                            
                            if (severitySummary.CRITICAL > 0 || severitySummary.HIGH > 5) {
                                echo "🚨 Critical or multiple High severity vulnerabilities detected!"
                                input 'Critical vulnerabilities found. Continue with deployment?'
                            } else {
                                input 'Vulnerabilities found in container image. Continue with deployment?'
                            }
                        } else {
                            echo "✅ No vulnerabilities found in container image by Trivy"
                        }
                        
                    } catch (Exception e) {
                        echo "❌ Trivy scan failed: ${e.message}"
                        
                        // Try to generate a simple report even if detailed scan failed
                        sh '''
                            echo "Attempting quick scan with limited checks..."
                            docker run --rm \\
                                -v /var/run/docker.sock:/var/run/docker.sock \\
                                -v "${HOME}/.trivy_cache:/root/.cache/trivy" \\
                                aquasec/trivy:latest \\
                                image \\
                                --timeout 15m \\
                                --skip-db-update \\
                                --severity CRITICAL,HIGH \\
                                --exit-code 0 \\
                                ${BUILD_TAG} > CONTAINER_SCAN_reports/trivy-quick-results.txt 2>&1 || true
                        '''
                        
                        input 'Trivy scan encountered an error. Continue with deployment?'
                    }
                }
            }
        }
        
        // Step 3.3: Tagging Docker image
        stage('Tag Docker Image') {
            steps {
                script {
                    
                    // Creating the registry tag reference
                    sh "docker tag ${BUILD_TAG} ${REGISTRY_TAG}"
                    
                    // Creating the "latest" tag
                    sh "docker tag ${BUILD_TAG} ${REGISTRY_LATEST}"
                    
                    echo "Created and tagged images:"
                    sh "docker images | grep ${APP_NAME}"
                }
            }
        }
		
        // Step 4: Pushing to local Registry
        stage('Push to Registry') {
            steps {
                echo "Pushing images to registry ${REGISTRY_HOST}..."
                script {
                    // Pushing both tags into registry
                    docker.withRegistry("http://${REGISTRY_HOST}") {
                        docker.image("${REGISTRY_TAG}").push()
                        docker.image("${REGISTRY_LATEST}").push()
                    }
                    
                    // Checking images in registry
                    sh """
                        echo "Checking registry:"
                        curl -s http://${REGISTRY_HOST}/v2/_catalog | jq . 2>/dev/null || \
                        curl -s http://${REGISTRY_HOST}/v2/_catalog
                        echo ""
                        echo "Tags for ${APP_NAME}:"
                        curl -s http://${REGISTRY_HOST}/v2/${APP_NAME}/tags/list | jq . 2>/dev/null || \
                        curl -s http://${REGISTRY_HOST}/v2/${APP_NAME}/tags/list
                    """
                }
            }
        }
        
        // Step 4.1: Sign Docker Images
        stage('Sign Docker Image') {
            steps {
                echo "Signing Docker image with Cosign using private key from Vault..."
                script {
                    
                    def imageRef = env.REGISTRY_TAG
                    
                    withCredentials([string(credentialsId: 'cosign-key-password', variable: 'COSIGN_KEY_PWD')])
                    
                    {
                    // Fetching private key from Vault and passing to cosign with env variable
                    sh """
                        # echo 'Signing image: ${imageRef}'
                        
                        IMAGE_REF_DG=\$(docker inspect --format='{{index .RepoDigests 0}}' ${imageRef} 2>/dev/null || echo "")
                        
                        echo 'Signing image 1: \$IMAGE_REF_DG'
                        
                        echo 'Fetching Cosign private key from Vault and signing image...'
                        
                        set +x
                        
                        export COSIGN_PRIVATE_KEY=\$(curl -s \
                            --header 'X-Vault-Token: ${VAULT_TOKEN}' \
                            ${VAULT_ADDR}/v1/secret/data/docker-signing/cosign-private \
                            | jq -r .data.data.key)
                        
                        set -x
                        
                        if [ -z '\$COSIGN_PRIVATE_KEY' ]; then
                            echo '❌ Failed to fetch private key from Vault'
                            exit 1
                        fi
                
                        export COSIGN_PASSWORD=\${COSIGN_KEY_PWD}
                
                        docker run --rm \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            -e COSIGN_PRIVATE_KEY \
                            -e COSIGN_PASSWORD \
                            gcr.io/projectsigstore/cosign:latest \
                            sign --key env://COSIGN_PRIVATE_KEY \
                                 --allow-insecure-registry \
                                 --yes \
                                 \$IMAGE_REF_DG
                            
                        echo '✅ Image signed successfully!'
                    """
                    }
                }
            }
        }
        
        // Step 5: Clean the local images
        stage('Clean Local Images') {
            steps {
                echo "Clean local images ${APP_NAME}..."
                script {
                    // Removing all images vulnerable-app
                    sh """
                        echo "Removing images ${APP_NAME}..."
                        docker rmi -f \$(docker images -q ${APP_NAME}) 2>/dev/null || true
                        
                        echo "Checking the images:"
                        docker images | grep ${APP_NAME} || echo "Images ${APP_NAME} has been removed"
                    """
                }
            }
        }
        
        // Step 5.1: Verify Docker Image Signature
        stage('Verify Docker Image Signature') {
            steps {
                echo "Verifying Docker image signature with Cosign..."
                script {
                    withCredentials([file(credentialsId: 'cosign-public-key', variable: 'COSIGN_PUBLIC_KEY_FILE')])
                    {
                    def imageToVerify = env.REGISTRY_LATEST
                    def verificationPassed = false
                    
                    echo "=== Verifying image signature: ${imageToVerify} ==="
                    
                    sh '''
                    echo "Creating temporary public key file with proper permissions..."
                    TEMP_KEY_FILE="${WORKSPACE}/temp_cosign.pub"
                    cp "${COSIGN_PUBLIC_KEY_FILE}" "${TEMP_KEY_FILE}"
                    chmod 644 "${TEMP_KEY_FILE}"
                    '''
                    
                    // Checking the signature
                    try {
                        
                        sh """
                        
                            echo "Attempting to verify image signature..."
                            
                            # Checking signature with public key
                            docker run --rm \
                                -v /var/run/docker.sock:/var/run/docker.sock \
                                -v "${WORKSPACE}/temp_cosign.pub:/cosign.pub:ro" \
                                gcr.io/projectsigstore/cosign:latest \
                                verify --key /cosign.pub \
                                       --allow-insecure-registry \
                                       ${imageToVerify}
                            
                            echo "✅ Cosign verify command executed successfully"
                        """
                        
                        verificationPassed = true
                        echo "✅ Image signature verified successfully!"
                        
                    } catch (Exception e) {
                        echo "❌ Error during signature verification: ${e.message}"
                        verificationPassed = false
                    } finally {
                        sh '''
                        echo "Cleaning up temporary key file..."
                        rm -f "${WORKSPACE}/temp_cosign.pub" 2>/dev/null || true
                        '''
                    }
                    
                    // If the signature verification failed - asking for the further decision
                    if (!verificationPassed) {
                        input 'Image signature verification failed. Continue with deployment?'
                    }
                    }
                }
            }
        }
        
        // Step 6: Running the vulnerable app from the local registry
        stage('Run Test Deployment') {
            steps {
                echo "Deployment from the local registry..."
                script {
                    // Stopping previous containers if any
                    sh '''
                        docker stop test-vulnerable-app 2>/dev/null || true
                        docker rm -v test-vulnerable-app 2>/dev/null || true
                        
                        docker stop test-mysql 2>/dev/null || true
                        docker rm -v test-mysql 2>/dev/null || true
                    '''
                    
                    // Running MySQL from the registry
                    sh """
                        echo "Running MySQL from the registry..."
                        docker run -d \
                            --name test-mysql \
                            -e MYSQL_ROOT_PASSWORD=rootpassword \
                            -e MYSQL_DATABASE=userdb \
                            -p 3307:3306 \
                            ${MYSQL_IMAGE}
                        
                        # Waiting for MySQL start
                        sleep 30
                        
                        echo "MySQL status:"
                        docker ps | grep mysql
                    """
                    
                    // Running the vulnerable app from the registry
                    sh """
                        echo "Running the vulnerable app from the registry..."
                        docker run -d \
                            --name test-vulnerable-app \
                            --link test-mysql:mysql \
                            -e SPRING_DATASOURCE_URL=jdbc:mysql://mysql:3306/userdb \
                            -e SPRING_DATASOURCE_USERNAME=root \
                            -e SPRING_DATASOURCE_PASSWORD=rootpassword \
                            -p 8081:8080 \
                            ${REGISTRY_LATEST}
                        
                        echo "Vulerable app status:"
                        docker ps | grep vulnerable-app
                        
                        # Waiting for the app start
                        sleep 10
                        
                        echo "Check the app availability..."
                        curl -f http://localhost:8081 || echo "App is not ready yet..."
                    """
                }
            }
        }
        
        // Step 7: Verification
        stage('Verify Deployment') {
            steps {
                echo "Deployment verification..."
                script {
                    sh """
                        echo "=== Containers ==="
                        docker ps
                        
                        echo ""
                        echo "=== Vuln app logs (the first 20 ones) ==="
                        docker logs test-vulnerable-app --tail 20 2>/dev/null || echo "Logs available"
                    """
                }
            }
        }
    }
    
    post {
        always {
            echo "Pipeline completed (status: ${currentBuild.result})"
        }
        
        success {
            echo "✅ Build successful!"
        }
        
        failure {
            echo "❌ Build failed!"
        }
    }
}