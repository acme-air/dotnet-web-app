// path of the template to use
def templatePath = 'https://raw.githubusercontent.com/acme-air/dotnet-web-app/master/openshift/templates/dotnet-app-template.json'
// name of the template that will be created
def templateName = 'dotnet-web-app'
// NOTE, the "pipeline" directive/closure from the declarative pipeline syntax needs to include, or be nested outside,
// and "openshift" directive/closure from the OpenShift Client Plugin for Jenkins.  Otherwise, the declarative pipeline engine
// will not be fully engaged.
pipeline {
    agent any
    options {
        // set a timeout of 20 minutes for this pipeline
        timeout(time: 20, unit: 'MINUTES')
        parallelsAlwaysFailFast()
    }

    environment {
        
        DOCKER_REGISTRY="797124978737.dkr.ecr.us-east-2.amazonaws.com"
        DOCKER_REPOSITORY="gsort_fargate_integration_service"
        REGION="us-east-2"
        BUILD_TAG= "latest"
        IGNORE_ENV='DL3006,DL3020,DL4000'
    }

    stages {
        stage('initialize') {
           steps {
                checkout scm
                echo "Initialized"
            } // steps
        } //stage
        stage('Linting') {
            steps {
                sh 'printf "ignored:" > hadolint.conf;'
                sh '(IFS=","; for word in ${IGNORE_ENV}; do printf "\n  - $word" >> hadolint.conf ; done)'            
                sh 'hadolint-Linux-x86_64 --trusted-registry mcr.microsoft.com -c hadolint.conf dotnet-web-app-inspec/Dockerfile'
            } // steps
        } // stage
        stage('build') {
            parallel {
                stage('local') {
                    steps {
                        script {
                            sh "docker build -t ${DOCKER_REGISTRY}/${DOCKER_REPOSITORY}:${BUILD_TAG} -f NetCoreDockerTest/Dockerfile ."
                        } // script
                    } // steps
                } // stage
                stage('remote-check') {
                    steps {
                        echo "Done"
                    } // steps
                } // stage
            } // parallel
        } // stage
        stage("scan prep") {
            steps {
                script {
                    sh '''#!/bin/bash
                    echo "" >> wicked-suppression.txt
                    '''
                }
            }
        }
        stage('test') {
            steps {
                echo "Done"
            } // steps
        } // stage
        stage('Quality Gate') {
            parallel {
                stage('SonarQube') {
                    steps {
                        script {
                            withSonarQubeEnv('acme-sonarqube') {
                                def scannerHome = tool 'acme-sonarqube';
                                sh "${scannerHome}/bin/sonar-scanner"
                                sh "sleep 30"
                            }
                            def qg = waitForQualityGate()
                            if (qg.status != 'OK') {
                                error "Pipeline aborted due to quality gate failure: ${qg.status}"
                            }
                        }
                    }
                } // stage
                stage("OWASP Check") {
                    steps {
                         dependencyCheck additionalArguments: '', odcInstallation: 'acme-dependency-check'
                         dependencyCheckPublisher pattern: ''
                         sh "echo Done"
                    } // steps
                } // stage
                //stage('Twistlock') {
                //   steps {
                //        script {
                //            echo "Running Twistlock scan on image ${templateName}:latest"
                //            prismaCloudScanImage ca: '', cert: '', dockerAddress: 'tcp://192.168.64.10:2375', ignoreImageBuildTime: true, image: "${templateName}:latest", key: '', logLevel: 'debug', podmanPath: '', project: '', resultsFile: 'prisma-cloud-scan-results.json'
                //            echo "Completed Twistlock scan."
                //            echo "Publishing Analysis"
                //            prismaCloudPublish resultsFilePattern: 'prisma-cloud-scan-results.json'
                //            echo "Completed Twistlock publish"
                //        } // script
                //    } // steps
                //} // stage
                stage('Clair Scan') {
                  steps 
                  {  
                    script 
                    {
                      sh '''#!/bin/bash
                        ts() {
                          date "+%Y-%m-%d %k:%M:%S"
                        }
                        #
                        # parse command line arguments
                        #
                        VERBOSE=0
                        #IMAGE_ASSESS_RISK_VERBOSE_FLAG=-s
                        IMAGE_ASSESS_RISK_VERBOSE_FLAG=-v
                        NO_PULL_DOCKER_IAMGES=0
                        VULNERABILITY_WHITELIST='json://{"ignoreSevertiesAtOrBelow": "critical"}'
                        #
                        # :TRICKY: if this configuration is changed be sure to also change
                        # .cut-release-release-branch-changes.sh
                        #
                        # :TODO: how do we ensure Clair version and database version are the same?
                        #
                        CLAIR_CICD_VERSION=latest
                        CLAIR_DATABASE_IMAGE=simonsdave/clair-cicd-database:${CLAIR_CICD_VERSION}
                        CLAIR_VERSION=$(docker run --rm "${CLAIR_DATABASE_IMAGE}" /bin/bash -c 'echo ${CLAIR_VERSION}')
                        CLAIR_IMAGE=invhariharan/clair-cicd-clair:${CLAIR_CICD_VERSION}
                        aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${DOCKER_REGISTRY}
                        docker pull ${DOCKER_REGISTRY}/${DOCKER_REPOSITORY}:${BUILD_TAG}

                        DOCKER_IMAGE_TO_ANALYZE=797124978737.dkr.ecr.us-east-2.amazonaws.com/gsort_fargate_integration_service:latest
                        echo  "About to pull images"
                        #
                        # pull image and spin up clair database
                        #
                        if [ "0" -eq "${NO_PULL_DOCKER_IAMGES:-0}" ]; then
                            echo "$(ts) pulling clair database image '${CLAIR_DATABASE_IMAGE}'"
                            if ! docker pull "${CLAIR_DATABASE_IMAGE}" > /dev/null; then
                                echo "$(ts) error pulling clair database image '${CLAIR_DATABASE_IMAGE}'" >&2
                                exit 1
                            fi
                            echo "$(ts) successfully pulled clair database image"
                        else
                            echo "$(ts) **not** pulling clair database image '${CLAIR_DATABASE_IMAGE}'"
                        fi
                        # CLAIR_DATABASE_CONTAINER=clair-db-$(echo $RANDOM | tr '[0-9]' '[a-z]')
                        CLAIR_DATABASE_CONTAINER=clair-db-001
                        echo "$(ts) starting clair database container '${CLAIR_DATABASE_CONTAINER}'"
                        if ! docker run --name "${CLAIR_DATABASE_CONTAINER}" -d "${CLAIR_DATABASE_IMAGE}" > /dev/null; then
                            echo "$(ts) error starting clair database container '${CLAIR_DATABASE_CONTAINER}'" >&2
                            exit 1
                        fi
                        echo -n "$(ts) waiting for database server in container '${CLAIR_DATABASE_CONTAINER}' to start "
                        while true
                        do
                            if docker logs "${CLAIR_DATABASE_CONTAINER}" 2>&1 | grep "database system is ready to accept connections" > /dev/null; then
                                break
                            fi
                            echo -n "."
                            sleep 1
                        done
                        echo ""
                        echo "$(ts) successfully started clair database container"
                        #
                        # create and configure clair config container
                        #
                        # :TRICKY: motivation for creating this container is described in
                        # https://circleci.com/docs/2.0/building-docker-images/#mounting-folders
                        #
                        # CLAIR_CONFIG_CONTAINER=clair-config-$(echo $RANDOM | tr '[0-9]' '[a-z]')
                        CLAIR_CONFIG_CONTAINER=clair-config-001
                        CLAIR_CONFIG_YAML=$(mktemp 2> /dev/null || mktemp -t DAS)
                        echo "$(ts) clair configuration in '${CLAIR_CONFIG_YAML}'"
                        curl \
                            -s \
                            -o "${CLAIR_CONFIG_YAML}" \
                            -L \
                            "https://raw.githubusercontent.com/coreos/clair/${CLAIR_VERSION}/config.example.yaml"
                        sed \
                            -i \
                            -e 's|source:.*$|source: postgresql://postgres@clair-database:5432/clair?sslmode=disable|g' \
                            "${CLAIR_CONFIG_YAML}"
                        CLAIR_CONFIG_IMAGE=alpine:3.4
                        # explict pull to create opportunity to swallow stdout
                        docker pull "${CLAIR_CONFIG_IMAGE}" > /dev/null
                        docker create \
                            -v /config \
                            --name "${CLAIR_CONFIG_CONTAINER}" \
                            "${CLAIR_CONFIG_IMAGE}" \
                            /bin/true \
                            > /dev/null
                        docker cp "${CLAIR_CONFIG_YAML}" "${CLAIR_CONFIG_CONTAINER}:/config/config.yaml"
                        #
                        # pull image and spin up clair
                        #
                        if [ "0" -eq "${NO_PULL_DOCKER_IAMGES:-0}" ]; then
                            echo "$(ts) pulling clair image '${CLAIR_IMAGE}'"
                            if ! docker pull "${CLAIR_IMAGE}" > /dev/null; then 
                                echo "$(ts) error pulling clair image '${CLAIR_IMAGE}'" >&2
                                exit 1
                            fi
                            echo "$(ts) successfully pulled clair image '${CLAIR_IMAGE}'"
                        else
                            echo "$(ts) **not** pulling clair image '${CLAIR_IMAGE}'"
                        fi
                        #
                        # :TODO: need to derive the ports
                        # CLAIR_API_PORT @ .clair.api.port in ${CLAIR_CONFIG_YAML}
                        # CLAIR_HEALTH_API_PORT @ .clair.api.healthport in ${CLAIR_CONFIG_YAML}
                        CLAIR_API_PORT=6060
                        CLAIR_HEALTH_API_PORT=6061
                        # {"Event":"starting main API","Level":"info","Location":"api.go:52","Time":"2019-12-31 17:11:28.608914","port":6060}
                        # {"Event":"starting health API","Level":"info","Location":"api.go:85","Time":"2019-12-31 17:11:28.609998","port":6061}
                        #
                        #    -p "${CLAIR_API_PORT}":"${CLAIR_API_PORT}" \
                        #    -p "${CLAIR_HEALTH_API_PORT}":"${CLAIR_HEALTH_API_PORT}" \
                        # CLAIR_CONTAINER=clair-$(echo $RANDOM | tr '[0-9]' '[a-z]')
                        CLAIR_CONTAINER=clair-001
                        echo "$(ts) starting clair container '${CLAIR_CONTAINER}'"
                        if ! docker run \
                            -d \
                            --name "${CLAIR_CONTAINER}" \
                            --link "${CLAIR_DATABASE_CONTAINER}":clair-database \
                            --volumes-from "${CLAIR_CONFIG_CONTAINER}" \
                            -v /var/run/docker.sock:/var/run/docker.sock \
                            "${CLAIR_IMAGE}" \
                            -log-level=debug \
                            -config=/config/config.yaml \
                            > /dev/null;
                        then
                            echo "$(ts) error starting clair container '${CLAIR_CONTAINER}'" >&2
                            exit 1
                        fi
                        #
                        # wait for Clair to start
                        #
                        while true
                        do
                            HTTP_STATUS_CODE=$(docker exec "${CLAIR_CONTAINER}" curl -s --max-time 3 -o /dev/null -w '%{http_code}' "http://127.0.0.1:${CLAIR_HEALTH_API_PORT}/health")
                            if [ "200" == "${HTTP_STATUS_CODE}" ]; then
                                break
                            fi
                            sleep 1
                        done
                        echo "$(ts) successfully started clair container '${CLAIR_CONTAINER}'"
                        #
                        # if the vulnerability whitelist is in a file copy the file into
                        # Clair container so it's accessible to assess-image-risk.sh
                        #
                        echo "check whitelisting"
                        if [[ $VULNERABILITY_WHITELIST == file://* ]]; then
                            VULNERABILITY_WHITELIST_IN_CONTAINER=/tmp/whitelist.json
                        #    if ! docker cp "${VULNERABILITY_WHITELIST/file:///}" "${CLAIR_CONTAINER}:${VULNERABILITY_WHITELIST_IN_CONTAINER}"; then
                        #        echo "$(ts) error copying whitelist from '${VULNERABILITY_WHITELIST/file:///}' to '${CLAIR_CONTAINER}:${VULNERABILITY_WHITELIST_IN_CONTAINER}'" >&2
                        #        exit 1
                        #    fi
                            VULNERABILITY_WHITELIST=file://${VULNERABILITY_WHITELIST_IN_CONTAINER}
                        fi
                        echo "assesing image risk "
                        #
                        # Now that the Clair container and Clair database container are started
                        # it's time to kick-off the process of assessing the image's risk.
                        #
                        echo ${VULNERABILITY_WHITELIST}
                        docker exec "${CLAIR_CONTAINER}" assess-image-risk.sh --whitelist "${VULNERABILITY_WHITELIST}" --api-port "${CLAIR_API_PORT}" "${IMAGE_ASSESS_RISK_VERBOSE_FLAG}" "${DOCKER_IMAGE_TO_ANALYZE}"
                        scan_status=$?
                        #docker exec "${CLAIR_CONTAINER}" assess-image-risk.sh  --api-port "${CLAIR_API_PORT}" "${IMAGE_ASSESS_RISK_VERBOSE_FLAG}" "${DOCKER_IMAGE_TO_ANALYZE}"
                        echo "Completed scan"

                        echo "cleaning up  image  "
                        #
                        # a little bit of cleanup
                        #
                        docker kill "${CLAIR_CONTAINER}" >& /dev/null
                        docker rm "${CLAIR_CONTAINER}" >& /dev/null
                        docker kill "${CLAIR_CONFIG_CONTAINER}" >& /dev/null
                        docker rm "${CLAIR_CONFIG_CONTAINER}" >& /dev/null
                        docker kill "${CLAIR_DATABASE_CONTAINER}" >& /dev/null
                        docker rm "${CLAIR_DATABASE_CONTAINER}" >& /dev/null
                        #
                        # we're all done:-)
                        #
                        if [[ ${scan_status} -ne 0 ]];
                        then
                          exit 1
                        else
                          exit 0
                        fi
                      '''

                    }
                  }
                } 
                stage('Compliance') {
                    steps {
                        sh 'echo Running compliance'
                        sh 'rm -rf dotnet-web-app-inspec'
                        sh 'git clone https://github.com/acme-air/dotnet-web-app-inspec'
                        sh 'inspec exec dotnet-web-app-inspec --reporter=junit junit:output.xml'
                    }
                }
            } // parallel
        } // stage
        stage('Push image to ECR'){
            steps{
                sh "aws ecr get-login-password --region ${REGION} | docker login --username AWS --password-stdin ${DOCKER_REGISTRY}"
                sh "docker push ${DOCKER_REGISTRY}/${DOCKER_REPOSITORY}:${BUILD_TAG}"
            }
        }
        stage('deploy') {
            steps {
                echo "Done"
            } // steps
        } // stage
        stage('promote') {
            steps {
                echo "Done"
            } // steps
        } // stage
    } // stages
    post {
        always {
            junit '*.xml'
        }
    }
} // pipeline
