pipeline {
    agent none

    options {
        disableConcurrentBuilds()
    }

    triggers {
        gitlab(triggerOnPush: true,
                triggerOnMergeRequest: true,
                branchFilterType: 'All')
    }

    stages {
        stage('Docker build') {
            agent {
                dockerfile {
                    filename 'Dockerfile'
                }
            }
            steps {
                sh 'mkdir build'
                sh 'cd build && cmake -DCPPKCS11_ENABLE_TESTING=1 ..'
                sh 'cd build && make -j4'
                script {
                    tokenSlot = initSoftHSM()
                    echo "Token slot to use: ${tokenSlot}"
                    withEnv(['CPPKCS11_UNDERLYING_LIBRARY=/usr/lib/softhsm/libsofthsm2.so',
                             "CPPKCS11_UNITTEST_TOKEN_SLOT=${tokenSlot}",
                             'CPPKCS11_UNITTEST_PIN=titi',
                             'SOFTHSM2_CONF=/tmp/softhsm.cfg']) {
                        sh "cd build && ctest"
                    }
                }
            }
        }
    }
}

def initSoftHSM() {
    script {
        // Write the softhsm config file...
        writeFile(file: 'softhsm.cfg',
                text: """#SoftHSM v2 configuration file

directories.tokendir = /tmp/
objectstore.backend = file

# ERROR, WARNING, INFO, DEBUG
log.level = ERROR

# If CKF_REMOVABLE_DEVICE flag should be set
slots.removable = false
""")
        // Now move it... apparently writeFile cannot write absolute file...
        sh 'mv softhsm.cfg /tmp'
        sh 'cat /tmp/softhsm.cfg'
        withEnv(['SOFTHSM2_CONF=/tmp/softhsm.cfg']) {
            output = sh(script: 'softhsm2-util --init-token --label "Toto" --pin "titi" --so-pin "tata" --slot 0',
                    returnStdout: true)
            // Sample output: "The token has been initialized and is reassigned to slot 68347983"
            String[] parsed
            parsed = output.split(' ')

            return parsed[10]
        }
    }
}
