@Library("islog-helper") _

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

    environment {
        // Fix MSBuild issue for Windows builds.
        MSBUILDDISABLENODEREUSE = 1
        PACKAGE_NAME = "cppkcs11/1.1"
    }

    stages {
        stage('Docker build') {
            agent {
                docker {
                    alwaysPull true
                    image 'artifacts.linq.hidglobal.com:5000/debian_build:latest'
                }
            }
            steps {
                sh 'mkdir build'
                sh 'cd build && conan install ..'
                sh 'cd build && conan build ..'
                script {
                    tokenSlot = initSoftHSM()
                    echo "Token slot to use: ${tokenSlot}"
                    withEnv(['CPPKCS11_UNDERLYING_LIBRARY=/usr/lib/softhsm/libsofthsm2.so',
                             "CPPKCS11_UNITTEST_TOKEN_SLOT=${tokenSlot}",
                             'CPPKCS11_UNITTEST_PIN=titi',
                             'SOFTHSM2_CONF=/tmp/softhsm.cfg']) {
                        sh "cd build && ctest -V"
                    }
                }
            }
        }

        stage('Build Conan Package') {
            // Build packages for various configuration we use at Islog.
            parallel {
                stage('Linux 64 Release GCC 10') {
                    agent { docker { image 'artifacts.linq.hidglobal.com:5000/debian_build:latest' } }
                    steps {
                        script {
                            conan.installIslogProfiles("$HOME/.conan")
                            sh "conan create -profile compilers/x64_gcc10_release . ${PACKAGE_NAME}"
                            sh "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                        }
                    }
                }
                stage('Linux 64 Debug GCC 10') {
                    agent { docker { image 'artifacts.linq.hidglobal.com:5000/debian_build:latest' } }
                    steps {
                        script {
                            conan.installIslogProfiles("$HOME/.conan")
                            sh "conan create -pr compilers/x64_gcc10_debug . ${PACKAGE_NAME}"
                            sh "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                        }
                    }
                }

                stage('Windows 64 Release') {
                    agent { label 'win2016' }
                    steps {
                        script {
                            conan.withFreshWindowsConanCache {
                                bat "conan create -pr compilers/x64_msvc_release . ${PACKAGE_NAME}"
                                bat "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                            }
                        }
                    }
                }

                stage('Windows 64 Debug') {
                    agent { label 'win2016' }
                    steps {
                        script {
                            conan.withFreshWindowsConanCache {
                                bat "conan create -pr compilers/x64_msvc_debug . ${PACKAGE_NAME}"
                                bat "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                            }
                        }
                    }
                }

                stage('Windows 32 Release') {
                    agent { label 'win2016' }
                    steps {
                        script {
                            conan.withFreshWindowsConanCache {
                                bat "conan create -pr compilers/x86_msvc_release . ${PACKAGE_NAME}"
                                bat "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                            }
                        }
                    }
                }

                stage('Windows 32 Debug') {
                    agent { label 'win2016' }
                    steps {
                        script {
                            conan.withFreshWindowsConanCache {
                                bat "conan create -pr compilers/x86_msvc_debug . ${PACKAGE_NAME}"
                                bat "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                            }
                        }
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
            output = sh(script: '/usr/bin/softhsm2-util --init-token --label "Toto" --pin "titi" --so-pin "tata" --slot 0',
                    returnStdout: true)
            // Sample output: "The token has been initialized and is reassigned to slot 68347983"
            String[] parsed
            parsed = output.split(' ')

            return parsed[10]
        }
    }
}
