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
        PACKAGE_NAME = "cppkcs11/1.1@islog/master"
    }

    stages {
        stage('Docker build') {
        agent { docker { image 'docker-registry.islog.com:5000/conan-recipes-support-buster:latest' } }
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
                        sh "cd build && ctest"
                    }
                }
            }
        }

        stage('Build Conan Package') {
            // Build packages for various configuration we use at Islog.
            parallel {
                stage('Linux 64 Release GCC 6') {
                    agent { docker { image 'docker-registry.islog.com:5000/conan-recipes-support:latest' } }
                    steps {
                        script {
                            conan.installIslogProfiles("$HOME/.conan")
                            sh "conan create -p compilers/x64_gcc6_release . ${PACKAGE_NAME}"
                            sh "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                        }
                    }
                }
                stage('Linux 64 Debug GCC 6') {
                    agent { docker { image 'docker-registry.islog.com:5000/conan-recipes-support:latest' } }
                    steps {
                        script {
                            conan.installIslogProfiles("$HOME/.conan")
                            sh "conan create -p compilers/x64_gcc6_debug . ${PACKAGE_NAME}"
                            sh "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                        }
                    }
                }
               stage('Linux 64 Release GCC 8') {
                    agent { docker { image 'docker-registry.islog.com:5000/conan-recipes-support-buster:latest' } }
                    steps {
                        script {
                            sh "conan create -p compilers/x64_gcc8_release . ${PACKAGE_NAME}"
                            sh "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                        }
                    }
                }
                stage('Linux 64 Debug GCC 8') {
                    agent { docker { image 'docker-registry.islog.com:5000/conan-recipes-support-buster:latest' } }
                    steps {
                        script {
                            sh "conan create -p compilers/x64_gcc8_debug . ${PACKAGE_NAME}"
                            sh "conan upload ${PACKAGE_NAME} -r islog-test --all --confirm --check --force"
                        }
                    }
                }

                stage('Windows 64 Release') {
                    agent { label 'win2016' }
                    steps {
                        script {
                            conan.withFreshWindowsConanCache {
                                bat "conan create -p compilers/x64_msvc_release . ${PACKAGE_NAME}"
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
                                bat "conan create -p compilers/x64_msvc_debug . ${PACKAGE_NAME}"
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
                                bat "conan create -p compilers/x86_msvc_release . ${PACKAGE_NAME}"
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
                                bat "conan create -p compilers/x86_msvc_debug . ${PACKAGE_NAME}"
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
            output = sh(script: 'softhsm2-util --init-token --label "Toto" --pin "titi" --so-pin "tata" --slot 0',
                    returnStdout: true)
            // Sample output: "The token has been initialized and is reassigned to slot 68347983"
            String[] parsed
            parsed = output.split(' ')

            return parsed[10]
        }
    }
}
