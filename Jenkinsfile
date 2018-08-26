properties([
	scmpoll_spec: "H/5 * * * *"
])

pipeline {
    agent any 

    stages {
        stage('build') {
            steps {
                sh 'python --version'
                sh 'uname -a'
            }
        }
    }
}
