properties([
	[$class: 'BuildDiscarderProperty',strategy: [$class: 'LogRotator', numToKeepStr: '10']],
	pipelineTriggers([[$class: "SCMTrigger", scmpoll_spec: "H/5 * * * *"]])
])

pipeline {
    agent any 
    triggers {
        cron('H/30 * * * *')
    }

    stages {
        stage('build') {
            steps {
                sh 'python --version'
                sh 'uname -a'
            }
        }
    }
}
