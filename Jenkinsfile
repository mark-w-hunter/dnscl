properties([
	[$class: 'BuildDiscarderProperty',strategy: [$class: 'LogRotator', numToKeepStr: '10']],
	pipelineTriggers([[$class: "SCMTrigger", scmpoll_spec: "H/45 * * * *"]])
])

pipeline {
    agent any
    triggers {
        cron('H */4 * * *')
    }

    stages {
        stage('build') {
            steps {
                sh 'pylint dnscl.py'
            }
        }
    }
}
