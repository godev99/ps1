Param (
    [string] $username,
    [string] $password,
    [string[]] $organizations,
    [string] $client,
    [string] $secret,
    [string] $tenant
)

$base64AuthInfo = [Convert]::ToBase64String([Text.Encoding]::ASCII.GetBytes(("{0}:{1}" -f $username,$password)))
$headers = @{ Authorization = ("Basic {0}" -f $base64AuthInfo) }
$Csvs = @('ReportEnvironments.csv','ReportOrganization.csv','ReportProjects.csv','ReportReleases.csv','ReportReleasesDef.csv','ReportTasks.csv','ReportDeployments.csv')

ForEach($Csv in $Csvs) {
    If(!(Test-Path $Csv)) {
        New-Item $Csv -Force
    }
}

#Azure
$resource = 'https://management.azure.com'
$body = @{
    grant_type = "client_credentials"
    client_id = $client
    client_secret = $secret
    resource = $resource
}

$resp = Invoke-RestMethod -Method 'Post' -Uri "https://login.microsoftonline.com/$tenant/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body
$azheaders = @{
    Authorization = "Bearer $( $resp.access_token )"
}

$ReportEnvironments = Import-Csv 'ReportEnvironments.csv'
$ReportOrganization = Import-Csv 'ReportOrganization.csv'
$ReportProjects = Import-Csv 'ReportProjects.csv'
$ReportReleases = Import-Csv 'ReportReleases.csv'
$ReportReleasesDef = Import-Csv 'ReportReleasesDef.csv'
$ReportTasks = Import-Csv 'ReportTasks.csv'
$ReportDeployments = Import-Csv 'ReportDeployments.csv'

class ClsOrganization {
    [object] ${OrganizationName_ProjectName}
    [object] ${OrganizationName}
}

class ClsProjects {
    [object] ${OrganizationName_ProjectName}
    [object] ${OrganizationName}
    [object] ${ProjectName}
}

class ClsReleasesDef {
    [object] ${OrganizationName_ProjectName}
    [object] ${OrganizationName_ProjectName_ReleaseDefId}
    [object] ${ReleaseDefId}
    [object] ${ReleaseDefName}
    [object] ${ProjectName}
}

class ClsReleases {
    [object] ${OrganizationName_ProjectName_ReleaseDefId}
    [object] ${OrganizationName_ProjectName_ReleaseDefId_ReleaseId}
    [object] ${ReleaseId}
    [object] ${ReleaseDefId}
}

class ClsEnvironments {
    [object] ${OrganizationName_ProjectName_ReleaseDefId_EnvironmentId}
    [object] ${OrganizationName_ProjectName_ReleaseDefId_ReleaseId}
    [object] ${EnvironmentId}
    [object] ${EnvironmentName}
    [object] ${AttemptNb}
    [object] ${DeploymentDate}
    [object] ${TimetoDeploy}
    [object] ${Status}
    [object] ${ReleaseId}
}

class ClsTasks {
    [object] ${OrganizationName_ProjectName}
    [object] ${OrganizationName_ProjectName_ReleaseDefId}
    [object] ${OrganizationName_ProjectName_ReleaseDefId_ReleaseId}
    [object] ${TaskId_TaskVersion_TimelineRecordId}
    [object] ${TaskId}
    [object] ${TaskVersion}
    [object] ${TaskName}
    [object] ${TaskDisplayName}
    [object] ${TaskStatus}
    [object] ${TaskYear}
    [object] ${TaskDay}
    [object] ${TaskMonth}
    [object] ${TaskDayNumber}
    [object] ${TaskStartDate}
    [object] ${TaskEndDate}
    [object] ${TaskAgentName}
    [object] ${TaskLog}
    [object] ${TaskIssueType}
    [object] ${TimelineRecordId}
    [object] ${EnvironmentName}
    [object] ${Attempt}
    [object] ${JobName}
    [object] ${ReleaseDefName}
    [object] ${DeploymentName}
    [object] ${ProjectName}
    [object] ${ContributionIdentifier}
}

class ClsDeployment {
    [object] ${OrganizationName_ProjectName}
    [object] ${OrganizationName_ProjectName_ReleaseDefId_EnvironmentId}
    [object] ${OrganizationName_ProjectName_ReleaseDefId_ReleaseId}
    [object] ${TaskId_TaskVersion_TimelineRecordId}
    [object] ${DeploymentName_ResourceType_ResourceName_OperationType_DeploymentStatus}
    [object] ${DeploymentName}
    [object] ${DeploymentStatus}
    [object] ${ResourceType}
    [object] ${ResourceName}
    [object] ${OperationType}
}

ForEach($organization in $organizations)
{
    $projects = az devops project list --organization "https://dev.azure.com/$($organization)" --query value[].name  | ConvertFrom-Json
    ForEach ($project in $projects)
    {

        If($ReportOrganization.OrganizationName_ProjectName -notcontains "$( $organization )_$( $project )")
        {
            # Organization Object
            $ListOrganization = [ClsOrganization]::new()
            $ListOrganization.OrganizationName_ProjectName = "$( $organization )_$( $project )"
            $ListOrganization.OrganizationName = $organization
            Write-Host 'OrganizationName_ProjectName' $ListOrganization.OrganizationName_ProjectName
            Write-Host 'OrganizationName' $ListOrganization.OrganizationName
            Write-Host ""
            $ListOrganization | Export-Csv ReportOrganization.csv -NoTypeInformation -Force -Append
        }

        If($ReportProjects.OrganizationName_ProjectName -notcontains "$($organization)_$($project)")
        {
            # Project Object
            $ListProjects = [ClsProjects]::new()
            $ListProjects.OrganizationName_ProjectName = "$($organization)_$($project)"
            $ListProjects.OrganizationName = $organization
            $ListProjects.ProjectName = $project
            Write-Host "ListProjects"
            Write-Host "OrganizationName_ProjectName : " $ListProjects.OrganizationName_ProjectName
            Write-Host "OrganizationName : " $ListProjects.OrganizationName
            Write-Host "ProjectName : " $ListProjects.ProjectName
            Write-Host ""
            $ListProjects | Export-Csv ReportProjects.csv -NoTypeInformation -Force -Append
        }

        $releasesdef = az pipelines release definition list --organization "https://dev.azure.com/$($organization)" --project $project | ConvertFrom-Json
        ForEach ($releasedef in $releasesdef)
        {
            If($ReportReleasesDef.OrganizationName_ProjectName_ReleaseDefId -notcontains "$($organization)_$($project)_$($releasedef.id)_$($release.id)")
            {
                # Release Definition Object
                $ListReleaseDef = [ClsReleasesDef]::new()
                $ListReleaseDef.OrganizationName_ProjectName = "$($organization)_$($project)"
                $ListReleaseDef.OrganizationName_ProjectName_ReleaseDefId = "$($organization)_$($project)_$($releasedef.id)_$($release.id)"
                $ListReleaseDef.ReleaseDefId = $releasedef.id
                $ListReleaseDef.ReleaseDefName = $releasedef.name
                $ListReleaseDef.ProjectName = $project
                Write-Host "ListReleaseDef"
                Write-Host "ReleaseDefId : " $ListReleaseDef.ReleaseDefId
                Write-Host "ReleaseDefName : " $ListReleaseDef.ReleaseDefName
                Write-Host "ProjectName : " $ListReleaseDef.ProjectName
                Write-Host ""
                $ListReleaseDef | Export-Csv ReportReleasesDef.csv -NoTypeInformation -Force -Append
            }

            # List Release per Release Definition Id
            $releases = az pipelines release list --organization "https://dev.azure.com/$($organization)" --project $project --definition-id $releasedef.id | ConvertFrom-Json

            ForEach ($release in $releases)
            {
                $resp = Invoke-RestMethod -Method 'Post' -Uri "https://login.microsoftonline.com/$tenant/oauth2/token" -ContentType "application/x-www-form-urlencoded" -Body $body
                $azheaders = @{
                    Authorization = "Bearer $( $resp.access_token )"
                }

                If($ReportReleases.OrganizationName_ProjectName_ReleaseDefId_ReleaseId -notcontains "$($organization)_$($project)_$($releasedef.id)_$($release.id)")
                {
                    # Release Object
                    $ListRelease = [ClsReleases]::new()
                    $ListRelease.OrganizationName_ProjectName_ReleaseDefId = "$($organization)_$($project)_$($releasedef.id)"
                    $ListRelease.OrganizationName_ProjectName_ReleaseDefId_ReleaseId = "$($organization)_$($project)_$($releasedef.id)_$($release.id)"
                    $ListRelease.ReleaseId = $release.id
                    $ListRelease.ReleaseDefId = $releasedef.id
                    Write-Host "ListRelease"
                    Write-Host "ReleaseId : " $ListRelease.ReleaseId
                    Write-Host "ReleaseDefId : " $ListRelease.ReleaseDefId
                    Write-Host ""
                    $ListRelease | Export-Csv ReportReleases.csv -NoTypeInformation -Force -Append
                }

                # Get Release details
                $releasedetails = az pipelines release show --organization "https://dev.azure.com/$($organization)" --project $project --id $release.id | ConvertFrom-Json
                # Loop through environments
                ForEach ($environment in $releasedetails.environments)
                {
                    If(($environment.status -ne 'notStarted|rejected') -and ($environment.deploySteps.releaseDeployPhases.deploymentJobs.tasks.task.name))
                    {
                        # Add environment only if deployment has been initiated
                        If($ReportEnvironments.OrganizationName_ProjectName_ReleaseDefId_EnvironmentId -notcontains "$($organization)_$($project)_$($releasedef.id)_$($environment.id)")
                        {
                            # Environment Object
                            $ListEnvironments = [ClsEnvironments]::new()
                            $ListEnvironments.OrganizationName_ProjectName_ReleaseDefId_EnvironmentId  = "$($organization)_$($project)_$($releasedef.id)_$($environment.id)"
                            $ListEnvironments.OrganizationName_ProjectName_ReleaseDefId_ReleaseId  = "$($organization)_$($project)_$($releasedef.id)_$($release.id)"
                            $ListEnvironments.EnvironmentId = $environment.id
                            $ListEnvironments.EnvironmentName = $environment.name
                            $ListEnvironments.AttemptNb = $environment.deploySteps.attempt[-1]
                            $ListEnvironments.DeploymentDate = $environment.createdOn
                            $ListEnvironments.TimetoDeploy = $environment.timeToDeploy
                            $ListEnvironments.Status = $environment.status
                            $ListEnvironments.ReleaseId = $release.id
                            Write-Host "ListEnvironments"
                            Write-Host "ProjectName_ReleaseDefId_EnvironmentId : " $ListEnvironments.OrganizationName_ProjectName_ReleaseDefId_EnvironmentI
                            Write-Host "EnvironmentId : " $ListEnvironments.EnvironmentId
                            Write-Host "EnvironmentName : " $ListEnvironments.EnvironmentName
                            Write-Host "Attempt : " $ListEnvironments.AttemptNb
                            Write-Host "DeploymentDate : " $ListEnvironments.DeploymentDate
                            Write-Host "TimetoDeploy : " $ListEnvironments.TimetoDeploy
                            Write-Host "Status : " $ListEnvironments.Status
                            Write-Host "ReleaseId : " $ListEnvironments.ReleaseId
                            Write-Host ""
                            $ListEnvironments | Export-Csv ReportEnvironments.csv -NoTypeInformation -Force -Append
                        }

                        $attempts = $environment.deploySteps
                        $attemptnb = 0
                        ForEach ($attempt in $attempts){
                            $attemptnb += 1
                            $jobs = $attempt.releaseDeployPhases
                            ForEach($job in $jobs){
                                $jobLog = $job.deploymentJobs.job.logUrl

                                # Get all tasks per environment
                                $executedTasks = $job.deploymentJobs.tasks

                                if($jobLog)
                                {
                                    Remove-Item job.log -ErrorAction Continue
                                    Invoke-RestMethod -Uri $jobLog -Method Get -ContentType 'application/json' -Headers $headers | Out-File job.log -Force
                                }

                                $refTasks = $environment.deployPhasesSnapshot.workflowTasks
                                [System.Collections.ArrayList]$refTasksArray = @()

                                ForEach ($refTask in $refTasks)
                                {
                                    # If taskname is equal to 'test $(keyvault)' we will replace $(keyvault) by its value.
                                    $regex = '\${1}\({1}[\S]+\){1}'
                                    $regmatches = $refTask.name | Select-String $regex -AllMatches
                                    $newname = $refTask.name
                                    ForEach ($m in $regmatches.Matches.Value)
                                    {
                                        $name = $m.Split('$(')[2].Split(')')[0]
                                        $newregex = "[$( $name )] --> "
                                        $joblog = Get-Content .\job.log
                                        $line = $joblog -match "\[$name\] --> \["
                                        $value = ($line -Split '--> \[')[1].Split('\]')[0]
                                        $newname = $newname -Replace "\$\($name\)", $value
                                        $refTasksArray.Add(@($newname,$refTask.name)) > Out-null
                                    }
                                    If(! ($regmatches.Matches.Value))
                                    {
                                        $refTasksArray.Add(@($refTask.name,$refTask.name)) > Out-null
                                    }
                                }

                                # For every Task in Release
                                ForEach ($executedTask in $executedTasks)
                                {
                                    If($executedTask.task.name -and ($executedTask.status -notmatch 'skipped'))
                                    {

                                        If($executedTask.task.name -match 'AzureResourceGroupDeployment|AzureResourceManagerTemplateDeployment'){
                                            ForEach($refTaskArray in $refTasksArray){
                                                If($executedTask.name -like $refTaskArray[0])
                                                {
                                                    $refTask = $environment.deployPhasesSnapshot.workflowTasks | Where-Object{ $_.name -like $refTaskArray[1] }
                                                    $endpointid = $refTask.inputs.ConnectedServiceName
                                                    Write-Host 'match!'

                                                    If($executedTask.logUrl)
                                                    {
                                                        try {
                                                            $uri = $executedTask.logUrl
                                                            Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -Headers $headers | Out-File task.log -Force
                                                        }
                                                        catch {
                                                            Write-Error 'Deployment request failed'
                                                        }
                                                        #write-host '#######################'
                                                        $regex = 'Deployment name is'
                                                        $response = (Select-String -Path .\task.log -Pattern $regex -AllMatches)
                                                        #$response
                                                        $newregex = 'Checking if the following resource group exists'
                                                        $newresponse = (Select-String -Path .\task.log -Pattern $newregex -AllMatches)
                                                        #$newresponse.Matches
                                                        #write-host '#######################'

                                                        If($response -and $newresponse)
                                                        {
                                                            Write-Host 'ok!'
                                                            $rgName = $newresponse.Line.Split(' ')[- 1]
                                                            $rgName = $rgName.Substring(0, $rgName.Length - 1)
                                                            $deploymentName = $response.Line.Split(' ')[- 1]

                                                            $uri = "https://dev.azure.com/$organization/$project/_apis/serviceendpoint/endpoints?endpointIds=$( $endpointid )&api-version=6.0-preview.4"
                                                            $endpointid = ''
                                                            $response = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -Headers $Headers
                                                            $subscriptionid = $response.value.data.subscriptionId
                                                            if((Get-AzContext).Subscription.Id -notmatch $subscriptionid) {
                                                                Select-AzSubscription $subscriptionid
                                                            }
                                                            try
                                                            {
                                                                $rg = Get-AzResourceGroup | Where-Object{$_.ResourceGroupName -match $rgName}
                                                                if($rg){
                                                                    $deployment = Get-AzResourceGroupDeployment -ResourceGroupName $rgName -DeploymentName $deploymentName
                                                                } else {
                                                                    Write-Host 'subscription ' $subscriptionid
                                                                    Write-Host 'no rg found ' $rgName
                                                                    Write-Host ''
                                                                    Continue
                                                                }
                                                            }
                                                            catch
                                                            {
                                                                Write-Host 'no deployment found'
                                                                Write-Host ''
                                                                Continue
                                                            }

                                                            if($deployment)
                                                            {
                                                                Write-Host 'deployment detected' $deploymentName
                                                                try
                                                                {
                                                                    $operationIds = (Get-AzResourceGroupDeploymentOperation -ResourceGroupName $rgName -DeploymentName $deploymentName).OperationId
                                                                }
                                                                catch {
                                                                    Write-Error 'Failed to retrieve deployment'
                                                                }
                                                                    $operations = @()
                                                                    ForEach ($operationId in $operationIds)
                                                                    {
                                                                        Write-Host 'operationId :' $operationId
                                                                        $ListDeployment = [ClsDeployment]::new()
                                                                        $ListDeployment.OrganizationName_ProjectName = "$($organization)_$($project)"
                                                                        $ListDeployment.OrganizationName_ProjectName_ReleaseDefId_EnvironmentId  = "$($organization)_$($project)_$($releasedef.id)_$($environment.id)"
                                                                        $ListDeployment.DeploymentName = $deploymentName
                                                                        $ListDeployment.OrganizationName_ProjectName_ReleaseDefId_ReleaseId = "$($organization)_$($project)_$($releasedef.id)_$($release.id)"
                                                                        $ListDeployment.TaskId_TaskVersion_TimelineRecordId = "$( $executedTask.task.id )_$( $executedTask.task.version )_$( $executedTask.timelineRecordId )"

                                                                        $uri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$rgName/providers/Microsoft.Resources/deployments/$deploymentName/operations/$( $operationId )?api-version=2020-06-01"
                                                                        $response = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -Headers $azheaders
                                                                        if($response.properties.targetResource.resourceType -match 'Microsoft.Resources/deployments')
                                                                        {
                                                                            #Write-Host 'deployment resourcetype detected' $response.properties.targetResource.resourceType
                                                                            $newoperationIds = (Get-AzResourceGroupDeploymentOperation -ResourceGroupName $rgName -DeploymentName $response.properties.targetResource.resourceName).OperationId
                                                                            ForEach ($newoperationId in $newoperationIds)
                                                                            {
                                                                                $uri = "https://management.azure.com/subscriptions/$subscriptionid/resourceGroups/$rgName/providers/Microsoft.Resources/deployments/$( $response.properties.targetResource.resourceName )/operations/$( $newoperationId )?api-version=2020-06-01"
                                                                                $newResponse = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -Headers $azheaders
                                                                                if($newResponse.properties.provisioningOperation -match 'EvaluateDeploymentOutput')
                                                                                {
                                                                                    Continue
                                                                                }
                                                                                $ListDeployment.ResourceType = $newResponse.properties.targetResource.resourceType
                                                                                $ListDeployment.ResourceName = $newResponse.properties.targetResource.resourceName
                                                                                $ListDeployment.OperationType = $newResponse.properties.provisioningOperation
                                                                                $ListDeployment.DeploymentStatus = $newResponse.properties.provisioningState
                                                                            }
                                                                        }
                                                                        else
                                                                        {
                                                                            #Write-Host 'normal deployment detected' $response.properties.targetResource.resourceType
                                                                            if($response.properties.provisioningOperation -match 'EvaluateDeploymentOutput')
                                                                            {
                                                                                Continue
                                                                            }
                                                                            $ListDeployment.ResourceType = $response.properties.targetResource.resourceType
                                                                            $ListDeployment.ResourceName = $response.properties.targetResource.resourceName
                                                                            $ListDeployment.OperationType = $response.properties.provisioningOperation
                                                                            $ListDeployment.DeploymentStatus = $response.properties.provisioningState
                                                                        }
                                                                        $ListDeployment.DeploymentName_ResourceType_ResourceName_OperationType_DeploymentStatus = "$($ListDeployment.DeploymentName)_$($ListDeployment.ResourceType)_$($ListDeployment.ResourceName)_$($ListDeployment.OperationType)__$($ListDeployment.DeploymentStatus)"
                                                                        Write-Host "ListDeployments"
                                                                        Write-Host "DeploymentName : " $ListDeployment.DeploymentName
                                                                        Write-Host "ResourceType : " $ListDeployment.ResourceType
                                                                        Write-Host "ResourceName : " $ListDeployment.ResourceName
                                                                        Write-Host "OperationType : " $ListDeployment.OperationType
                                                                        Write-Host "Status : " $ListDeployment.DeploymentStatus

                                                                        Write-Host ''
                                                                        $ListDeployment | Export-Csv ReportDeployments.csv -NoTypeInformation -Force -Append
                                                                    }
                                                            }
                                                        }
                                                    }
                                                }
                                            }
                                        } elseif($executedTask.task.name -notmatch 'DownloadBuildArtifacts') {
                                            # Get task contribution
                                            $taskId = $executedTask.task.id

                                            $uri = "https://dev.azure.com/$organization/_apis/distributedtask/tasks/$taskId"
                                            Write-Host 'uri' $uri
                                            try {
                                                $response = Invoke-RestMethod -Uri $uri -Method Get -ContentType 'application/json' -Headers $headers
                                                $ContributionIdentifier = $response.value[0].contributionIdentifier
                                            }
                                            catch{
                                                $ContributionIdentifier = 'Undefined'
                                            }

                                            If($ContributionIdentifier -eq ""){
                                                $ContributionIdentifier = 'Undefined'
                                            }

                                            If($addenv -eq $true) {
                                                # reset addenv
                                                $addenv = $false
                                            }

                                            If($ReportTasks.TaskId_TaskVersion_TimelineRecordId -notcontains "$( $executedTask.task.id )_$( $executedTask.task.version )_$( $executedTask.timelineRecordId )") {
                                                # Tasks Object
                                                $TaskYear = $executedTask.finishTime | Get-Date -UFormat %Y
                                                $TaskDay = $executedTask.finishTime | Get-Date -UFormat %A
                                                $TaskMonth = $executedTask.finishTime | Get-Date -UFormat %B
                                                $TaskDayNumber = $executedTask.finishTime | Get-Date -UFormat %d

                                                $ListTasks = [ClsTasks]::new()
                                                $ListTasks.OrganizationName_ProjectName  = "$($organization)_$($project)"
                                                $ListTasks.OrganizationName_ProjectName_ReleaseDefId  = "$($organization)_$($project)_$($releasedef.id)"
                                                $ListTasks.OrganizationName_ProjectName_ReleaseDefId_ReleaseId  = "$($organization)_$($project)_$($releasedef.id)_$($release.id)"
                                                $ListTasks.TaskId_TaskVersion_TimelineRecordId = "$( $executedTask.task.id )_$( $executedTask.task.version )_$( $executedTask.timelineRecordId )"
                                                $ListTasks.TaskId = $executedTask.task.id
                                                $ListTasks.TaskVersion = $executedTask.task.version
                                                $ListTasks.TaskName = $executedTask.task.name
                                                $ListTasks.TaskDisplayName = $executedTask.name
                                                $ListTasks.TaskDisplayName = $executedTask.name
                                                $ListTasks.TaskStatus = $executedTask.status
                                                $ListTasks.TaskYear = $TaskYear
                                                $ListTasks.TaskMonth = $TaskMonth
                                                $ListTasks.TaskDay = $TaskDay
                                                $ListTasks.TaskDayNumber = $TaskDayNumber
                                                $ListTasks.TaskStartDate = $executedTask.dateStarted
                                                $ListTasks.TaskEndDate = $executedTask.dateEnded
                                                $ListTasks.TaskAgentName = $executedTask.agentName
                                                $ListTasks.TaskLog = $executedTask.logUrl
                                                $ListTasks.TaskIssueType = $executedTask.issues.issueType
                                                $ListTasks.TimelineRecordId = $executedTask.timelineRecordId
                                                $ListTasks.EnvironmentName = $environment.name
                                                $ListTasks.Attempt = $attemptnb
                                                $ListTasks.JobName = $job.name
                                                $ListTasks.ReleaseDefName = $releasedef.name
                                                $ListTasks.ProjectName = $project
                                                $ListTasks.ContributionIdentifier = $ContributionIdentifier
                                                Write-Host "ListTasks"
                                                Write-Host "TaskId : " $ListTasks.TaskId
                                                Write-Host "TaskVersion : " $ListTasks.TaskVersion
                                                Write-Host "TaskName : " $ListTasks.TaskName
                                                Write-Host "TaskDisplayName : " $ListTasks.TaskDisplayName
                                                Write-Host "TaskAgentName : " $ListTasks.TaskAgentName
                                                Write-Host "TaskStatus : " $ListTasks.TaskStatus
                                                Write-Host "TaskStartDate : " $ListTasks.TaskStartDate
                                                Write-Host "TaskEndDate : " $ListTasks.TaskEndDate
                                                Write-Host "TaskYear : " $ListTasks.TaskYear
                                                Write-Host "TaskMonth : " $ListTasks.TaskMonth
                                                Write-Host "TaskDayNumber : " $ListTasks.TaskDayNumber
                                                Write-Host "TaskDay : " $ListTasks.TaskDay
                                                Write-Host "TaskLog : " $ListTasks.TaskLog
                                                Write-Host "TaskIssueType : " $ListTasks.TaskIssueType
                                                Write-Host "TimelineRecordId : " $ListTasks.TimelineRecordId
                                                Write-Host "EnvironmentName : " $ListTasks.EnvironmentName
                                                Write-Host "Attempt : " $ListTasks.Attempt
                                                Write-Host "JobName : " $ListTasks.JobName
                                                Write-Host "ReleaseDefName : " $ListTasks.ReleaseDefName
                                                Write-Host "ProjectName : " $project
                                                Write-Host "ContributionIdentifier : " $ContributionIdentifier
                                                Write-Host ""
                                                $ListTasks | Export-Csv ReportTasks.csv -NoTypeInformation -Force -Append
                                            }
                                        }
                                    }
                                }
                            }
                        }
                    }
                }
                Write-Host ""
            }
        }
    }
}


