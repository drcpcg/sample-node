import json
import boto3
import botocore
import logging
import time
import sys
logger = logging.getLogger()
logger.setLevel(logging.INFO)
client_ecs = boto3.client('ecs')
client_ses = boto3.client('ses')


def assume_role(account_id, account_role):
    creds = {}
    sts_client = boto3.client('sts')
    role_arn = 'arn:aws:iam::' + account_id + ':role/' + account_role
    print(role_arn)
    assuming_role = True
    while assuming_role is True:
        try:
            assuming_role = False
            assumedRoleObject = sts_client.assume_role(
                RoleArn=role_arn,
                RoleSessionName="NewAccountRole"
            )
        except botocore.exceptions.ClientError as e:
            assuming_role = True
            logger.error(e)
            logger.error("Retrying...")
            time.sleep(60)
    creds['aws_access_key_id'] = assumedRoleObject['Credentials']['AccessKeyId']
    creds['aws_secret_access_key'] = assumedRoleObject['Credentials']['SecretAccessKey']
    creds['aws_session_token'] = assumedRoleObject['Credentials']['SessionToken']
    session = boto3.session.Session(**creds)
    return session
  

def setup_clients(session, client, region, *args):
    for arg in args:
        client[arg] = session.client(arg, region_name=region)
    return client


def get_task_def(td):
    task = None
    try:   
        task = clients['ecs'].describe_task_definition(
            taskDefinition=td
        )
        print("TaskDefinition = {}".format(task))
    except Exception as e:
        print("Could not get task def. {}".format("e"))
    return task


def check_task_def_volumes(td):
    print("Checking task def. for volumes")
    volumes = []
    for v in td["taskDefinition"]["volumes"]:
        if v['name'] != "tw_policy":
            volumes.append(v)
    print("Volumes = {}".format(volumes))
    return volumes
    

def check_task_file_system(td):
    print("Checking task def. for storage")
    container = {}
    for num, v in enumerate(td["taskDefinition"]["containerDefinitions"]):
        if "readonlyRootFilesystem" in v:
            if v['readonlyRootFilesystem'] != "true":
                container['ContainerName'+str(num)] = v['name']
                container['readonlyRootFilesystem'+str(num)] = v['readonlyRootFilesystem']
        else:
            container['ContainerName'+str(num)] = v['name']
            container['readonlyRootFilesystem'+str(num)] = "NOT-SET"
    print("storage_read_only = {}".format(container))
    return container


def email_notification(account, region, cluster, service, taskDefinition, volumes=None, storage=None):
    print("Sending email alert")
    SENDER = "AWS ECS Compliance Scanner <aws-ecs-alerts@capgroup.com>"
    RECIPIENT = "aws-ecs-alerts <aws-ecs-alerts@capgroup.com>"
    Details = None
    Subject = None
    if volumes:
        SUBJECT = "Testing Mode - AWS ECS Fargate Volume Scan Alert"
        Details = volumes
        print("Volume data = {}".format(Details))
    if storage:
        SUBJECT = "Testing Mode - AWS ECS Fargate Storage Scan Alert"
        Details = storage
        print("Storage data = {}".format(Details))
    
    try:
        Details=str(Details)
        Details = Details.replace('[','')
        Details = Details.replace('[','')
        Details = Details.replace(']','')
        Details = Details.replace('{','')
        Details = Details.replace('}','')
        Details = Details.replace('\'','')
        
        CONTENT = ('<html> <body>' +
        '<h1>' + SUBJECT + '</h1>' +
        '<p>Account = ' + account + '<p>' +
        '<p>Region = ' + region + '<p>' +
        '<p>Cluster = ' + cluster + '<p>' +
        '<p>Service = ' + service + '<p>' +
        '<p>TaskDefinition = ' + taskDefinition + '<p>' +
        '<p>Details = ' + Details + '<p>' +
        '</body> </html>'
        )
        CHARSET = "UTF-8"
    except Exception as err:
        print(err)

    try:
        send_response = client_ses.send_email(Source=SENDER,
                                            Destination={'ToAddresses': [RECIPIENT]},
                                            Message={
                                            'Subject': {
                                            'Charset': 'UTF-8',
                                            'Data': SUBJECT,
                                            },
                                            'Body': {
                                            'Html': {
                                                'Charset': 'UTF-8',
                                                'Data': CONTENT
                                                }
                                            }
                                            })
    except Exception as err:
        print(err)
    else:
        print("-----------------------------Email sent! Message ID:")


def lambda_handler(event, context):
    try:
        if (event["detail"]["eventName"] == "UpdateService" or event["detail"]["eventName"] == "CreateService") and event["source"] == "aws.ecs":
            print(json.dumps(event))
            
            account = event["account"]
            region = event["region"]
            cluster = event["detail"]["requestParameters"]["cluster"]
            service = event["detail"]["responseElements"]["service"]["serviceName"]
            taskDefinition = event["detail"]["requestParameters"]["taskDefinition"]
            
            session = assume_role(account, "OrganizationAccountAccessRole")
            global clients
            clients = {}
            clients = setup_clients(session, clients, region, 'ecs', 'ses')
            
            task = get_task_def(event["detail"]["responseElements"]["service"]["taskDefinition"])
            volumes = check_task_def_volumes(task)
            storage_read_only = check_task_file_system(task)
            
            if volumes:
                print("Volume mount found for:")
                print("Account = {} \nRegion = {} \nECS Cluster = {} \nService = {} \nTaskDefinition = {} \nVolumes = {}".format(account, region, cluster, service, taskDefinition, volumes))
                email_notification(account, region, cluster, service, taskDefinition, volumes=volumes, storage=None)
            if storage_read_only:
                print("Storage File Permissions:")
                print("Account = {} \nRegion = {} \nECS Cluster = {} \nService = {} \nTaskDefinition = {} \nStorage = {}".format(account, region, cluster, service, taskDefinition, storage_read_only))
                email_notification(account, region, cluster, service, taskDefinition, volumes=None, storage=storage_read_only)
    except Exception as e:
        pass
