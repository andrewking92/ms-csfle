import boto3
import sys
from botocore.exceptions import ClientError

def getAWSToken():
 try:
   sts_client = boto3.client('sts')
   # Call the assume_role method of the STSConnection object and pass the role
   # ARN and a role session name.
   assumed_role_object=sts_client.assume_role(
       RoleArn="",
       RoleSessionName="applicationSession",
       DurationSeconds=3600
   )
   return assumed_role_object['Credentials']
 except ClientError as e:
   print(e)
   sys.exit(1)

def main():
  token = getAWSToken()
