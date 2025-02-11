#!/usr/bin/env python
# coding: utf-8

import boto3
import time
import hashlib
import requests
import json
import re

from botocore.exceptions import ClientError
from datetime import date, timedelta
from requests.auth import HTTPBasicAuth
from urllib.parse import urlencode
CLEANR = re.compile('<.*?>|&([a-z0-9]+|#[0-9]{1,6}|#x[0-9a-f]{1,6});')


# define a HTML cleaner function

def cleanhtml(raw_html):
    cleantext = re.sub(CLEANR, '', raw_html)
    return cleantext

# retrieve Alation data source connection string

secrets_manager_client = boto3.client('secretsmanager')
qbusiness_client = boto3.client('qbusiness')

application_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
index_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
data_source_id = "xxxxxxxx-xxxx-xxxx-xxxx-xxxxxxxxxxxx"
secret_name = "alation_test"

try:
    get_secret_value_response = secrets_manager_client.get_secret_value(
        SecretId=secret_name
    )
    secret = eval(get_secret_value_response['SecretString'])

except ClientError as e:
        raise e

# define API access URLs - be sure to change <id> with your value below
        
base_url = "https://<id>.alationcloud.com"
token_url = "/oauth/v2/token/"
introspect_url = "/oauth/v2/introspect/"
jwks_url = "/oauth/v2/.well-known/jwks.json/"

api_url = base_url + token_url
print(api_url)

# define the connection

data = {
        "grant_type": "client_credentials",
       }
client_id = secret['Client_Id']
client_secret = secret['Client_Secret']

auth = HTTPBasicAuth(username=client_id, password=client_secret)
response = requests.post(url=api_url, data=data, auth=auth)
print(response.json())

# Get access_token for later
access_token = response.json().get('access_token','')

api_url = base_url + introspect_url + "?verify_token=true"
print(api_url)
# Get access_token from previous steps
data = {
        "token": access_token,
       }

# Here we again use basic auth as set up previously

response = requests.post(url=api_url, data=data, auth=auth)
print(response.json())

#Identity users from both data sources

primary_principal_list = []
workplace_policy_principals = []
hr_policy_principals = []
regulatory_policy_principals = []

# Replace user email IDs with your use case

principal_user_email_ids = ['alejandro_rosalez@example.com', 'sofia_martinez@example.com', 'diego_martinez@example.com']
workplace_policy_email_ids = ['alejandro_rosalez@example.com', 'sofia_martinez@example.com', 'diego_ramirez@example.com']
hr_policy_email_ids = ['alejandro_rosalez@example.com', 'sofia_martinez@example.com']
regulatory_policy_email_ids = ['alejandro_rosalez@example.com', 'diego_ramirez@example.com']

for workplace_policy_member in workplace_policy_email_ids:
    workplace_policy_members_dict = { 'user': { 'id': workplace_policy_member, 'access': 'ALLOW', 'membershipType': 'DATASOURCE' }}
    workplace_policy_principals.append(workplace_policy_members_dict)
    if workplace_policy_member not in primary_principal_list:
        primary_principal_list.append(workplace_policy_member)

for hr_policy_member in hr_policy_email_ids:
    hr_policy_members_dict = { 'user': { 'id': hr_policy_member, 'access': 'ALLOW', 'membershipType': 'DATASOURCE' }}
    hr_policy_principals.append(hr_policy_members_dict)
    if hr_policy_member not in primary_principal_list:
        primary_principal_list.append(hr_policy_member)
        
for regulatory_policy_member in regulatory_policy_email_ids:
    regulatory_policy_members_dict = { 'user': { 'id': regulatory_policy_member, 'access': 'ALLOW', 'membershipType': 'DATASOURCE' }}
    regulatory_policy_principals.append(regulatory_policy_members_dict)
    if regulatory_policy_member not in primary_principal_list:
        primary_principal_list.append(regulatory_policy_member)


# Pulling workplace policy details

url = "https://<id>.alationcloud.com/integration/v1/business_policies/?limit=200&skip=0&search=Workplace&deleted=false"

headers = {
    "accept": "application/json",
    "TOKEN": access_token
}

response = requests.get(url, headers=headers)
workplace_policy_data = ""

for workplace_policy in json.loads(response.text):
    if workplace_policy["title"] is not None:
        workplace_policy_title = cleanhtml(workplace_policy["title"])
    else:
        workplace_policy_title = "None"
    if workplace_policy["description"] is not None:
        workplace_policy_description = cleanhtml(workplace_policy["description"])
    else:
        workplace_policy_description = "None"
    temp_data = workplace_policy_title + ":\n" + workplace_policy_description + "\n\n"
    workplace_policy_data += temp_data

print(workplace_policy_data)


# Pulling HR policy details


url = "https://<id>.alationcloud.com/integration/v1/business_policies/?limit=200&skip=0&search=HR&deleted=false"

headers = {
    "accept": "application/json",
    "TOKEN": access_token
}

response = requests.get(url, headers=headers)
hr_policy_data = ""

for hr_policy in json.loads(response.text):
    if hr_policy["title"] is not None:
        hr_policy_title = cleanhtml(hr_policy["title"])
    else:
        hr_policy_title = "None"
    if hr_policy["description"] is not None:
        hr_policy_description = cleanhtml(hr_policy["description"])
    else:
        hr_policy_description = "None"
    temp_data = hr_policy_title + ":\n" + hr_policy_description + "\n\n"
    hr_policy_data += temp_data

print(hr_policy_data)


# Pulling regulatory policy details


url = "https://<id>.mtse.alationcloud.com/integration/v1/business_policies/?limit=200&skip=0&search=Regulatory&deleted=false"

headers = {
    "accept": "application/json",
    "TOKEN": access_token
}

response = requests.get(url, headers=headers)
regulatory_policy_data = ""

for regulatory_policy in json.loads(response.text):
    if regulatory_policy["title"] is not None:
        regulatory_policy_title = cleanhtml(regulatory_policy["title"])
    else:
        regulatory_policy_title = "None"
    if regulatory_policy["description"] is not None:
        regulatory_policy_description = cleanhtml(regulatory_policy["description"])
    else:
        regulatory_policy_description = "None"
    temp_data = regulatory_policy_title + ":\n" + regulatory_policy_description + "\n\n"
    regulatory_policy_data += temp_data

print(regulatory_policy_data)



# Create all identified users in Q Business application

for principal in primary_principal_list:
    create_user_response = qbusiness_client.create_user(
        applicationId=application_id,
        userId=principal,
        userAliases=[
            {
                'indexId': index_id,
                'dataSourceId': data_source_id,
                'userId': principal
            },
        ],
    )
    print(create_user_response)

# Ensuring the users are added

for principal in primary_principal_list:
    get_user_response = qbusiness_client.get_user(
        applicationId=application_id,
        userId=principal
    )
    for user_alias in get_user_response['userAliases']:
        if "dataSourceId" in user_alias:
            print(user_alias['userId'])


# Start Q Business data sync for workplace policy input

try:
    start_data_source_sync_job_response = qbusiness_client.start_data_source_sync_job(
        dataSourceId = data_source_id,
        indexId = index_id,
        applicationId = application_id
    )
    job_execution_id = start_data_source_sync_job_response['executionId']
except:
    print("Exception when calling API")

# Upload workplace policy document into Q Business

try:
    workplace_policy_document_id = hashlib.shake_256(workplace_policy_data.encode('utf-8')).hexdigest(128)
    docs = [ {
        "id": workplace_policy_document_id,
        "content" : {
            'blob': workplace_policy_data.encode('utf-8')
        },
        "contentType": "PLAIN_TEXT",
        "title": "Unicorn Rentals - Workplace Policy",
        "accessConfiguration" : { 'accessControls': [ { 'principals': workplace_policy_principals } ] }   
    }    
    ]
    
    batch_put_document_response = qbusiness_client.batch_put_document(
        applicationId = application_id,
        indexId = index_id,
        dataSourceSyncId = job_execution_id,
        documents = docs,
    )
except:
    print("Exception when calling API")

# Stop Q Business data sync and wait for the upload to be indexed

try:
    stop_data_source_sync_job_response = qbusiness_client.stop_data_source_sync_job(
        dataSourceId = data_source_id,
        indexId = index_id,
        applicationId = application_id
    )
    max_time = time.time() + 1*60*60
    found = False
    while time.time() < max_time and bool(found) == False:
        list_documents_response = qbusiness_client.list_documents(
            applicationId=application_id,
            indexId=index_id
        )
        if list_documents_response:
            for document in list_documents_response["documentDetailList"]:
                if document["documentId"] == workplace_policy_document_id:
                    status = document["status"]
                    print(status)
                    if status == "INDEXED" or status == "FAILED" or status == "DOCUMENT_FAILED_TO_INDEX" or status == "UPDATED":
                        found = True        
                    else:
                        time.sleep(10)        
except:
    print("Exception when calling API")


# Start Q Business data sync for hr policy input

try:
    start_data_source_sync_job_response = qbusiness_client.start_data_source_sync_job(
        dataSourceId = data_source_id,
        indexId = index_id,
        applicationId = application_id
    )
    job_execution_id = start_data_source_sync_job_response['executionId']
except:
    print("Exception when calling API")


# Upload hr policy document into Q Business

try:
    hr_policy_document_id = hashlib.shake_256(hr_policy_data.encode('utf-8')).hexdigest(128)
    docs = [ {
        "id": hr_policy_document_id,
        "content" : {
            'blob': hr_policy_data.encode('utf-8')
        },
        "contentType": "PLAIN_TEXT",
        "title": "Unicorn Rentals - HR Policy",
        "accessConfiguration" : { 'accessControls': [ { 'principals': hr_policy_principals } ] }   
    }    
    ]
    
    batch_put_document_response = qbusiness_client.batch_put_document(
        applicationId = application_id,
        indexId = index_id,
        dataSourceSyncId = job_execution_id,
        documents = docs,
    )
except:
    print("Exception when calling API")

# Stop Q Business data sync and wait for the upload to be indexed

try:
    stop_data_source_sync_job_response = qbusiness_client.stop_data_source_sync_job(
        dataSourceId = data_source_id,
        indexId = index_id,
        applicationId = application_id
    )
    max_time = time.time() + 1*60*60
    found = False
    while time.time() < max_time and bool(found) == False:
        list_documents_response = qbusiness_client.list_documents(
            applicationId=application_id,
            indexId=index_id
        )
        for document in list_documents_response["documentDetailList"]:
            if document["documentId"] == hr_policy_document_id:
                status = document["status"]
                print(status)
                if status == "INDEXED" or status == "FAILED" or status == "DOCUMENT_FAILED_TO_INDEX" or status == "UPDATED":
                    found = True        
                else:
                    time.sleep(10)        
except:
    print("Exception when calling API")

#Start Q Business data sync for regulatory policy input

try:
    start_data_source_sync_job_response = qbusiness_client.start_data_source_sync_job(
        dataSourceId = data_source_id,
        indexId = index_id,
        applicationId = application_id
    )
    job_execution_id = start_data_source_sync_job_response['executionId']
except:
    print("Exception when calling API")

# Upload hr policy document into Q Business

regulatory_policy_document_id = hashlib.shake_256(regulatory_policy_data.encode('utf-8')).hexdigest(128)
docs = [ 
    {
        "id": regulatory_policy_document_id,
        "content" : {
            'blob': regulatory_policy_data.encode('utf-8')
        },
        "contentType": "PLAIN_TEXT",
        "title": "Unicorn Rentals - Regulatory Policy",
        "accessConfiguration" : { 'accessControls': [ { 'principals': regulatory_policy_principals } ] }  
    }    
]
    
batch_put_document_response = qbusiness_client.batch_put_document(
    applicationId = application_id,
    indexId = index_id,
    dataSourceSyncId = job_execution_id,
    documents = docs,
)

# Stop Q Business data sync and wait for the upload to be indexed

try:
    stop_data_source_sync_job_response = qbusiness_client.stop_data_source_sync_job(
        dataSourceId = data_source_id,
        indexId = index_id,
        applicationId = application_id
    )
    max_time = time.time() + 1*60*60
    found = False
    while time.time() < max_time and bool(found) == False:
        list_documents_response = qbusiness_client.list_documents(
            applicationId=application_id,
            indexId=index_id
        )
        for document in list_documents_response["documentDetailList"]:
            if document["documentId"] == regulatory_policy_document_id:
                status = document["status"]
                print(status)
                if status == "INDEXED" or status == "FAILED" or status == "DOCUMENT_FAILED_TO_INDEX" or status == "UPDATED":
                    found = True        
                else:
                    time.sleep(10)        
except:
    print("Exception when calling API")