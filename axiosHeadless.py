import asyncio #python async library
import traceback #error traceback
import os #os local library
import requests #http request
from datetime import datetime
from delinea.secrets.server import SecretServer, PasswordGrantAuthorizer #delinea secret server library
from msgraph_beta import graph_service_client #graph BETA service client
from msgraph_beta.generated.identity_protection.risky_users.risky_users_request_builder import RiskyUsersRequestBuilder #graph BETA identity protection
from msgraph.generated.models.message import Message #all part of building an email message in EXO
from msgraph.generated.models.recipient import Recipient
from msgraph.generated.models.email_address import EmailAddress
from msgraph.generated.models.item_body import ItemBody
from msgraph.generated.users.item.send_mail.send_mail_post_request_body import SendMailPostRequestBody
from azure.identity.aio import CertificateCredential #azure certificate cred
from kiota_abstractions.base_request_configuration import RequestConfiguration #query builder

def ssToken():
    site = 'https://secretserver.com/' #Secret server site

    username = 'username' #username of api account
    password = os.environ['env variable'] #environment variable that store api account password

    auth = PasswordGrantAuthorizer(site, username, password) #get secret server access token

    ss_client = SecretServer(base_url=site, authorizer=auth) #instantiate secret server instance

    try:
        secret = ss_client.get_secret(####) #get secret
        return secret
    except Exception as e:
        exit()

def authenticate():
    scopes = ['https://graph.microsoft.com/.default'] #graph scope
    tenant_id = "id" #azure tenant id
    client_id = "id" #azure app client id
    cert_path = 'c:\path\to\cert'
    phrase = ssToken()
    passPhrase = phrase['items'][2]['itemValue'] #store secret into variable

    try:
        credential = CertificateCredential (
            tenant_id=tenant_id,
            client_id=client_id,
            certificate_path=cert_path,
            password=passPhrase
        )
    except ValueError as e:
        exit()

    return credential, scopes

async def emailAlert(graph, body):
    graph_client = graph #import graph client from main()

    email_body = ItemBody(content=body, content_type="Text") #import message from main() as body
    recipient = Recipient(email_address=EmailAddress(address='email1'))
    recipient2 = Recipient(email_address=EmailAddress(address='email2'))

    message = Message(
        subject='Risky User Information',
        body=email_body,
        to_recipients=[recipient, recipient2]
    )

    request_body = SendMailPostRequestBody(message=message, save_to_sent_items=True)

    await graph_client.users.by_user_id('sender email').send_mail.post(request_body)

async def risky_users(graph_client, today):
    query = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters (
        filter=f"riskState eq microsoft.graph.riskState'atRisk' and riskLastUpdatedDateTime ge {str(today)}", #make sure user risk not cleared and last update today
        orderby=["riskLastUpdatedDateTime desc"],
        top=1
    )
    request_conf = RequestConfiguration (query_parameters=query)
    risk = await graph_client.identity_protection.risky_users.get(request_configuration=request_conf)

    return risk.value

async def risky_detections(user, graph_client):
    query = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters (filter=f"userId eq '{user.id}'", top=3) #pull detections for specific user
    request_conf = RequestConfiguration (query_parameters=query)
    risk_events = await graph_client.identity_protection.risk_detections.get(request_configuration=request_conf)

    return risk_events.value

async def risky_logins(user, graph_client, today):
    query = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters (filter=f"userID eq '{user.id}' and createdDateTime ge {today}", top=3, #pull sign ins for specific user
                                                                                 select=['userAgent', 'appDisplayName', 'createdDateTime']) #grab user agent, app name, log timestamp
    request_conf = RequestConfiguration (query_parameters=query)
    login_events = await graph_client.audit_logs.sign_ins.get(request_configuration=request_conf)

    return login_events.value

def ipCheck(ip):
    api_key = os.environ['abuseAPI'] #abuse ipdb api key
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': ip}
    resp = requests.get(url, headers=headers, params=params)

    return resp.json()

async def main():
    message = ''
    try:
        today = datetime.now().date()
        cred, scope = authenticate()
        graph_client = graph_service_client.GraphServiceClient(credentials=cred, scopes=scope) #initialize graph client

        risky_user = await risky_users(graph_client=graph_client, today=today)
    
        for user in risky_user:
            message += f"User Principal Name: {user.user_principal_name}\n"
            message += f"Risk Level: {user.risk_level}\n" 
            message += f"Risk State: {user.risk_state}\n"

            risky_events, risky_signin = await asyncio.gather( #run detections and sign-ins simultaneously
                risky_detections(user=user, graph_client=graph_client),
                risky_logins(user=user, graph_client=graph_client, today=today)
            )

            for detection in risky_events:
                ipAddr = getattr(detection, 'ip_address', 'N/A') #get ip address
                ipConf = ipCheck(ipAddr)
                keys_get = ['abuseConfidenceScore','countryCode','ip','domain','totalReports','lastReportedAt'] #what to pull out of abuse ipdb response
                aCS, cc, iSP, domain, tRep, lastRep = [(ipConf['data']).get(key) for key in keys_get]
                message += f"Risk Event: {detection.risk_event_type} at {detection.detected_date_time}\n" 
                message += f"IP: {ipAddr}. Here is the Abuse IPDB Report on it:\n" 
                message += f"Abuse Confidence Score: {aCS}\n" 
                message += f"Country Code: {cc}\n" 
                message += f"ISP: {iSP}\n" 
                message += f"Domain: {domain}\n" 
                message += f"Total Reports: {tRep}\n" 
                message += f"Last Reported at: {lastRep}\n"
        
            for log in risky_signin:
                message += f"Sign-in: {log.app_display_name} at {log.created_date_time}\n"
                if log.user_agent == 'axios': #the bad one
                    message += f"WARNING: Axios user agent detected! Please run the Phishing Playbook to remediate user {user.user_principal_name}\n"
                else:
                    message += f"User Agent: {log.user_agent}\n"
    except Exception as e:
        traceback.print_exc()

    email = asyncio.create_task(emailAlert(graph_client, message))
    await email

if __name__ == "__main__":
    asyncio.run(main())
