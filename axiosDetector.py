import asyncio #python async library
import traceback #error traceback
import os #os local library
import requests #http request
from datetime import datetime
from delinea.secrets.server import SecretServer, PasswordGrantAuthorizer #delinea secret server library
from msgraph_beta import graph_service_client #graph BETA service client
from msgraph_beta.generated.identity_protection.risky_users.risky_users_request_builder import RiskyUsersRequestBuilder #graph BETA identity protection
from azure.identity.aio import CertificateCredential #azure certificate cred
from kiota_abstractions.base_request_configuration import RequestConfiguration #query builder

def ssToken():
    print("Executing ssToken function!")
    print()
    site = 'https://secretserver/SecretServer' #Secret server site

    username = 'username' #username of api account
    password = os.environ['env variable'] #environment variable that store api account password

    auth = PasswordGrantAuthorizer(site, username, password) #get secret server access token

    ss_client = SecretServer(base_url=site, authorizer=auth) #instantiate secret server instance

    try:
        secret = ss_client.get_secret(number) #get secret #
        print("Secret acquired.")
        return secret
    except Exception as e:
        print(f"An error occurred: {e}")

def authenticate():
    print("Executing graph authentication function")
    print()
    scopes = ['https://graph.microsoft.com/.default'] #graph scope
    tenant_id = "tenant id" #azure tenant id
    client_id = "app id" #azure app client id
    cert_path = 'path/to/cert'
    phrase = ssToken()
    passPhrase = phrase['items'][2]['itemValue'] #store secret into variable
    print("Secret passphrase acquired")
    print()

    try:
        credential = CertificateCredential (
            tenant_id=tenant_id,
            client_id=client_id,
            certificate_path=cert_path,
            password=passPhrase
        )
    except ValueError as e:
        print(f"Error making cert credential: {e}")
        exit()

    return credential, scopes

async def risky_users(graph_client, today):
    query = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters (
        filter=f"riskState eq microsoft.graph.riskState'atRisk' and riskLastUpdatedDateTime ge {str(today)}", #make sure user risk not cleared and last update today
        orderby=["riskLastUpdatedDateTime desc"],
        top=10
    )
    request_conf = RequestConfiguration (query_parameters=query)
    risk = await graph_client.identity_protection.risky_users.get(request_configuration=request_conf)

    return risk.value

async def risky_detections(user, graph_client):
    query = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters (filter=f"userId eq '{user.id}'", top=5) #pull detections for specific user
    request_conf = RequestConfiguration (query_parameters=query)
    risk_events = await graph_client.identity_protection.risk_detections.get(request_configuration=request_conf)

    return risk_events.value

async def risky_logins(user, graph_client, today):
    query = RiskyUsersRequestBuilder.RiskyUsersRequestBuilderGetQueryParameters (filter=f"userID eq '{user.id}' and createdDateTime ge {today}", top=5, #pull sign ins for specific user
                                                                                 select=['userAgent', 'appDisplayName', 'createdDateTime']) #grab user agent, app name, log timestamp
    request_conf = RequestConfiguration (query_parameters=query)
    login_events = await graph_client.audit_logs.sign_ins.get(request_configuration=request_conf)

    return login_events.value

def ipCheck(ip):
    print()
    api_key = os.environ['env variable'] #abuse ipdb api key
    url = 'https://api.abuseipdb.com/api/v2/check'
    headers = {'Accept': 'application/json', 'Key': api_key}
    params = {'ipAddress': ip}
    resp = requests.get(url, headers=headers, params=params)

    return resp.json()

async def main():
    try:
        today = datetime.now().date()
        print(f"Date set to {today}")
        print()
        cred, scope = authenticate()
        print("Authentication complete.")
        print()
        graph_client = graph_service_client.GraphServiceClient(credentials=cred, scopes=scope) #initialize graph client
        print("Graph client created")
        print()

        risky_user = await risky_users(graph_client=graph_client, today=today)
        
        if not risky_user:
            print("No risky users found - check your filter or permissions")
            print()
            input("Press enter to quit...")
            return
    
        for user in risky_user:
            print("-" * 20)
            print(f"User Principal Name: {user.user_principal_name}")
            print(f"Risk Level: {user.risk_level}")
            print(f"Risk State: {user.risk_state}")

            risky_events, risky_signin = await asyncio.gather( #run detections and sign-ins simultaneously
                risky_detections(user=user, graph_client=graph_client),
                risky_logins(user=user, graph_client=graph_client, today=today)
            )

            prtEvent = input("Would you like to see the risk detections? ")
            if prtEvent == 'Yes' or prtEvent == 'yes':
                for detection in risky_events:
                    ipAddr = getattr(detection, 'ip_address', 'N/A') #get ip address
                    ipConf = ipCheck(ipAddr)
                    keys_get = ['abuseConfidenceScore','countryCode','ip','domain','totalReports','lastReportedAt'] #what to pull out of abuse ipdb response
                    aCS, cc, iSP, domain, tRep, lastRep = [(ipConf['data']).get(key) for key in keys_get]
                    print(f"Risk Event: {detection.risk_event_type} at {detection.detected_date_time}")
                    print(f"""IP: {ipAddr}. Here is the Abuse IPDB Report on it:
                           Abuse Confidence Score: {aCS}
                           Country Code: {cc}
                           ISP: {iSP}
                           Domain: {domain}
                           Total Reports: {tRep}
                           Last Reported at: {lastRep}""")
        
            prtLogin = input("Would you like to see sign-in events? ")
            if prtLogin == 'Yes' or prtLogin == 'yes':
                for log in risky_signin:
                    print(f"Sign-in: {log.app_display_name} at {log.created_date_time}")
                    if log.user_agent == 'axios': #the bad one
                        print(f"WARNING: Axios user agent detected! Please run the Phishing Playbook to remediate user {user.user_principal_name}")
                    else:
                        print(f"User Agent: {log.user_agent}")
    except Exception as e:
        print(f"Error: {e}")
        traceback.print_exc()
        input("Press enter to exit...")

if __name__ == "__main__":
    asyncio.run(main())

    input("Press enter to exit...")
