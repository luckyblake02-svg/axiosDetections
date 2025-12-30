import win32com.client #hook in to outlook
import time
import axiosHeadless #script to be executed

def check_email():
    try:
        outlook = win32com.client.Dispatch("Outlook.Application").GetNameSpace("MAPI") #instantiate outlook instance
        inbox = outlook.GetDefaultFolder(6) #set default folder to index 6 (inbox default)
        messages = inbox.Items 

        for message in messages:
            if message.UnRead:
                if message.Subject == "User at risk detected" and message.SenderName == "azure-noreply@microsoft.com": #azure risky users
                    axiosHeadless #execute headless script

    except Exception:
        exit()

while True:
    check_email()
    time.sleep(600) #10 minute intervals
