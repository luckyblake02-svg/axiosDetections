import win32com.client #hook in to outlook
import time
import axiosHeadless #script to be executed
import asyncio

def check_email():
    try:
        outlook = win32com.client.Dispatch("Outlook.Application").GetNameSpace("MAPI") #instantiate outlook instance
        print("Outlook initialized!\n")
        inbox = outlook.GetDefaultFolder(6) #set default folder to index 6 (inbox default)
        messages = inbox.Items 

        u = 1
        for message in messages:
            print(f"Reading message #{u}")
            if message.UnRead:
                if message.Subject == "User at risk detected" and message.SenderName == "Microsoft Azure": #azure risky users
                    print("Matched Risky User email! Running Headless script")
                    await axiosHeadless.main()
            u += 1
            
    except Exception:
        exit()

while True:
    asyncio.run(check_email())
    time.sleep(600) #10 minute intervals
