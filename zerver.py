import argparse
from pymongo import MongoClient
from datetime import datetime 
from admin import run_as_admin



parser = argparse.ArgumentParser(
                    prog='Zerver',
                    description='Config Zerver',
                    epilog='End Zerver')


parser.add_argument('command', choices = ['start', 'stop', 'setup','show'])
args = parser.parse_args()

def start():
    print(""""
███████╗███████╗██████╗░██╗░░░██╗███████╗██████╗░
╚════██║██╔════╝██╔══██╗██║░░░██║██╔════╝██╔══██╗
░░███╔═╝█████╗░░██████╔╝╚██╗░██╔╝█████╗░░██████╔╝
██╔══╝░░██╔══╝░░██╔══██╗░╚████╔╝░██╔══╝░░██╔══██╗
███████╗███████╗██║░░██║░░╚██╔╝░░███████╗██║░░██║
╚══════╝╚══════╝╚═╝░░╚═╝░░░╚═╝░░░╚══════╝╚═╝░░╚═╝""")

    print("""
    
█▄█ █▀█ █░█ █▀█   █▀ ▀█▀ ▄▀█ ▀█▀ █▀▀   █▀█ █▀▀   ▀█▀ █░█ █▀▀   ▄▀█ █▀█ ▀█▀   █▀ █▀▀ █▀█ █░█ █▀▀ █▀█
░█░ █▄█ █▄█ █▀▄   ▄█ ░█░ █▀█ ░█░ ██▄   █▄█ █▀░   ░█░ █▀█ ██▄   █▀█ █▀▄ ░█░   ▄█ ██▄ █▀▄ ▀▄▀ ██▄ █▀▄

█░░ █▀█ █▀▀ █▀▀ █ █▄░█ █▀▀   █▀ █▄█ █▀ ▀█▀ █▀▀ █▀▄▀█   █ █▀   ░░█ █░█ █▀ ▀█▀   ▄▀█   █▀▀ █░░ █ █▀▀ █▄▀
█▄▄ █▄█ █▄█ █▄█ █ █░▀█ █▄█   ▄█ ░█░ ▄█ ░█░ ██▄ █░▀░█   █ ▄█   █▄█ █▄█ ▄█ ░█░   █▀█   █▄▄ █▄▄ █ █▄▄ █░█

▄▀█ █░█░█ ▄▀█ █▄█ ░ ░ ░
█▀█ ▀▄▀▄▀ █▀█ ░█░ ▄ ▄ ▄
    """)
    run_as_admin()



        
        
tconf_string ="""
[agent]
hostname = "{hostname}"
[[outputs.mongodb]]
dsn = "mongodb+srv://test:test@sanenomore.mteelpf.mongodb.net/?retryWrites=true&w=majority"
database = "servers"
[[inputs.nginx]]
[[inputs.system]]
[[inputs.mem]]
[[inputs.cpu]]
"""


def setup():

    hostname = input("Enter your server's hostname:")
    mongo_client = MongoClient("mongodb+srv://test:test@sanenomore.mteelpf.mongodb.net/")
    
    db = mongo_client["servers"]
    collection = db["server_list"] 

    existing_document = collection.find_one({"hostname": hostname})
    
    if existing_document:
        print(f"Error: Hostname '{hostname}' already exists. Please try again")
        setup()
    else:
        new_document = {
            "hostname": hostname,
            "timestamp": datetime.now()
        }
        result = collection.insert_one(new_document)
        print(f"Hostname '{hostname}' added successfully")
        with open("tconf","w") as f:
            f.write(tconf_string .format(hostname = hostname))

def stop():
    print("stop")

def show():
    mongo_client = MongoClient("mongodb+srv://test:test@sanenomore.mteelpf.mongodb.net/")
    db = mongo_client["servers"]
    collection = db["server_list"] 
    documents = collection.find()
    for document in documents:
        print(document)




if args.command == "start":
    start()

if args.command == "stop":
    stop()

if args.command == "setup":
    setup()

if args.command == "show":
    show()


