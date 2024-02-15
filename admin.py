import ctypes
import socket
import subprocess
import sys
import threading
import os
import pymongo
import main as main
import db

mongo_uri = "mongodb+srv://test:test@sanenomore.mteelpf.mongodb.net/?retryWrites=true&w=majority"
client = pymongo.MongoClient(mongo_uri)

ghostname = socket.gethostname()
# print(ghostname)

all_threads_admin = []
def run_in_thread(target_function):
    thread = threading.Thread(target=target_function)
    # thread.daemon = True  # Daemon threads will exit when the main program finishes
    thread.start()
    all_threads_admin.append(thread)


def telegraf():
    command = '.\\telegraf.exe --config tconf --debug'

    import os
    try:
        os.system(command)
        # result = subprocess.run(command, shell=True, check=True, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    except subprocess.CalledProcessError as e:
        print("Error executing the command:", e)
        print("Command output:\n", e.stdout)
        print("Command error output:\n", e.stderr)


def is_mysql_installed():
    try:
        result = subprocess.run(['mysql', '--version'], capture_output=True, text=True)
        output = result.stdout.lower()
        return 'mysql' in output
    except FileNotFoundError:
        return False
    
def is_nginx_installed():
    # Common installation directories for Nginx on Windows
    nginx_paths = [
        "C:\\nginx",  # Change this to your Nginx installation directory if different
        "C:\\Program Files\\nginx",
        "C:\\Program Files (x86)\\nginx",
        "C:\\nginx-1.24.0",
        # Add more paths if you have a custom installation location
    ]
    nginx_executable = "nginx.exe"
    # print("nginx")
    # Check if the Nginx executable exists in any of the specified directories
    for path in nginx_paths:
        nginx_path = os.path.join(path, nginx_executable)
        if os.path.exists(nginx_path):
            return True
    return False

def is_postgres_installed():
    try:
        result = subprocess.run(['psql', '--version'], capture_output=True, text=True)
        output = result.stdout.lower()
        return 'postgres' in output
    except FileNotFoundError:
        return False

# mysql_flag = False
# nginx_flag = False

def do_admin_tasks():

    run_in_thread(telegraf)
    if is_mysql_installed() and is_nginx_installed():
        print("running!!!...")
        run_in_thread(main.run_all_tests)
        run_in_thread(db.run_all_tests)
    elif is_mysql_installed():
        db.run_all_tests()
    elif is_nginx_installed():
        main.run_all_tests()
    
def run_as_admin():
    print("Run as admin running...")
    if ctypes.windll.shell32.IsUserAnAdmin() == 0:
        ctypes.windll.shell32.ShellExecuteW(None, "runas", sys.executable, " ".join(sys.argv), None, 1)
    else:

        # After getting admin permissions, perform tasks
        do_admin_tasks()

    for i in all_threads_admin:
            i.join()

# Main code execution starts here
#run_as_admin()
#for i in all_threads_admin:
#    i.join()