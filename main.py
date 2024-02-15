import re
import datetime
import subprocess
import os
import platform
import psutil
import socket
from datetime import timedelta
from pymongo import MongoClient
import requests
from time import sleep
import threading
from datetime import datetime,timedelta
from pymongo import MongoClient
import boto3
from botocore.exceptions import NoCredentialsError
import pandas as pd
from prophet import Prophet
import jellyfish
from itertools import combinations
import csv
import notifications


mongo_uri = "mongodb+srv://test:test@sanenomore.mteelpf.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(mongo_uri)

aws_access_key_id = 'AKIAQXZF3HZ2SRHD5IEI'
aws_secret_access_key = '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'






all_threads = []
# run in thread
def run_in_thread(target_function):
    thread = threading.Thread(target=target_function)
    thread.daemon = True  # Daemon threads will exit when the main program finishes
    thread.start()
    all_threads.append(thread)
    return thread

hostname = ""
with open("tconf") as f:
    for l in f:
        if "hostname" in l:
            hostname = l.split("=")[-1].strip()

# ghostname = input("Enter your host name")
ghostname = hostname
#ghostname = socket.gethostname()
# print(ghostname)
db = client["log_analysis"]
# print(db)

s3 = boto3.resource("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
bucket_name = "downloadfileshis"

def upload_to_s3(local_file_path, file_name):
    try:
        s3.meta.client.upload_file(Filename=local_file_path, Bucket=bucket_name, Key=file_name)
        print(f"File '{file_name}' uploaded successfully to '{bucket_name}'.")

    except FileNotFoundError:
        print(f"The file '{local_file_path}' was not found.")

    except NoCredentialsError:
        print("AWS credentials not available or invalid. Please check your credentials.")

    except Exception as e:
        print(f"An error occurred: {str(e)}")

def read_nginx_conf_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def write_to_new_file(content, output_file):
    with open(output_file, 'w') as file:
        file.write(content)

def config_history():
    if nginx_conf_directory:
        conf_file_path = os.path.join(nginx_conf_directory, 'nginx.conf')
        if os.path.exists(conf_file_path):
            conf_content = read_nginx_conf_file(conf_file_path)
            output_file = 'new_conf_file.txt'
            write_to_new_file(conf_content, output_file)
            upload_to_s3("new_conf_file.txt",f"config_at_{datetime.utcnow().date()}.txt")
            print(f"Configuration file '{conf_file_path}' has been read and written to '{output_file}'.")
        else:
            print("Nginx configuration file not found.")
    else:
        print("Nginx configuration directory not found.")
    sleep(3600*24)

def calculate_total_stars():
    try:
        # MongoDB connection details
        total_stars_collection_name = "total_stars"
        total_stars_collection = db[total_stars_collection_name]

        # Check if there are documents in the "requests" collection
        if db.requests.count_documents({}) > 0:
            # Fetch the latest document from "requests" collection to get the number of logs per minute
            latest_logs_count_document = db.requests.find_one(sort=[("_id", -1)])
            logs_count = latest_logs_count_document.get('total_count', 0)
        else:
            logs_count = 0

        # Fetch the total number of error_logs documents in the last minute (update variable name accordingly)
        start_time = datetime.utcnow() - timedelta(minutes=1)

        # Check if there are documents in the "error_logs" collection
        if db.error_logs.count_documents({"timestamp": {"$gte": start_time}}) > 0:
            total_error_logs_last_minute = db.error_logs.count_documents({"timestamp": {"$gte": start_time}})
        else:
            total_error_logs_last_minute = 0
        # Fetch accepted_count and failed_count from the status_codes collection (update variable name accordingly)
        if db.status_codes.count_documents({}) > 0:
            status_codes_document = db.status_codes.find_one(sort=[("_id", -1)])
            accepted_count = status_codes_document.get('accepted_count', 0)
            failed_count = status_codes_document.get('failed_count', 0)
        else:
            accepted_count = 0
            failed_count = 0

        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)

        # Memory usage
        memory_info = psutil.virtual_memory()
        remaining_memory = memory_info.percent

        # Calculate stars
        star1 = abs(((total_error_logs_last_minute/(logs_count+1)) * 100) - 100)
        star2 = abs(cpu_percent - 100)
        star3 = abs(remaining_memory - 100)
        star4 = ((accepted_count+1)/(accepted_count+failed_count+1))  * 100
        star5 = ((failed_count+1)/(accepted_count+failed_count+1)) * 100

        print(star1, star2, star3, star4, star5)

        totalstars = star1 + star2 + star3 + star4 + star5

        # Push total stars to MongoDB
        total_stars_collection.insert_one({
            "timestamp": datetime.utcnow(),
            "total_stars": totalstars,
            "hostname":ghostname
        })
        print(f"total stars {totalstars}")

        return totalstars

    except Exception as e:
        print(f"Error in calculate_total_stars: {e}")

def find_nginx_conf_directory():
    default_nginx_path = "C:\\nginx"
    
    if os.path.exists(default_nginx_path):
        conf_directory = os.path.join(default_nginx_path, 'conf')
        if os.path.exists(conf_directory):
            return conf_directory
        else:
            return "Configuration directory not found within the default Nginx path."
    else:
        return "Default Nginx path not found on this system."

def read_nginx_conf_file(file_path):
    with open(file_path, 'r') as file:
        return file.read()

def write_to_new_file(content, output_file):
    with open(output_file, 'w') as file:
        file.write(content)

nginx_conf_directory = find_nginx_conf_directory()

def run_command(command):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        print("Command executed successfully.")
        print("Output:")
        print(result.stdout)
        return result.stdout
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        if e.stderr:
            print(f"Error details:\n{e.stderr}")
        return None

def generate_summary():
    try:
        # Check if there are documents in the "requests" collection
        if db.requests.count_documents({}) > 0:
            # Fetch the latest document from "requests" collection to get the number of logs per minute
            logs_count_document = db.requests.find_one(sort=[("_id", -1)])
            logs_per_minute = logs_count_document.get('total_count', 0)
        else:
            logs_per_minute = 0

        # Check if there are documents in the "status_codes" collection
        if db.status_codes.count_documents({}) > 0:
            # Fetch the latest document from "status_codes" collection to get hits and misses
            status_codes_document = db.status_codes.find_one(sort=[("_id", -1)])
            hits = status_codes_document.get('accepted_count', 0)
            misses = status_codes_document.get('failed_count', 0)
        else:
            hits = 0
            misses = 0

        # Fetch the last value of memory percentage
        memory_info = psutil.virtual_memory()
        last_memory_percent = memory_info.percent

        # Check if there are documents in the "error_logs" collection
        if db.error_logs.count_documents({}) > 0:
            # Fetch the last value of error_logs
            last_error_logs_document = db.error_logs.find_one(sort=[("_id", -1)])
            last_error_logs = last_error_logs_document.get('log_data', 'No error logs available.')
        else:
            last_error_logs = 'No error logs available.'

        # Check if there are documents in the "information_logs" collection
        if db.information_logs.count_documents({}) > 0:
            # Fetch the last value of success logs
            last_success_logs_document = db.information_logs.find_one(sort=[("_id", -1)])
            last_success_logs = last_success_logs_document.get('log_data', 'No success logs available.')
        else:
            last_success_logs = 'No success logs available.'

        # Create a summary string
        summary = (
            f"Logs per minute: {logs_per_minute}, "
            f"Hits: {hits}, Misses: {misses}, "
            f"Last Memory %: {last_memory_percent}, "
            f"Last Error Log: {last_error_logs}, "
            f"Last Success Log: {last_success_logs}"
        )

        # Push the summary to MongoDB
        summary_collection = db["summary"]
        summary_data = {
            "timestamp": datetime.utcnow(),
            "summary": summary,
            "hostname":ghostname

        }
        summary_collection.insert_one(summary_data)

        print("Summary pushed to MongoDB successfully.")

    except Exception as e:
        print(f"Error in generate_summary(): {e}")

def security_runner():
    security_cmd_and_save(['systeminfo'], 'sysinfo.txt')
    run_command(r"python .\wesng-master\wesng-master\wes.py --update")
    security_cmd_and_save(['python', '.\\wesng-master\\wesng-master\\wes.py', 'sysinfo.txt'], 'securityinfo.txt')
    security_patches('securityinfo.txt')
    security_vulnerabilities_string('securityinfo.txt')
    security_vulnerabilities_count('securityinfo.txt')
    security_os_information('securityinfo.txt')

def security_patches(file_path):
    try:
        with open(file_path, 'r') as file:
            data = file.read()
        missing_patches_count = int(re.search(r'Missing patches: (\d+)', data).group(1))
        missing_patches = re.findall(r'- (\S+): patches (\d+) vulnerabilities', data)
        required_lines = [f"{line[0]}: {line[1]}" for line in missing_patches[:missing_patches_count]]
        collection = db["missing_patches"]
        entry = {
            "Timestamp": datetime.utcnow(),
            "MissingPatches": required_lines,
            "hostname":ghostname

        }
        collection.insert_one(entry)

        print("Missing patches information inserted into MongoDB successfully.")
    except Exception as e:
        print(f"Error: {e}")

def security_vulnerabilities_string(file_path):
    try:
        with open(file_path, 'r') as file:
            data = file.read()
        vulnerabilities = re.findall(r'Date: (\d{8})\nCVE: (\S+)\nKB: (\S+)\nTitle: (.*?)\nAffected product: (.*?)\nAffected component: (.*?)\nSeverity: (.*?)\nImpact: (.*?)\nExploit: (.*?)\n', data, re.DOTALL)
        collection = db["vulnerabilities"]
        for vulnerability in vulnerabilities:
            entry = {
                "Date": vulnerability[0],
                "CVE": vulnerability[1],
                "KB": vulnerability[2],
                "Title": vulnerability[3].strip(),
                "AffectedProduct": vulnerability[4].strip(),
                "AffectedComponent": vulnerability[5].strip(),
                "Severity": vulnerability[6].strip(),
                "Impact": vulnerability[7].strip(),
                "Exploit": vulnerability[8].strip(),
                "Timestamp": datetime.utcnow(),
                "hostname":ghostname
            }
            collection.insert_one(entry)

        print("Vulnerabilities inserted into MongoDB successfully.")
    except Exception as e:
        print(f"Error: {e}")

def security_vulnerabilities_count(file_path):
    try:
        with open(file_path, 'r') as file:
            data = file.read()
        threshold_collection = db['threshold']
        threshold_data = threshold_collection.find_one()
        email_ = threshold_data.get('email', '727721eucs169@skcet.ac.in')

        # Count vulnerabilities based on severity
        severity_counts = {
            'Critical': len(re.findall(r'Severity: Critical', data)),
            'Important': len(re.findall(r'Severity: Important', data)),
            'Moderate': len(re.findall(r'Severity: Moderate', data)),
            'Low': len(re.findall(r'Severity: Low', data)),
            "hostname": ghostname
        }

        # Insert vulnerability counts into MongoDB
        vulnerabilities_count_collection = db["vulnerabilities_count_security"]
        vulnerabilities_count_collection.insert_one(severity_counts)

        # Check if vulnerability count exceeds the threshold
        vulnerabilities_count_threshold = threshold_data.get('vulnerabilities_count_threshold', 10)  # Replace with your actual threshold
        if severity_counts['Critical'] > vulnerabilities_count_threshold:
            notifications.sendemail(f"Vulnerability count ALERT FOR {ghostname}", "vulnerability count of your server has exceeded the threshold!!..", email_)
            notifications.send_sms(f"Vulnerability count ALERT FOR {ghostname}", "9443335826")
            print("Vulnerability count has exceeded the threshold!")

        print("Vulnerabilities counts inserted into MongoDB successfully.")
    
    except Exception as e:
        print(f"Error: {e}")


def security_os_information(file_path):
    try:
        with open(file_path, 'r') as file:
            data = file.read()

        lines = data.split('\n')
        os_info = {}
        parsing_os_info = False
        for line in lines:
            if line.startswith('[+] Operating System'):
                parsing_os_info = True
            elif parsing_os_info and line.startswith('    - Name:'):
                os_info['Name'] = line.split(': ')[1].strip()
            elif parsing_os_info and line.startswith('    - Generation:'):
                os_info['Generation'] = int(line.split(': ')[1].strip())
            elif parsing_os_info and line.startswith('    - Build:'):
                os_info['Build'] = int(line.split(': ')[1].strip())
            elif parsing_os_info and line.startswith('    - Version:'):
                os_info['Version'] = line.split(': ')[1].strip()
            elif parsing_os_info and line.startswith('    - Architecture:'):
                os_info['Architecture'] = line.split(': ')[1].strip()
            elif parsing_os_info and line.startswith('    - Installed hotfixes'):
                hotfixes = line.split(': ')[1].strip().split(', ')
                os_info['Installed_hotfixes'] = hotfixes

        os_info['Timestamp'] = datetime.utcnow()
        os_info["hostname"] = ghostname

        collection = db["operating_systems_info_security"]
        collection.insert_one(os_info)

        print("OS information inserted into MongoDB successfully.")
    except Exception as e:
        print(f"Error: {e}")

def security_cmd_and_save(command, output_file):
    try:
        result = subprocess.run(command, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True, check=True)
        with open(output_file, 'w') as file:
            file.write(result.stdout)
        print(f"Command executed successfully. Output written to {output_file}")
    except subprocess.CalledProcessError as e:
        print(f"Error executing command: {e}")
        if e.stderr:
            print(f"Error details:\n{e.stderr}")

def find_nginx_logs():
    possible_access_paths = [
        "C:\\Program Files\\nginx\\logs\\access.log",
        "C:\\nginx-1.24.0\\logs\\access.log",
        "C:\\nginx\\logs\\access.log",
        "C:\\nginx-1.24.0\\access.log",
        "C:\\nginx\\access.log",
        "D:\\nginx-1.24.0\\logs\\access.log",  # Add more possible paths for access log here
        # Add more possible paths as required for access log based on your installation
    ]

    possible_error_paths = [
        "C:\\Program Files\\nginx-1.24.0\\logs\\error.log",
        "C:\\nginx-1.24.0\\logs\\error.log",
        "C:\\nginx\\logs\\error.log",
        "C:\\nginx-1.24.0\\logs",
        "C:\\nginx\\logs",
        "C:\\nginx-1.24.0\\error.log",
        "C:\\nginx\\error.log",
        "D:\\nginx-1.24.0\\logs\\error.log",  # Add more possible paths for error log here
        # Add more possible paths as required for error log based on your installation
    ]

    # Finding Access Log file
    access_log = None
    for path in possible_access_paths:
        if os.path.exists(path):
            access_log = path
            break

    # Finding Error Log file
    error_log = None
    for path in possible_error_paths:
        if os.path.exists(path):
            error_log = path
            break

    return access_log, error_log  # Return found log file paths or None

# memory usage percentage
def get_cpu_usage_percentage():
    try:
        cpu_usage_table = db["cpu_usage"]
        threshold_collection = db['threshold']
        
        while True:
            cpu_percent = psutil.cpu_percent(interval=1)
            threshold_data = threshold_collection.find_one({}, sort=[('_id', -1)])
            
            # Make sure 'cpu_threshold' is defined before using it
            cpu_threshold = threshold_data.get('cpu_threshold', 80)
            
            cpu_data = {
                "timestamp": datetime.utcnow(),
                "cpu_percent": cpu_percent,
                "hostname": ghostname
            }
            cpu_usage_table.insert_one(cpu_data)
            
            email_ = threshold_data.get('email', '727721eucs169@skcet.ac.in')
            
            if cpu_data['cpu_percent'] > cpu_threshold:
                notifications.sendemail(f"CPU usage ALERT FOR {ghostname}", "CPU usage of your server has exceeded the threshold!!..", email_)
                notifications.send_sms(f"CPU usage ALERT FOR {ghostname}", "9443335826")
                print("CPU usage exceeded threshold!")
    
    except Exception as e:
        print(f"Error in get_cpu_usage_percentage: {e}")
# get cpu usage percentage
def get_cpu_usage_percentage():
    try:
        cpu_usage_table = db["cpu_usage"]
        threshold_collection = db['threshold']
        
        while True:
            cpu_percent = psutil.cpu_percent(interval=1)
            threshold_data = threshold_collection.find_one({}, sort=[('_id', -1)])
            
            # Make sure 'cpu_threshold' is defined before using it
            cpu_threshold = threshold_data.get('cpu_threshold', 80)
            
            cpu_data = {
                "timestamp": datetime.utcnow(),
                "cpu_percent": cpu_percent,
                "hostname": ghostname
            }
            cpu_usage_table.insert_one(cpu_data)
            
            email_ = threshold_data.get('email', '727721eucs169@skcet.ac.in')
            
            if cpu_data['cpu_percent'] > cpu_threshold:
                notifications.sendemail(f"CPU usage ALERT FOR {ghostname}", "CPU usage of your server has exceeded the threshold!!..", email_)
                notifications.send_sms(f"CPU usage ALERT FOR {ghostname}", "9443335826")
                print("CPU usage exceeded threshold!")
    
    except Exception as e:
        print(f"Error in get_cpu_usage_percentage: {e}")
# get virtual memory usage
def get_virtual_memory_info():
    try:
        virtual_memory_table = db["virtual_memory"]
        virtual_memory_info = psutil.virtual_memory()
        virtual_memory_data = {
            "timestamp": datetime.utcnow(),
            "virtual_memory_info": {
                "total": virtual_memory_info.total,
                "available": virtual_memory_info.available,
                "percent": virtual_memory_info.percent,
                "used": virtual_memory_info.used,
                "free": virtual_memory_info.free
            },
            "hostname":ghostname

        }
        virtual_memory_table.insert_one(virtual_memory_data)

        print("Virtual memory running and upadting 30 secs")
    except Exception as e:
        print(f"Error in get_virtual_memory_info: {e}")


# get location data of the incoming ip addresses
def push_device_ip_location(get_ip_location_api_key, ip_address, serial_number):
    try:
        response = requests.get(f"https://ipinfo.io/{ip_address}?token={get_ip_location_api_key}")
        if response.status_code == 200:
            data = response.json()
            location_data = {
                "serial_number": serial_number,
                "timestamp": datetime.utcnow(),
                "ip": data.get("ip", "N/A"),
                "city": data.get("city", "N/A"),
                "region": data.get("region", "N/A"),
                "country": data.get("country", "N/A"),
                "location": data.get("loc", "N/A"),
                "hostname":ghostname

            }
            device_location_table = db["device_location"]
            device_location_table.insert_one(location_data)
            
            print("Device IP Location Information pushed to MongoDB")
        else:
            print(f"Error: Unable to fetch location for IP {ip_address}. Status code: {response.status_code}")

    except (socket.error, requests.RequestException) as e:
        print(f"Error in push_device_ip_location: {e}")

# no of failed and successful requests
def process_status_code(status_code):
    try:
        status_code_collection = db["status_codes"]
        logs_count_collection = db["logs_count"]
        if not status_code_collection.find_one():
            status_code_collection.insert_one({"accepted_count": 0, "failed_count": 0, "last_update":datetime.utcnow(), "hostname":ghostname})
        if 200 <= status_code < 300:
            updated_values = status_code_collection.find_one()
            last_document = status_code_collection.find().sort([("_id", -1)]).limit(1)
            status_code_collection.insert_one({"accepted_count": 0, "failed_count": 0, "last_update":datetime.utcnow()})
            # status_code_collection.update_one({}, {"$inc": {"accepted_count": 1}})
        elif 400 <= status_code < 500:
            status_code_collection.update_one({}, {"$inc": {"failed_count": 1}})
            status_code_collection.update_one({}, {"$set": {"last_update": datetime.utcnow()}}, upsert=True)
        updated_values = status_code_collection.find_one()
        total_count = updated_values["accepted_count"] + updated_values["failed_count"]
        logscount = logs_count_collection.insert_one({"logs_count":total_count,"hostname":ghostname, "timestamp":datetime.utcnow()})
        print("*******Logs count: ",logscount)
        return {
            "accepted_count": updated_values["accepted_count"],
            "failed_count": updated_values["failed_count"],
            "total_count": total_count,
            "last_update": updated_values["last_update"]
        }

    except Exception as e:
        print(f"Error in process_status_code: {e}")

# Count the total number of requests all in all
def process_request():
    try:
        request_collection = db["requests"]
        if not request_collection.find_one():
            request_collection.insert_one({"total_count": 0,"last_updated": datetime.utcnow(), "hostname":ghostname})
        request_collection.update_one({}, {"$inc": {"total_count": 1}})
        request_collection.update_one({}, {"$set": {"last_update": datetime.utcnow()}}, upsert=True)
        updated_values = request_collection.find_one()

        return {
            "total_count": updated_values["total_count"],
            "last_update": updated_values["last_update"],
            "hostname":ghostname
        }

    except Exception as e:
        print(f"Error in process_request: {e}")

# unparsed full log to collection
def log_data_to_collection(log_data):
    try:
        if "error" in log_data.lower():
            logs_table = db["error_logs"]
        else:
            logs_table = db["information_logs"]

        log_entry = {
            "timestamp": datetime.utcnow(),
            "log_data": log_data,
            "hostname":ghostname
        }

        logs_table.insert_one(log_entry)

    except Exception as e:
        print(f"Error in log_data_to_collection: {e}")

def parse_ip(log_data):
    basic_data_collection = db["basic_data"]

    log_entry_pattern = re.compile(r'(\d+\.\d+\.\d+\.\d+) .* "(GET|POST|PUT|DELETE) (.+)" (\d+)', re.MULTILINE)

    match = log_entry_pattern.search(log_data)

    if match:
        ip_address, http_method, requested_path, status_code = match.groups()

        # Find the location of the IP address user
        api_key = "d4f782d596585f"
        push_device_ip_location(api_key, ip_address, 1)
            
        # Count the number of good and bad status addresses
        process_status_code(int(status_code))

        # Count the total number of requests
        process_request()

        # Classify if it is an error or information log
        log_data_to_collection(log_data)

        # Push parsed data to "basic_data" collection
        log_entry = {
            "timestamp": datetime.utcnow(),
            "ip_address": ip_address,
            "http_method": http_method,
            "requested_path": requested_path,
            "status_code": int(status_code),
            "hostname":ghostname
        }

        basic_data_collection.insert_one(log_entry)


logs_count = 0
def read_logs(path):
    print(f"NGINX log found at: {path}")
    with open(path, 'r') as f:
        f.seek(0,2)
        while True:
            log_data = f.readline()
            if log_data:
                parse_ip(log_data)
                server_url = "http://10.60.48.232:5000/log_endpoint"
                try:
                    timestamp = datetime.now().isoformat()
                    log_entry = {
                        "timestamp": timestamp,
                        "log_line": log_data.strip(),
                        "host_name": ghostname
                    }
                    
                    # response = requests.post(server_url, json=log_entry)
                except requests.RequestException as e:
                    print("Error sending log entry:", e)

def pipe():
    try:
        # Find NGINX log file paths
        nginx_access_log, nginx_error_log = find_nginx_logs()

        if nginx_error_log:
            # Execute read_logs for error log in a thread
            run_in_thread(lambda: read_logs(nginx_error_log))

        if nginx_access_log:
            # Execute read_logs for access log in a thread
            run_in_thread(lambda: read_logs(nginx_access_log))
    except Exception as e:
        print(f"Error in pipe function: {e}")

#to predict the daily active users count
def daily_users_forecast():

    #write the model and train it
    df = pd.read_csv("daily_users_forcast_data.csv")
    df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
    df.rename(columns={'timestamp': 'ds', 'usage': 'y'}, inplace=True)
    m = Prophet(interval_width=0.95, daily_seasonality=True)
    model = m.fit(df)
    future = m.make_future_dataframe(periods=100, freq='D')
    forecast = m.predict(future)

    #add to mongodb
    collection_name = "daily_users_forecast"
    if collection_name in db.list_collection_names():
        db[collection_name].drop()
    collection = db[collection_name]
    forecast['hostname'] = ghostname

    data_to_insert = forecast[['ds', 'yhat', 'hostname']].to_dict(orient='records')
    collection.insert_many(data_to_insert)


# To estimate the daily cost
def cost_estimation_forecast():
    try:
        # Write the model and train it
        df = pd.read_csv("cost_estimation_data.csv")
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df.rename(columns={'timestamp': 'ds', 'usage': 'y'}, inplace=True)
        m = Prophet(interval_width=0.95, daily_seasonality=True)
        model = m.fit(df)
        future = m.make_future_dataframe(periods=100, freq='D')
        forecast = m.predict(future)

        # Add to MongoDB
        collection_name = "cost_estimation_forecast"
        if collection_name in db.list_collection_names():
            db[collection_name].drop()
        collection = db[collection_name]
        forecast['hostname'] = ghostname

        data_to_insert = forecast[['ds', 'yhat','hostname']].to_dict(orient='records')
        collection.insert_many(data_to_insert)
        
    except Exception as e:
        print(f"Error in cost_estimation_forecast: {e}")

def logs_estimation_forecast():
    try:
        # Write the model and train it
        df = pd.read_csv("logs_estimation_data.csv")
        df['timestamp'] = pd.to_datetime(df['timestamp'], errors='coerce')
        df.rename(columns={'timestamp': 'ds', 'usage': 'y'}, inplace=True)
        m = Prophet(interval_width=0.95, daily_seasonality=True)
        model = m.fit(df)
        future = m.make_future_dataframe(periods=100, freq='D')
        forecast = m.predict(future)

        # Add to MongoDB
        collection_name = "logs_estimation_forecast"
        if collection_name in db.list_collection_names():
            db[collection_name].drop()
        collection = db[collection_name]
        forecast['hostname'] = ghostname
        data_to_insert = forecast[['ds', 'yhat','hostname']].to_dict(orient='records')
        collection.insert_many(data_to_insert)
    except Exception as e:
        print(f"Error in logs_estimation_forecast: {e}")


#find all the common parts of the error strings
def find_common_errors():
    
    csv_path = 'error_string.csv'
    strings = []

    with open(csv_path, 'r') as csvfile:
        reader = csv.reader(csvfile)
        paths = [row[0] for row in reader]

    http_methods = ["PUT", "POST", "DELETE", "PATCH", "GET", "HEAD", "OPTIONS", "CONNECT", "TRACE"]

    processed_paths = []
    for path in paths:
        for method in http_methods:
            if path.startswith(method):
                processed_paths.append(path.split('/', 1)[-1].strip())
                break  
        else:
            processed_paths.append(path)

    processed_paths = [path.split('HTTP/')[0].strip() for path in processed_paths]

    with open(csv_path, 'w', newline='') as csvfile:
        writer = csv.writer(csvfile)
        for processed_path in processed_paths:
            writer.writerow([processed_path])

    print(f"Processed paths written back to {csv_path}")

    threshold = 0.90
    similarities = {}

    for pair in combinations(processed_paths, 2):
        s1, s2 = pair
        jaro_winkler = jellyfish.jaro_winkler_similarity(s1, s2)

        if jaro_winkler > threshold:
            if s1 not in similarities:
                similarities[s1] = [s1]
            similarities[s1].append(s2)

    collection = db["common_errors"]  
    for common_prefix in set(processed_paths):  
        collection.insert_one({"common_prefix": common_prefix, "hostname":ghostname})

    print("Common prefixes inserted into MongoDB")


def get_machine_details():
    ghostname = socket.gethostname()
    try:
        machine_details_table = db["machine_details"]

        # Get machine type information
        machine_type_info = platform.machine()
        ip = socket.gethostbyname(socket.gethostname())
        os_info, architecture_info = platform.system(), platform.architecture()
        processor_name = platform.processor()
        logical_count = os.cpu_count()
        machine_detail = {
            "timestamp": datetime.utcnow(),
            "machine_type": machine_type_info,
            "ip_address": ip,
            "os": os_info,
            "architecture": architecture_info,
            "processor_name": processor_name,
            "logical_cpu_count": logical_count,
            "hostname": ghostname
        }
        machine_details_table.insert_one(machine_detail)
    except Exception as e:
        print(f"Error in get_machine_details: {e}")

def create_threshold_collection(cpu_threshold, memory_threshold, error_logs_threshold, vulnerabilities_logs_threshold,email):
    try:
        threshold_collection = db['threshold']

        threshold_data = {
            "timestamp": datetime.utcnow(),
            "cpu_threshold": cpu_threshold,
            "memory_threshold": memory_threshold,
            "error_logs_threshold": error_logs_threshold,
            "vulnerabilities_logs_threshold": vulnerabilities_logs_threshold,
            "email":email,
            "hostname":ghostname
        }
        threshold_collection.insert_one(threshold_data)
    except Exception as e:
        print(f"Error creating threshold collection: {e}")

def check_every_30_seconds():
    while True:
        try:
            get_virtual_memory_info()
            get_cpu_usage_percentage()
            get_memory_usage()
            sleep(30)

        except Exception as e:
            print(f"Error in check_every_30_seconds: {e}")

def check_every_1_minute():
    while True:
        try:
            generate_summary()
            calculate_total_stars()
            sleep(60)

        except Exception as e:
            print(f"Error in check_every_1_minute: {e}")

def check_every_1_hour():
    while True:
        security_runner()
        notifications.sendemail(f"CPU usage ALERT FOR {ghostname}", "CPU usage of your server has exceeded the threshold!!..","727721eucs169@skcet.ac.in")  # Trigger the notification function
        notifications.send_sms(f"CPU usage ALERT FOR {ghostname}","9443335826")

        sleep(3600)

def check_every_day():
    while True:
        daily_users_forecast()
        logs_estimation_forecast()
        cost_estimation_forecast()
        find_common_errors()
        sleep(3600*24)

def run_all_tests():
    try:
        create_threshold_collection(80,40,16,60,10)
        run_in_thread(pipe)
        run_in_thread(get_machine_details)
        run_in_thread(check_every_30_seconds)
        run_in_thread(check_every_1_hour)
        run_in_thread(check_every_1_minute)
        run_in_thread(config_history)

    except Exception as e:
        print(f"Error in run_all_tests: {e}")

    for t in all_threads:
        t.join()

# run_all_tests()


