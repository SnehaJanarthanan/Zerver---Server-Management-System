import csv
import datetime
import os
import platform
import socket
import subprocess
import psutil
from datetime import timedelta
from datetime import datetime
from pymongo import MongoClient
from time import sleep
import threading
import mysql.connector
import re
import random
import os
import pymongo
import jellyfish
from itertools import combinations
import pandas as pd
from prophet import Prophet
import notifications
import boto3
from botocore.exceptions import NoCredentialsError

aws_access_key_id = 'AKIAQXZF3HZ2TNZ7JFPW'
aws_secret_access_key = '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'

s3 = boto3.resource("s3", aws_access_key_id=aws_access_key_id, aws_secret_access_key=aws_secret_access_key)
bucket_name = "log-saving-files"
local_directory = r"./"  # give the directory path from which u want to take files and  store in aws

ghostname = socket.gethostname()
print(ghostname)

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

class MyHandler:
    def __init__(self):
        self.last_uploaded = set()

    def check_for_new_files(self):
        current_files = set(os.listdir(local_directory))
        new_files = current_files - self.last_uploaded

        for file_name in new_files:
            file_path = os.path.join(local_directory, file_name)
            print(f"New file found: {file_name}")
            upload_to_s3(file_path, file_name)

        self.last_uploaded = current_files


config = {
    'user': 'root',
    'password': 'tiger',
    'host': '127.0.0.1',  # or your MySQL server IP
    'database': 'spring',
}

mongo_uri = "mongodb+srv://test:test@sanenomore.mteelpf.mongodb.net/?retryWrites=true&w=majority"
client = MongoClient(mongo_uri)


db = client["log_analysis"]

all_threads = []
# run in thread
def run_in_thread(target_function):
    thread = threading.Thread(target=target_function)
    thread.daemon = True  # Daemon threads will exit when the main program finishes
    thread.start()
    # thread.join()
    all_threads.append(thread)
    return thread


# create threshold collection
def create_threshold_collection(cpu_threshold, memory_threshold, error_logs_threshold, vulnerabilities_logs_threshold,email):
    try:
        threshold_collection = db["threshold"]
        notifications_collection = db["notifications"]
        threshold_data = {
            "timestamp": datetime.utcnow(),
            "cpu_threshold": cpu_threshold,
            "memory_threshold": memory_threshold,
            "error_logs_threshold": error_logs_threshold,
            "vulnerabilities_logs_threshold": vulnerabilities_logs_threshold,
            "email":email,
            "last_updated": datetime.utcnow(),
            "hostname":ghostname
        }
        threshold_collection.insert_one(threshold_data)
        print(threshold_data)
    
    except Exception as e:
        print(f"Error creating threshold collection: {e}")



# Count the total number of requests all in all
def process_request():
    try:
        request_collection = db["requests"]
        if not request_collection.find_one():
            request_collection.insert_one({"total_count": 0, "hostname":ghostname})
        request_collection.update_one({}, {"$inc": {"total_count": 1},"hostname":ghostname })
        request_collection.update_one({}, {"$set": {"last_update": datetime.utcnow()}}, upsert=True)
        updated_values = request_collection.find_one()

        return {
            "total_count": updated_values["total_count"],
            "last_update": updated_values["last_update"]
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

def calculate_total_stars():
    try:
        # MongoDB connection details
        total_stars_collection_name = "total_stars"
        total_stars_collection = db[total_stars_collection_name]

        # Fetch the latest document from "log_level_count" collection (update variable name accordingly)
        collection = db["log_level_count"]
        document = collection.find_one({})
        if document:
            system_count = document.get("system_count")
            logs_count = document.get("total_count")
            total_warning_logs_last_minute = document.get("warning_count")
        else:
            logs_count = 100
            total_warning_logs_last_minute = 10
        
        print(logs_count)

        # CPU usage
        cpu_percent = psutil.cpu_percent(interval=1)

        # Memory usage
        memory_info = psutil.virtual_memory()
        remaining_memory = memory_info.percent

        # Calculate stars
        star1 = abs(((total_warning_logs_last_minute / logs_count) * 100) - 100)
        star2 = abs(cpu_percent - 100)
        star3 = abs(remaining_memory - 100)

        # Calculate total stars
        totalstars = star1 + star2 + star3 + 200  # Assuming star4 and star5 were not defined

        # Print individual stars for debugging
        print(star1, star2, star3)

        # Push total stars to MongoDB
        total_stars_collection.insert_one({
            "timestamp": datetime.utcnow(),
            "total_stars": totalstars,
            "hostname":ghostname
        })

        return totalstars

    except Exception as e:
        raise e
        print(f"Error in calculate_total_stars: {e}")


# summary
def generate_summary():
    try:

        total_stars_collection_name = "total_stars"
        collection = db[total_stars_collection_name]
        count_collection = db["log_level_count"]

        # Fetch the latest document from "log_level_count" collection (update variable name accordingly)
        document = count_collection.find_one({})
        star_document = collection.find_one({})
        stars = star_document.get("total_stars")

        if stars > 50:
            star_grade = "Healthy"
        else:
            star_grade = "Poor"

        if document:
            hits = document.get("system_count")
            logs_count = document.get("total_count")
            misses = document.get("warning_count")
        else:
            logs_count = 100
            misses = 10
            hits = 90
        
        print(logs_count)

        logs_per_minute = logs_count/30
        
        # Fetch the last value of memory percentage
        memory_info = psutil.virtual_memory()
        last_memory_percent = memory_info.percent

        perf = calculate_total_stars()
        if perf < 300:
            performance = f"Performing Average, {perf}"
        else:
            performance = f"Performing Good, {perf}"

        # Create a summary string
        summary = (
            f"Logs per minute: {logs_per_minute}, "
            f"Hits: {hits}, Misses: {misses}, "
            f"Last Memory %: {last_memory_percent},"
            f"Performance : {performance}, "
            f"Health of server : {star_grade}"
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

system_count = 0;
warning_count = 0;

# send to db
def send_to_mongodb(log_parts):
    global system_count, warning_count
    collection = db["dbLogs"]
    # print(collection)
    log_level_count = db["log_level_count"]
    # print(log_level_count)

    log_data = {
        "timestamp": log_parts[0],
        "id_number": log_parts[1],
        "system": log_parts[2],
        "message_type": log_parts[3],
        "log_message": log_parts[4]
    }

    log_type = log_parts[2]
    if log_type == 'System':
        system_count += 1
    elif log_type == 'Warning':
        warning_count += 1

    count_data = {
        "warning_count":warning_count,
        "system_count":system_count,
        "total_count":warning_count+system_count,
        "hostname":ghostname
    }

    try:
        result = collection.insert_one(log_data)
        log_level_count.update_one({}, {'$set': count_data}, upsert=True)
        print(f"Log data inserted. Inserted ID: {result.inserted_id}")
    except pymongo.errors.PyMongoError as e:
        print(f"Error inserting log data: {e}")

# calculate log level
def calculate_log_level():
    try:
        log_level_count = db["log_level_count"]
        log_level_count.update_many({}, {'$set': {"entries": 0}})
        log_level_count.update_one({'name': 'System'}, {'$set': {"entries": system_count}})
        log_level_count.update_one({'name': 'Warning'}, {'$set': {"entries": warning_count}})
        print("Log level count updated")

    except Exception as e:
        print(f"Error in calculate_log_level: {e}")

# get database log path
def get_db_log_path():
    try:
        connection = mysql.connector.connect(**config)
        if connection.is_connected():
            print('Connected to MySQL database')
            cursor = connection.cursor()
        # Fetch MySQL logs
        cursor.execute('SHOW VARIABLES LIKE "log_output";')
        log_output = cursor.fetchone()
        if log_output[1].lower() == 'file':
            cursor.execute('SHOW VARIABLES LIKE "log_error";')
            log_error = cursor.fetchone()
            
            # Assuming the log file path is obtained correctly
            log_file_path = os.path.join('C:\\', 'ProgramData', 'MySQL', 'MySQL Server 8.0', 'Data', log_error[1].lstrip('.\\'))
            return log_file_path
    
    except mysql.connector.Error as err:
        print(f"Error: {err}")

# run command
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


# run command and save
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


# pen testing
def security_runner():
    print("security")
    security_cmd_and_save(['systeminfo'], 'sysinfo.txt')
    print("security2")
    run_command(r"python .\wesng-master\wesng-master\wes.py --update")
    print("security3")
    security_cmd_and_save(['python', '.\\wesng-master\\wesng-master\\wes.py', 'sysinfo.txt'], 'securityinfo.txt')
    print("security4")
    security_patches('securityinfo.txt')
    print("security5")
    security_vulnerabilities_string('securityinfo.txt')
    print("security6")
    security_vulnerabilities_count('securityinfo.txt')
    print("security7")
    security_os_information('securityinfo.txt')
    print("security8")

# patch files
def security_patches(file_path):
    try:
        print("patches")
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

# vulnerabiliites 
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

#vulnerability count
def security_vulnerabilities_count(file_path):
    try:
        with open(file_path, 'r') as file:
            data = file.read()
        
        # Counting vulnerabilities based on severity
        severity_counts = {
            'Critical': len(re.findall(r'Severity: Critical', data)),
            'Important': len(re.findall(r'Severity: Important', data)),
            'Moderate': len(re.findall(r'Severity: Moderate', data)),
            'Low': len(re.findall(r'Severity: Low', data)),
            "hostname":ghostname
        }

        collection = db["vulnerabilities_count_security"]
        collection.insert_one(severity_counts)
        print("Vulnerabilities counts inserted into MongoDB successfully.")

        # Retrieve threshold value from the threshold collection
        threshold_collection = db['threshold']
        threshold_data = threshold_collection.find_one({}, {'vulnerabilities_logs_threshold': 1})
        if threshold_data:
            critical_threshold = threshold_data.get('vulnerabilities_logs_threshold', 10)  # Set a default threshold if not found

            # Checking if critical count exceeds the threshold
            if severity_counts['Critical'] > critical_threshold:
                notifications.sendemail("Critical Vulnerability Alert", f"Critical vulnerabilities count exceeded the threshold in {ghostname}!",threshold_data.get('email'))
                notifications.notify_dashboard(mysql_code,f"Critical Vulnerability Alert for {mysql_code}. Critical vulnerabilities count exceeded the threshold in {mysql_code}!!..","red")
                
                print("Critical vulnerabilities count exceeded the threshold! Email sent.")
    except Exception as e:
        print(f"Error: {e}")

# os security
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

# Function to parse log entry and write to CSV
def parse_log_entry(entry):
    regex_pattern = r'^(\d{4}-\d{2}-\d{2}T\d{2}:\d{2}:\d{2}\.\d+Z)\s(\d+)\s\[(\w+)\]\s(\[.*?\])\s(.*)$'
    match = re.match(regex_pattern, entry)
    if match:
        timestamp = match.group(1)
        id_number = match.group(2)
        system = match.group(3)
        message_type = match.group(4)
        log_message = match.group(5)

        return timestamp, id_number, system, message_type, log_message
    else:
        return

# pipe - read db logs
def pipe():
    try:
        file_path = get_db_log_path()
        new_file_path = 'db_log_file.txt'
        with open(file_path, 'r') as f, open(new_file_path, 'a') as f_write:

            while True:
                log_data = f.readline()
                if log_data:
                    # parse_log_entry(log_data)
                    send_to_mongodb(parse_log_entry(log_data))
                    f_write.write(log_data)

    except Exception as e:
        print(f"Error in pipe: {e}")

# crash
def calculate_crash_frequency():
    # Dictionary to store crash timestamps
    crash_times = []
    
    # Read the CSV file
    with open(os.path.join(os.path.dirname(__file__),"mysql_logs.csv"), 'r') as file:
        reader = csv.reader(file)
        next(reader)  # Skip header if exists
        
        # Parse each row and extract crash timestamps
        for row in reader:
            timestamp = datetime.strptime(row[0], '%Y-%m-%dT%H:%M:%S.%fZ')
            description = row[3]
            
            # Check for crash event
            if '[MY-010232]' in description:  # Assuming this code represents a crash event
                crash_times.append(timestamp)
    
    # Calculate time differences between consecutive crashes
    time_diffs = []
    for i in range(1, len(crash_times)):
        time_diff = (crash_times[i] - crash_times[i-1]).total_seconds()
        time_diffs.append(time_diff)
    
    # Calculate the trend of crash occurrences
    if len(time_diffs) > 0:
        avg_time_between_crashes = sum(time_diffs) / len(time_diffs)
        trend = 1 / avg_time_between_crashes
    else:
        trend = 0
    
    crash_collection = db["crash_details"]
    crash_data = {
        "crash_count": len(crash_times),
        "crash_trend": trend,
        "last_updated": datetime.utcnow(),
        "hostname":ghostname
    }
    crash_collection.insert_one(crash_data)

    return len(crash_times), trend

#to predict the daily active users count
def daily_users_forecast():
    # db = client["test"]
    try:
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
        data_to_insert = forecast[['ds', 'yhat']].to_dict(orient='records')
        collection.insert_many(data_to_insert)
        print("Pushed to mongo db")

    except Exception as e:
        print(f"Error in daily_users_forecast: {e}")

# To estimate the daily cost
def cost_estimation_forecast():
    # db = client["test"]
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
        data_to_insert = forecast[['ds', 'yhat']].to_dict(orient='records')
        collection.insert_many(data_to_insert)
        print("log estimation pushed")

    except Exception as e:
        print(f"Error in cost_estimation_forecast: {e}")

# log estimation
def logs_estimation_forecast():
    # db = client["test"]
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
        data_to_insert = forecast[['ds', 'yhat']].to_dict(orient='records')
        collection.insert_many(data_to_insert)
        print("Log estimation pushed to db")

    except Exception as e:
        print(f"Error in logs_estimation_forecast: {e}")

# find all the common parts of the error strings
def find_common_errors():
    # db = client["test"]
    try:
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

    except Exception as e:
        print(f"Error in find_common_errors: {e}")

def upload_to_s3_eod():
    event_handler = MyHandler()

    try:
        # while True:
        event_handler.check_for_new_files()
            # sleep(3600)
    except KeyboardInterrupt:
        print("Script interrupted.")


# check every 1 minute
def check_every_1_minute():
    while True:
        try:
            calculate_crash_frequency()
            calculate_total_stars()
            generate_summary()
            calculate_log_level()
            # evtLogs.run_all_os(mysql_code)
            sleep(60)

        except Exception as e:
                print(f"Error in check_every_1_minute: {e}")

# check every 1 hour
def check_every_1_hour():
    while True:
        try:
            security_runner()
            sleep(3600)
        except Exception as e:
            print(f"Error in check_every_1_hour: {e}")

# check every day
def check_every_day():
    while True:
        try:
            upload_to_s3_eod()
            sleep(3600*24)

        except Exception as e:
            print(f"Error in check_every_day: {e}")


# all tests
def run_all_tests():
    try:
        print("line0")
        run_in_thread(pipe)                                                             
        print("line2") 
        run_in_thread(check_every_1_minute)
        print("line4") 
        run_in_thread(check_every_1_hour)
        print("line5") 
        run_in_thread(check_every_day)
        print("line6") 

    except Exception as e:
        print(f"Error in run_all_tests: {e}")

    for t in all_threads:
        t.join()

# run_all_tests()
