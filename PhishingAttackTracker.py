import re, os, csv, sqlite3, logging, sys
import ipwhois
import whois
from tkinter import Tk
from tkinter.filedialog import askdirectory
import contextlib

#Define Global Variables
regex = '''^(25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)\.( 
            25[0-5]|2[0-4][0-9]|[0-1]?[0-9][0-9]?)$'''
db = None

#--------------------------- Functions -----------------------------------------

def check(IP_Address):
    """
    This function is used to check if an IP address is formated correctly. It uses
    Regex which I do not understand at all and got off of Stack Overflow. Its
    seems to work so I just don't really touch this function at all.

    Parameters:
    -----------
    IP_Address : String
        This string holds an IP address that is entered by the user

    Returns:
    --------
    Boolean :
        If the IP Address the user entered is formated correctly then True is
        returned. If it is not correctly formated then False is returned

    """

    if(re.search(regex, IP_Address)):
        return True

    else:
        return False

def load_DB(db_file):
    """
    This function is used to load the database at program start.
    ...
    Parameters
    ----------
    db_file : string
        The location that the database file should be. It should be located in
        the root directory of the program
    ...
    Returns
    -------
    db.cursor() : function
        This calls the cursor function that returns the cursor for the database
    """

    global db
    
    #Checks to see if the database file exists. If it does not the database
    # will be created
    if os.path.isfile('phishing_attack_tracker.db'):

       

        #create connection with the database
        db = sqlite3.connect(db_file)
    
    else:

        #Creates the database files
        db = sqlite3.connect(db_file)
        #Calls the create_db function to create the database tables
        create_DB(db.cursor())


    return db.cursor()

def isBlocked(Blocked): 
    """
    This function is used to check to see if an IP Address is blocked or not. This
    is a very simple function used to save code.

    Parameters:
    -----------
    Blocked: integer
        This integer holds 0 or 1. 0 for False and 1 for True

    Returns:
    --------
    Boolean:
        If the integer provided is 0, False is returned. If the integer is 1,
        True is returned 
    """

    if Blocked == "0":
        return "False"

    else:
        return "True"

def cursor():
    """
    This function is used to retreive the database cursor
    ...
    Returns
    -------
    db.cursor() : function
        This calls the cursor function that returns the cursor for the database
    """

    if not db:
        LoadDB()

    else:
        return db.cursor()

def commit():
    """
    This function is used to commit the database
    """

    db.commit()

def close():
    """
    This function is used to close the database connection
    """

    db.close()

def create_DB(c):
    """
    This function is used to create the database. If the database already exists
    this function will not run

    Parameters:
    -----------
    c: cursor object 
        This is the cursor object created for the database.
    """
    print('------------ Creating Database ------------')

    try:
        c.execute("""CREATE TABLE PHISHINGDATA (
                        ID integer PRIMARY KEY,
                        DOMAIN text,
                        IP_ADDRESS text,
                        EMAIL text,
                        IP_RANGE text,
                        OWNER text,
                        DATE_CREATED text,
                        DATE_EXPIRE text,
                        INTENT text,
                        TIMES_FOUND int,
                        REF text,
                        BLOCKED int
                        )""")


    except Exception as error:
        print(e)
    
    return

def commit_ip_address(domain, ip_address, email, ip_range, owner, date_created, date_expired, intent, times_found, ref, blocked):
    """
    A function used to add a new entry to the database.

    Parameters:
    -----------
    domain : String
        A string holding the domain that is being tracked. This can be N/A if database entry is not to track a domain

    ip_address : String
        A validated string holding an IP address entered by the user. This can be N/A if database entry is not to track a ip address

    email : String
        A string holding the email address being tracked. This can be N/A if database entry is not to track an email address

    ip_range : String
        A string holding the IP or IP range that the domain or IP address can be attributed to. This can be N/A if the entry is used to track an email address.

    date_created : String
        A string holding the date the domain being tracked was created. This can be N/A if the entry is not tracking a domain.

    date_expired : String
        A string holding the date the domain being tracked will expire. This can be N/A if the entry is not tracking a domain.

    intent : String
        A string holding the intent of the domain, email, or IP address being tracked. 

    times_found : Integer
        An integer holding the number of times that an email address, domain, of IP has been found before.

    ref : String
        A string holding any referance that could be used to track this (e.g Ticket Number).

    blocked : Integer
        An integer holding either a 0 or a 1 to represent False and True respectivly for if a domain, email address, or IP address was blocked. 
    """

    #SQL statement
    statement = "INSERT INTO PHISHINGDATA (DOMAIN, IP_ADDRESS, EMAIL, IP_RANGE, OWNER, DATE_CREATED, DATE_EXPIRE, INTENT, TIMES_FOUND, REF, BLOCKED) VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?, ?)"
    #Execute the SQL statement
    cursor().execute(statement, domain, ip_address, email, ip_range, owner, date_created, date_expired, intent, times_found, ref, blocked)
    commit()

def fetch(primary_key, input_classification):
    """

    This function is used for retreiving the IP address from the datbase.

    Parameters:
    -----------
    primary_key : String
        A string holding an email address, 
    """
    if input_classification == 'ip_address':
        statement = "SELECT * FROM PHISHINGDATA WHERE IP_ADDRESS = ?"

    elif input_classification == 'email_address':
        statement = "SELECT * FROM PHISHINGDATA WHERE EMAIL = ?"

    else:
        statement = "SELECT * FROM PHISHINGDATA WHERE DOMAIN = ?"

    #Execture the SQL statement
    table_data = cursor().execute(statement, (primary_key,)).fetchone()

    #If the IP address is in the database it will return the data associated
    if table_data: 
        return table_data
    
    #If nothing is returned, 0 is returned
    else:
        return "0"

def update(domain, ip_address, email, ip_range, owner, date_created, date_expired, intent, times_found, ref, blocked):
    """
    This function is used to update the IP Address listing in the database. This
    really is only used to update if it is blocked or how many times the IP
    address has been found

    Parameters:
    -----------
    ip_address : String
        This is a validated string holding an IP address entered by the user

    description : String
        Description of the IP address from WHO IS search

    ip_range : String
        The IP range that the IP belongs to

    date : String
        Date of initial ownership

    times_found : integer
        the number of times that the IP address has been run through the program
    """

    #SQL statement
    statement = "UPDATE PHISHINGDATA SET DOMAIN = ?, IP_ADDRESS = ?, EMAIL = ?, IP_RANGE = ?, OWNER = ?, DATE_CREATED = ?, DATE_EXPIRED = ?, INTENT = ?, TIME_FOUND = ?, REF = ?, BLOCKED = ?"
    #Execute the SQL statement
    cursor().execute(statement, (domain, ip_address, email, ip_range, owner, date_created, date_expired, intent, times_found, ref, blocked))
    commit()

def fetch_all():
    """
    This method is used to fetch all of the data from the database and returns it for parsing.

    Returns:
    --------

    ip_address_data : List of lists
        This list has all of the lists containing the data from the database. It can be used to
        output the data to the user in any way
    """

    #SQL statement
    statement = "SELECT * FROM PHISHINGDATA"
    #Execture the SQL statement
    database_data = cursor().execute(statement).fetchall()

    #If there is data it is returned to the user
    if database_data:
        return database_data

    #If there is no data then 0 is returned
    else:
        return '0'

def export():
    """
    This function is used to export reports to the user. It gives the user the ability to have a report printed
    in the terminal or for it to be exported into a csv file.
    """

    #Asking the user to chose where they want the report to be exported to
    user_export_choice = input('\n\n--------- Would you like to export the report to the terminal or to a csv? --------- \n\n1) Terminal\n2) CSV File\n\nYour Input: ')

    #Validating the users input
    while user_export_choice.lower() != '1' and user_export_choice.lower() != '2' and user_export_choice.lower() != 'terminal' and user_export_choice.lower() != 'csv' and user_export_choice.lower() != 'csv file' and user_export_choice.lower() != 'exit':
        user_export_choice = input('\n\n--------- Please only select one of the following options? --------- \n\n1) Terminal\n2) CSV File\n\nYour Input: ')

    #Fetching all of the data from the database
    ip_database_data = fetch_all()

    #Validating that there is data in the database
    if ip_database_data == '0':
        #Outputting to the user to say there is no data in the database
        print("\n\n----------------------- ERROR -----------------------\n")
        print("Looks like there is no data in the database.")
        print("Try adding some before trying to export")

        #Reprinting the options of what the user can do to them
        print("\n\n\n----------------------------- PROGRAM SUB-OPTIONS -----------------------------\n")
        print("Type 'Export' at any time to see all IP Addresses in the database")
        print("Type 'Exit' at any time to quit the program\n\n")

        #restarting the script
        main()

    #If the users choice is to output it to the terminal, this is run
    if user_export_choice.lower() == 'terminal' or user_export_choice == "1":
        #Printing the top of the table with headers 
        print("\n\nIP ADDRESS      IP RANGE              DESCRIPTION/OWNER          DATE AQUIRED     TIMES FOUND     BLOCKED")
        print("-------------------------------------------------------------------------------------------------------------")

        #For loop going through all of the entries in the database
        for x in ip_database_data:

            #Printing the data in a formated fashion to match the table
            print("%-15s %-21s %-26s %-16s %-15s %-7s"% (x[0], x[2], x[1], x[3], x[4], isBlocked(x[5])))

        #Allowing for the user to view the table before continuing
        input("\n\nPlease press any key to continue...")

        #Reprinting the options of what the user can do to them
        print("\n\n\n----------------------------- PROGRAM SUB-OPTIONS -----------------------------\n")
        print("Type 'Export' at any time to see all IP Addresses in the database")
        print("Type 'Exit' at any time to quit the program\n\n")

    #If the user selects to output to a csv this option is run
    elif user_export_choice.lower() == 'csv' or user_export_choice.lower() == '2' or user_export_choice.lower() == "csv file":
        #This uses a GUI to ask the user for the folder they want their report put into
        path = askdirectory(title='Select Folder')

        #TTrying to open and write to the file
        try: 
            #Creating/Opening the file to write the report in
            with open(path + '/IP_Report.csv', mode='w', newline='') as ip_report_file:
                #Creating the CSV writer
                employee_writer = csv.writer(ip_report_file)

                #Writing the headers
                employee_writer.writerow(["IP ADDRESS", "IP RANGE", "DESCRIPTION/OWNER", "DATE AQUIRED", "TIMES FOUND", "BLOCKED"])

                #Writing all the other rows from the database
                for x in ip_database_data:
                    employee_writer.writerow([x[0], x[2], x[1], x[3], x[4], isBlocked(x[5])])

            #Outputting to the user
            print("\n\n ----------------- Report Created -----------------")
            #Waiting for the user to want to move on
            input("\n\nPlease press any key to continue...")
            #Reprinting the program sub options to the user
            print("\n\n\n----------------------------- PROGRAM SUB-OPTIONS -----------------------------\n")
            print("Type 'Export' at any time to see all IP Addresses in the database")
            print("Type 'Exit' at any time to quit the program\n\n")

        #Catching any errors and outputting the error if there is one
        except Exception as e:
            print(e)

def enter_ip_address(user_input,user_known_intent,ref):

    try:

        IP_data = ipwhois.IPWhois(user_input).lookup_rdap()

    except:

        print("\n\n------------ ERROR ------------\nThere was a problem reaching out to the API\n\Restarting Scriptn\n")
        main()

    entity = IP_data.get('entities')



    

    #TODO Ask the user if they would like the block the IP address if it is not already blocked

    #TODO Ask the user for the intent and referance if the IP isn't already there 

    IP_data_list = ["N/A", user_input, "N/A", IP_data.get('asn_cidr'), IP_data.get('objects').get(entity[0]).get('contact').get("name"), IP_data.get('asn_date'), "N/A", user_known_intent, 0, ref, 0]

    print("\n\n------------ Exporting Data Found ------------\n")
    print("\n\nDOMAIN           IP ADDRESS     EMAIL ADDRESS                 IP RANGE          OWNER                                   DATE CREATED     DATE EXPIRES")
    print("-----------------------------------------------------------------------------------------------------------------------------------------------------------")
    print("%-16s %-14s %-29s %-17s %-39s %-16s %-16s"% (IP_data_list[0],IP_data_list[1],IP_data_list[2],IP_data_list[3],IP_data_list[4],IP_data_list[5],IP_data_list[6]))


def user_intent():

    intent = input("\n\nPlease input what you consider the intent for this entry? \n\nInput: ")

    return intent


#----------------------------- Main Code ---------------------------------------

def main():

    input_classification = ""

    user_known_intent = "N/A"
    ref = "n/A"

    user_input = str(input('Please input an IP address, Email Address, or Domain. \n\nInput: '))

    user_known_intent = user_intent()
    
    if user_input.lower() == 'exit':
        exit()

    elif user_input.lower() == 'export':

        export()
        main()

    if check(user_input):
        input_classification = "ip_address"
        print(input_classification)
        pass

    else:
        
        for x in range(len(user_input)):
            if user_input[x] == "@":
                input_classification = "email_address"

        if input_classification == "":
            input_classification = "domain"

    
    print('\n')

    if input_classification == "ip_address":

        is_in_database = fetch(user_input, input_classification)

        if is_in_database == "0":
            enter_ip_address(user_input,user_known_intent,'test')

        else:
            
            #TODO Show the user to data if it is already in the database
            pass

    
    
        


    
    Repeat = input("\n\nWould you like to add another IP Address? \n\nInput (Yes/No):")

    while Repeat != 'yes' and Repeat != 'YES' and Repeat != 'Yes' and Repeat != 'no' and Repeat != 'NO' and Repeat != 'No' and Repeat.lower() != 'exit' and Repeat.lower() != 'export':
        
        Repeat = input("\n\tPlease only input Yes or no: ")

    if Repeat.lower() == "no":

        exit()

    elif Repeat.lower() == "exit":

        exit()

    elif Repeat.lower() == "export":

        export()
        main()

    else:

        print("\n\n")
        main()


print(" _____  _     _     _     _                     _   _             _    ")
print("|  __ \| |   (_)   | |   (_)               /\  | | | |           | |   ")
print("| |__) | |__  _ ___| |__  _ _ __   __ _   /  \ | |_| |_ __ _  ___| | __")
print("|  ___/| '_ \| / __| '_ \| | '_ \ / _` | / /\ \| __| __/ _` |/ __| |/ /")
print("| |    | | | | \__ \ | | | | | | | (_| |/ ____ \ |_| || (_| | (__|   <")
print("|_|____|_| |_|_|___/_| |_|_|_| |_|\__, /_/    \_\__|\__\__,_|\___|_|\_\ ")
print("|__   __|           | |            __/ |")                               
print("   | |_ __ __ _  ___| | _____ _ __|___/")                                
print("   | | '__/ _` |/ __| |/ / _ \ '__|")                                    
print("   | | | | (_| | (__|   <  __/ |")                                       
print("   |_|_|  \__,_|\___|_|\_\___|_|") 
print("\n\n\n----------------------------- PROGRAM SUB-OPTIONS -----------------------------\n")
print("Type 'Export' at any time to see all IP Addresses in the database")
print("Type 'Exit' at any time to quit the program\n\n")

input("Please select the folder you would like to create a new database in or open an existing database.\n\nPress Any Key to Continue...")

path = askdirectory(title='Select Folder')


try:
    with contextlib.redirect_stdout(None):
        load_DB(path + '/phishing_attack_tracker.db')

except Exception as e:
    print("\n\nERROR: No Database Found")
    print("\n----------------------------- Creating New Database ----------------------------- \n\n")
 
main()









