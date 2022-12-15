# PEA - Phishing Email Analyzer - v0.1 (PoC)
# Created by: Sam Roethemeyer
# This program inputs a .eml file and outputs the headers and body of the email.
# It also outputs the URLs found in the email.
# Created on 12/12/2022

# Import modules
# This was in the original code, but I don't know what it does
from __future__ import print_function
# This imports the argparse module
from argparse import ArgumentParser, FileType
# This imports the email module
from email import message_from_file
# This imports the re module
import re
# This imports the os module
import os
# This imports the quopri module
import quopri
# This imports the base64 module
import base64

# This prints the banner, version, and instructions
print("""\
           _____                    _____                    _____          
          /\    \                  /\    \                  /\    \         
         /::\    \                /::\    \                /::\    \        
        /::::\    \              /::::\    \              /::::\    \       
       /::::::\    \            /::::::\    \            /::::::\    \      
      /:::/\:::\    \          /:::/\:::\    \          /:::/\:::\    \     
     /:::/__\:::\    \        /:::/__\:::\    \        /:::/__\:::\    \    
    /::::\   \:::\    \      /::::\   \:::\    \      /::::\   \:::\    \   
   /::::::\   \:::\    \    /::::::\   \:::\    \    /::::::\   \:::\    \  
  /:::/\:::\   \:::\____\  /:::/\:::\   \:::\    \  /:::/\:::\   \:::\    \ 
 /:::/  \:::\   \:::|    |/:::/__\:::\   \:::\____\/:::/  \:::\   \:::\____\\
 \::/    \:::\  /:::|____|\:::\   \:::\   \::/    /\::/    \:::\  /:::/    /
  \/_____/\:::\/:::/    /  \:::\   \:::\   \/____/  \/____/ \:::\/:::/    / 
           \::::::/    /    \:::\   \:::\    \               \::::::/    /  
            \::::/    /      \:::\   \:::\____\               \::::/    /   
             \::/____/        \:::\   \::/    /               /:::/    /    
              ~~               \:::\   \/____/               /:::/    /     
                                \:::\    \                  /:::/    /      
                                 \:::\____\                /:::/    /       
                                  \::/    /                \::/    /        
                                   \/____/                  \/____/               V0.1
                                                                            
    _____                _           _   _              _____                   _____            _   _                                         
   / ____|              | |         | | | |            / ____|                 |  __ \          | | | |                                        
  | |     _ __ ___  __ _| |_ ___  __| | | |__  _   _  | (___   __ _ _ __ ___   | |__) |___   ___| |_| |__   ___ _ __ ___   ___ _   _  ___ _ __ 
  | |    | '__/ _ \/ _` | __/ _ \/ _` | | '_ \| | | |  \___ \ / _` | '_ ` _ \  |  _  // _ \ / _ \ __| '_ \ / _ \ '_ ` _ \ / _ \ | | |/ _ \ '__|
  | |____| | |  __/ (_| | ||  __/ (_| | | |_) | |_| |  ____) | (_| | | | | | | | | \ \ (_) |  __/ |_| | | |  __/ | | | | |  __/ |_| |  __/ |   
   \_____|_|  \___|\__,_|\__\___|\__,_| |_.__/ \__, | |_____/ \__,_|_| |_| |_| |_|  \_\___/ \___|\__|_| |_|\___|_| |_| |_|\___|\__, |\___|_|   
                                                __/ |                                                                           __/ |          
                                               |___/                                                                           |___/                                                                             
""")

print("\n")
print("\n")
print("\n")
print("Usage: python pea.py <filename>.eml")
print("\n") 
print("Example: python pea.py email.eml")
print("\n")
print("""This program is meant to help analyze emails that may be phishing attempts.
It will output the headers and body of the email, as well as the URLs found in the email.
This program is a work in progress, and is not meant to be used in a production environment.
It is meant to be used for educational purposes only. Use at your own risk.""")
print("\n")
print("\n")
print("\n")

# This defines the main function
def main(input_file):
    # Read the email into a message object
    emlfile = message_from_file(input_file)
    # Start with the headers
    for key, value in emlfile._headers:
        # Print the headers
        print("{}: {}".format(key, value))
    # Read payload
    print("\nBody\n")
    # Check if the email is multipart
    if emlfile.is_multipart():
        # If it is, loop through the parts
        for part in emlfile.get_payload():
            # Call the process_payload function
            process_payload(part)
    # If it's not multipart, just process the payload        
    else:
        # Call the process_payload function
        process_payload(emlfile[1])
    # Call the find_urls function
    find_urls(emlfile)

# This defines the process_payload function
def process_payload(payload):
    # Print the content type of the payload (text/html, text/plain, etc.) and a separator line of equal signs
    print(payload.get_content_type() + "\n" + "=" * len(
        payload.get_content_type()))
    # Assign the decoded payload to a variable called body
    body = quopri.decodestring(payload.get_payload())
    # Check if the payload has a charset
    if payload.get_charset():
        # If it does, decode the body using the charset
        body = body.decode(payload.get_charset())
    # If it doesn't, try to decode it as UTF-8
    else:
        try:
            body = body.decode()
        # If that doesn't work, try to decode it as cp1252    
        except UnicodeDecodeError:
            body = body.decode('cp1252')
    # Check if the payload is text/html
    if payload.get_content_type() == "text/html":
        # Opens a file with the same name as the EML file, but with a .html extension
        outfile = os.path.basename(args.EML_FILE.name) + ".html"
        # Write the body to the file
        open(outfile, 'w').write(body)
    # Check if the payload is application/octet-stream    
    elif payload.get_content_type().startswith('application'):
        # If it is, write the payload to a binary file
        outfile = open(payload.get_filename(), 'wb')
        # Decode the payload encoded in base64
        body = base64.b64decode(payload.get_payload())
        # Write the decoded payload to the file
        outfile.write(body)
        # Close the file
        outfile.close()
        # Print the name of the file that was written
        print("Exported: {}\n".format(outfile.name))
    # If it's not text/html or application/octet-stream, just print the body
    else:
        print(body)

# This defines the find_urls function
def find_urls(payload):
        # Open a file called urlsFound.txt
        with open('urlsFound.txt', 'w') as outfile:
            # Reads the parts of the payload
            for part in payload.get_payload():
                # Checks if the part has a content type of text/plain
                try:
                    # Assigns the result of the search to a variable called part1
                    part1 = re.search("plain", part.get_content_type())
                # If it doesn't, pass
                except AttributeError:
                    pass        
                # If it does, split the part into lines
                for i in part.as_string().split('\n'):
                    # If part1 is a match, search for URLs
                    if isinstance(part1, re.Match):
                        # Search for URLs and assign the result to a variable called url
                        url = re.search("(?P<url>https?://[^\s]+)", i)
                        # If url is None, continue
                        if url is None:
                            continue
                        # If url is not None, assign the URL to a variable called url
                        url = url.group("url")
                        # If the last character of the URL is a greater than sign, remove it
                        if url[-1] == ">":
                            url = url[:-1]
                        # Write the URL to the file
                        outfile.write(str(url) + "\n")
                        # Print the URL
                        print("URL Found: " + str(url))
            # Print "Done"
            print("Done")

# This is the main function
if __name__ == '__main__':
    # This defines the arguments that can be passed to the program
    parser = ArgumentParser(
        description="description",
        epilog="Developed by {} on {}".format(
            ", ".join("__authors__"), "__date__"))
    # This defines the argument for the EML file
    parser.add_argument("EML_FILE",
                        help="Path to EML File", type=FileType('r'))
    # This parses the arguments
    args = parser.parse_args()
    # This calls the main function
    main(args.EML_FILE)