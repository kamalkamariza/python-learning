import json
import requests
from datetime import datetime
from base64 import urlsafe_b64encode
import calendar
import urllib
import urllib2
from urlparse import urlparse
import os
from jose import jwt
from django.conf import settings
from celery import shared_task
import boto
from boto.s3.key import Key
from boto.s3.lifecycle import Expiration, Lifecycle, Rule
import time

"""
   Set the parameters to run this script
"""
nexmo_key = settings.NEXMO_API_KEY
nexmo_secret = settings.NEXMO_API_SECRET
# Leave blank unless you have already created an application
application_id = "ba683cf1-39ac-4fe6-86c3-2650f08b9dea"
# If you add an application ID here, add the private key in a file with the
# same name as the application ID in  the same directory as this script.

# And the phone number you are calling from
# This does not have to be a real phone number, just in the correct format
virtual_number = "441632960961"

"""
  The base URL for Nexmo endpoints.
"""
base_url = 'https://api.nexmo.com'
version = '/v1'
action = '/calls'

@shared_task
def print_success():
    return 'success!!!'

@shared_task
def delete_file_from_memory(file_dest):
    ''' remove file from memory by its destination '''
    try:
        os.remove(file_dest)
        return True
    except AttributeError:
        raise AttributeError('deletion failed. Check file.')

def push_code_to_Aws(dest):
    s3_connection = boto.connect_s3(aws_access_key_id=settings.AWS_ACCESS_KEY_ID,
                                    aws_secret_access_key=settings.AWS_SECRET_ACCESS_KEY)
    try:
        bucket = s3_connection.get_bucket('calljson')
    except:
        bucket = s3_connection.create_bucket('calljson')
    expiration = Expiration(days=1)
    rule = Rule(id='ruleid', status='Enabled', expiration=expiration)
    lifecycle = Lifecycle()
    lifecycle.append(rule)
    bucket.configure_lifecycle(lifecycle)
    # create new key in s3
    key = bucket.new_key(dest)
    key.content_type = 'text/plain'
    f = open(dest, 'r')
    mystring = f.read()
    key.set_contents_from_string(mystring, policy='public-read')
    time.sleep(2)
    url = key.generate_url(160)
    o = urlparse(url)
    return o.scheme + "://" + o.netloc + o.path


"""
 Function to generate a JWT using the private key associated with an application.
"""


def generate_jwt(application_id="none", keyfile="application_secret_key.txt"):
    print("Opening keyfile " + keyfile)
    application_private_key = open(keyfile, 'r').read()
    # Add the unix time at UCT + 0
    d = datetime.utcnow()

    token_payload = {
        "iat": calendar.timegm(d.utctimetuple()),  # issued at
        "application_id": application_id,  # application id
        "jti": urlsafe_b64encode(os.urandom(64)).decode('utf-8')
    }

    # generate our token signed with this private key...
    return jwt.encode(
        claims=token_payload,
        key=application_private_key,
        algorithm='RS256')


def create_json_file(code):
    code = str(code)
    message = "Your verification code is {}, ,{}, ,{}, ,{}.".format(code[0], code[1], code[2], code[3])
    initial = [
        {
            "action": "talk",
            "voiceName": "Salli",
            "text": "Hello there!{} {} {}".format(message, message, message),
        }
    ]
    filename_unique_code = urlsafe_b64encode(os.urandom(10))
    filename = "auth_user/static/talk_{}.json".format(filename_unique_code)
    with open(filename, 'wb+') as f:
        f.write(json.dumps(initial))
        f.close()
    url = push_code_to_Aws(filename)
    os.remove(filename)
    # delete_file_from_memory.apply_async((filename,), countdown=10, link=print_success.si())
    return url


def make_call(code, phone_number_to_call):
    assert code, "Code not entered"
    assert phone_number_to_call, "Phone Number not available"
    jwt_obj = generate_jwt(application_id, application_id)

    url = create_json_file(code)

    # Add the JWT to the request headers
    headers = {
        "Content-type": "application/json",
        "Authorization": "Bearer {0}".format(jwt_obj)
    }

    payload = {
        "to": [{
            "type": "phone",
            "number": phone_number_to_call
        }],
        "from": {
            "type": "phone",
            "number": virtual_number
        },
        "answer_url": [url]
    }
    #print ("Use the following payload to make the Call: \n" + json.dumps(payload, indent=4, sort_keys=True))

    print ("answer_url is pointing to the webhook endpoint providing the NCCO that manages the Call.")

    print ("And make the Call. ")

    response = requests.post(base_url + version + action, data=json.dumps(payload), headers=headers)
    if (response.status_code == 201):
        print ("The Call status is: " + response.content)
        return response
    else:
        print("Error: " + str(response.status_code) + " " + response.content)
        raise Exception("Error: " + str(response.status_code) + " " + response.content)



