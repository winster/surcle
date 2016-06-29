import requests
from time import ctime, sleep
from datetime import datetime
import logging
FORMAT = '%(message)s'
logging.basicConfig(format=FORMAT,level=logging.DEBUG)

def email(user_id, otp):
    jsonInput = {
        "from": "Admin <admin@loopme.in>",
        "to": user_id,
        "subject": "Welcome to LoopMe ",
        "html": "your otp is <b>{}</b>".format(otp)
    }
    res = requests.post('https://winmail.herokuapp.com/mail', None, jsonInput)
    logging.info(res.text)


def time_diff(time1, time2):
    diff = datetime.strptime(time2, "%a %b %d %H:%M:%S %Y")-datetime.strptime(time1, "%a %b %d %H:%M:%S %Y")
    print diff.seconds


if __name__ == '__main__':
    #email('winster.jose@amadeus.com', '123456')
    time1 = ctime()
    sleep(61)
    time2 = ctime()

    time_diff(time1, time2)