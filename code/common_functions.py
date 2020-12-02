from HLCAPP.commons.config_reader import LgConfig
from HLCAPP.Leggero.Leggero_JSON_Helper import LgReturnJSONV2
from pytz import timezone
from HLCAPP.notification_helper.notification_statics import TIMEZONE_FOR_NOTIFICATIONS
from datetime import datetime



LC = LgConfig().getConfig()
host = LC.get('HLCSERVER', ).get('host')
port = LC.get('HLCSERVER', ).get('port')
ipaddress = LC.get('ipAddress')
doc_ip_address = LC.get('HLCPATHS').get('docIP')


def get_profile_url(dict_data):
    """
    This function just take a dictionary which noctain document to make full url
    :param dict_data:
    :return:
    """
    if not 'document_path' in dict_data:
        return dict_data

    document_path = dict_data.pop('document_path')
    dict_data['profile_pic_url'] = doc_ip_address + "/download/" + document_path if document_path else ''
    return dict_data


def create_error_json(e, data=[], errCode=1, msgCode=0):
    retdata = LgReturnJSONV2()
    retdata.set_data(data)
    retdata.set_error_msg(errCode, e)
    retdata.update({'msgCode': msgCode})
    return retdata


def get_date_converted_to_timezone(data, timezone_name=TIMEZONE_FOR_NOTIFICATIONS):
    data = timezone(timezone_name).localize(data)
    return data
#
def check_south_african_ID(id):
    """
    860506 5397 083
     A South African ID number is a 13-digit number which is defined by the following format: YYMMDDSSSSCAZ.
     The first 6 digits (YYMMDD) are based on your date of birth. 20 February 1992 is displayed as 920220.
     The next 4 digits (SSSS) are used to define your gender.  Females are assigned numbers in the range 0000-4999 and males from 5000-9999.
     The next digit (C) shows if you're an SA citizen status with 0 denoting that you were born a SA citizen and 1 denoting that you are a permanent resident.
     The last digit (Z) is a checksum digit used to check that the number sequence is accurate using a set formula called the Luhn algorithm.
     https://formvalidation.io/guide/validators/id/south-african-identification-number/ or https://www.checkid.co.za/ to check online
    :param id:
    :return:
    """
    print("SID:",id)
    id_str = str(id)
    if not id_str.isdigit() or len(str(id_str)) != 13:
        return "Invalid length"
    year = int(id_str[0:2])
    month = int(id_str[2:4])
    day = int(id_str[4:6])
    date_format = '{day}-{month}-{year}'.format(day=day,month=month, year=year)
    print("date_format:",date_format)
    if not dateTryParse(year,month,day):
        return "Invalid DOB"

    # Check SSSS
    gender = id_str[6:10]
    if len (str(gender)) < 4 or int(gender) > 9999:
        return "Invalid Gender"
    # Check C
    citizen = int(id_str[10:11])
    print("Citizen:", citizen)
    if not citizen in [0,1]:
        return "Invalid Citizen"
    # Check A,A digit lies between 0-9 generally 8 or 9, it does not have any purpose, but it is in format
    racial = int(id_str[11:12])
    print("racial:", racial)
    if racial > 9:
        return "Invalid racial"
    if not is_luhn_algo_valid(id_str):
        return "Luhn invalidated number sequence"
    return "pass"


from datetime import datetime

def dateTryParse(year,month,days):

    result = True
    try:
        newDate = datetime(year, month, days)
    except Exception as e:
        result = False

    return result


def is_luhn_algo_valid(id_number):
    nDigits = len(id_number)
    nSum = 0
    isSecond = False

    for i in range(nDigits - 1, -1, -1):
        d = ord(id_number[i]) - ord('0')
        if (isSecond == True):
            d = d * 2

        # We add two digits to handle
        # cases that make two digits after
        # doubling
        nSum += d // 10
        nSum += d % 10

        isSecond = not isSecond

    print("Sum:",nSum)
    if (nSum % 10 == 0):
        return True
    else:
        return False


if __name__ == "__main__":
    #https://formvalidation.io/guide/validators/id/south-african-identification-number/
    #https://www.checkid.co.za/
    # Valid valid Ids:8001015009087,8801235111088
    # Invalid Ids:9501127062394,8905180127188,9202204720082
    res = check_south_african_ID('0123456789012')
    print(res)

