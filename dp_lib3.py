#!/bin/python3
import base64
import urllib
import urllib.request
import re
import socket
import datetime
import ssl
import logging
import os
from xml.etree import ElementTree
import sys
import json
from . import sendmail



#Set Global variables
namespaces = {
    'env': 'http://schemas.xmlsoap.org/soap/envelope/',
    'amp': 'http://www.datapower.com/schemas/appliance/management/3.0',
    'dp' : 'http://www.datapower.com/schemas/management'
}

if 'linux' in sys.platform:
    system = "DP"
    root_dir = '/usr/WebSphere/SOAAdmin/scripts'
    shell_dir = root_dir + '/shell/' + system
    work_dir = root_dir + '/work/' + system
    prop_dir = root_dir + '/properties/' + system
    dp_hosts_file = prop_dir + '/dp_hosts.txt'
    ca_file = prop_dir + '/capath/UMB_Internal_Strong_Root_Certificate_Authority_exp_02082033.pem'
    passwd_file = prop_dir + '/.password'
    log_dir = work_dir + '/dp_lib_log/'
    sep = '/'
else: #Running on Windows environment
    log_dir = 'C:\\Scripts\\DP\\dp_lib_log\\'
    dp_hosts_file = 'datapowerpy\\config\\dp_hosts.txt'
    passwd_file = 'datapowerpy\\config\\password.txt'
    ca_file = 'datapowerpy\\config\\UMB_Internal_Strong_Root_Certificate_Authority_exp_02082033.crt'
    sep = '\\'


#Set up logger
if not os.path.exists(log_dir):
    os.mkdir(log_dir)
log_file = log_dir + 'dp_lib_'+str(datetime.datetime.now().strftime("%m-%d-%Y")) +  '.log'
log_level = logging.INFO
logging.basicConfig(level=log_level,filename=log_file,filemode="a+", format="%(asctime)-15s %(levelname)-8s \"%(message)s\"")
logger = logging.getLogger(__name__)


def resp_to_json(response):
    return str(json.dumps(json.loads(response), indent=4))


def resp_to_dict(response):
    """
    Converts the response to dictionary
    :param dict_: dictionary datastructure to convert.
    :returns: JSON str
    """
    return json.loads(response)


def dict_to_json(dict_):
    """
    Converts a dictionary to JSON str with formatting.
    :param dict_: dictionary datastructure to convert.
    :returns: JSON str
    """
    return json.dumps(dict_, indent=4)


def send_email(send_to, subject, text, files=None, server="localhost"):
    """
    Sends an email...

    :param send_to: list, list of recipients.
    :param subject: str, subject readline
    :param text: str, body of send_email
    :param file: list of str, paths to files you wish to attach.
    :param server: str, defaults to locahost
    """
    sendmail.send_mail(send_to, subject, text, files=None, server="localhost")


def get_host_name():
    """
    Returns the host name of server this script is running on.

    :returns: str
    """
    return str.split(socket.gethostname(), '.')[0]


def get_quiesce_time():
    """
    Returns SOA's DataPower standard queisce time depending on environment.

    :returns: int dl10239 = 60 | dl10239 = 90 | defaults to 300
    """
    if get_host_name() == "dl10239":
        return 60
    elif get_host_name() == "ql10216":
        return 90
    else:
        return 300


def get_environments():
    return list(datapower_hosts.dp_hosts.keys())


def get_datapower_hosts(env=None, dmz=None, role=None, name=None):
    if env is None:
        host = get_host_name()
        if host == 'dl10239':
            env = 'DEV'
        elif host =='ql10216':
            env = 'QA'
        elif host == 'vrtpo30135':
            env = 'PROD'
        else:
            raise Exception('env is required for this function if it is not being ran on the management servers.')
    if env not in get_environments():
        raise Exception('get_datapower_hosts() failed, environment not found in datapowerpy/config/datapower_hosts.py')
    dp_env = datapower_hosts.dp_hosts.get(env)
    if dmz is None:
        for host in dp_env:
            pass

    return dp_env

# Returns Column 3 of dp_host.txt by default, if inv is set this will find the inverse (like grep -v).
def get_dp_hosts(where, pri_sec=None, column=2, inv=False, host=None):
    """
    Returns a list of DataPower hosts from dp_host.txt

    :param where:
    :param pri_sec: for specifying 'primary' or 'secondary' review dp_host.txt for clarification
    :param column: defaults to 2, which returns column 3.  lists start at 0.
    :param inv: default is False, set to true to get inverse like grep -v
    :param host: defaults to None and gets set in the function to the correct host.
                 host is optional and used primarily for testing.
    :reurns: list of hosts
    """

    if host is None:
        host = get_host_name()
    regex = '\\b%s\\b' % where
    dp_hosts = []
    if pri_sec is None:
        with open(dp_hosts_file, 'r') as fin:
            for line in fin:
                print(line)
                if inv:
                    if not re.findall(regex, line) and re.findall(host, line):
                        # Adds column 3 to dp_hosts[]
                        dp_hosts.append(line.split('|')[column])
                else:
                    if re.findall(regex, line) and re.findall(host, line):
                        # Adds column 3 to dp_hosts[]
                        dp_hosts.append(line.split('|')[column])
    else:
        with open(dp_hosts_file, 'r') as fin:
            for line in fin:
                if inv:
                    if not re.findall(regex, line) and re.findall(host, line) and re.findall(pri_sec, line):
                        # Adds column 3 to dp_hosts[]
                        dp_hosts.append(line.split('|')[column])
                else:
                    if re.findall(regex, line) and re.findall(host, line) and re.findall(pri_sec, line):
                        # Adds column 3 to dp_hosts[]
                        dp_hosts.append(line.split('|')[column])
    return dp_hosts


def get_url(dp_name, interface, uri=''):
    """
    Returns the correct URL depending on interface being called, ie amp, soma, or rest

    :param dp_name: Hostname of the DataPower.
    :param interface: amp, soma, or rest
    :param uri: defaults to '', only used for rest interface
    :returns: url str
    """
    if interface == 'amp':
        return 'https://' + dp_name + '.svrmgmt.umb.com:5550/service/mgmt/amp/3.0'
    elif interface == 'soma':
        return  'https://' + dp_name + '.svrmgmt.umb.com:5550/service/mgmt/current'
    else:#rest interface
        return 'https://' + dp_name + '.svrmgmt.umb.com:5551' + uri


def request_body(request, interface):
    """
    Returns the body for the request, this is only needed for amp/soma calls.

    :param request: body of the request
    :param interface: amp or soma
    :returns: str of entire request needed to be sent to DataPower
    """
    if interface == 'amp':
        return "<soapenv:Envelope xmlns:ns=\"http://www.datapower.com/schemas/appliance/management/3.0\" xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\"><soapenv:Header/><soapenv:Body>%s</soapenv:Body></soapenv:Envelope>" % (request)
    else:
        return "<soapenv:Envelope xmlns:soapenv=\"http://schemas.xmlsoap.org/soap/envelope/\" xmlns:man=\"http://www.datapower.com/schemas/management\"><soapenv:Body>%s</soapenv:Body></soapenv:Envelope>" % (request)


def gen_request(url, request, interface, method=''):
    """
    Generates the request to be used by urllib in make_request

    :param url: str, url created by get_url
    :param request: str, request generated by request_body
    :param interface: rest or None.  Determines whether or not to pass a http method
    :param method: str, as in http method POST, PUT, GET, DELETE etc.....
    :returns: urllib.request.Request
    """
    if interface == 'rest':
        print(str.encode(request))
        return urllib.request.Request(url, str.encode(request), method=method)
    else:
        return urllib.request.Request(url, str.encode(request_body(request, interface)))


def make_request(dp_name, request='', uri='', interface='', method=''):
    """
    Makes the SOMA/AMP/REST request to DataPower

    :param dp_name: str, DataPower Name
    :param request: str, request to be sent to DataPower
    :param uri: str, used for REST requests, leave as empty string if not needed.
    :param interface: str, soma|amp|rest
    :param method: str, as in http method POST, PUT, GET, DELETE etc, only used for rest
    :returns: response from DataPower, use read() to retrieve body of response.
              This is returned as XML or JSON

    EXAMPLE of XML using AMP/SOMA:
        >>> xml_response = make_request('tocdo30150', request=request, interface='amp').read()

    EXAMPLE of JSON using REST:
        >>> response = make_request('tocdo30150', uri='/mgmt/config/Security/MultiProtocolGateway/SingleSignOn', interface='rest', method='GET').read()
        >>> dict_ = dp_lib3.resp_to_dict(response))
    """
    url = get_url(dp_name, interface, uri=uri)
    req = gen_request(url, request, interface, method)


    logger.info(uri + request.replace('\n', ''))
    username = "admin"
    password = ""
    with open(passwd_file) as pf:
        password = pf.readline().strip()
    credentials = ('%s:%s' % (username,password))

    encoded_credentials = base64.b64encode(credentials.encode())

    header_str = 'Basic %s' %encoded_credentials.decode('utf-8')
    req.add_header('Authorization', header_str)

    ssl_context = ssl.create_default_context(purpose=ssl.Purpose.CLIENT_AUTH, cafile=ca_file)
    ssl_context.verify_mode = ssl.CERT_NONE
    https_handler = urllib.request.HTTPSHandler(context=ssl_context)

    opener = urllib.request.build_opener(https_handler)
    urllib.request.install_opener(opener)
    try:
        o = opener.open(req, timeout=60)
        return o
    except Exception as error:
        print(str(error))
        logger.error(str(error))


# argument: Data Power Name
# returns: list of domain names using array [strings]
def get_domains(dp_name):
    """
    Retreives all domains on a DataPower.

    :param dp_name: str, name of the DataPower
    :return: list, list of all DataPower Domains
    """
    request = "<ns:GetDomainListRequest/>"
    xml_response = make_request(dp_name, request=request, interface='amp').read()
    tree = ElementTree.fromstring(xml_response)
    domains = tree.findall(
        './env:Body'
        '/amp:GetDomainListResponse'
        '/amp:Domain',
        namespaces,
    )
    domain_list = []
    for domain in domains:
        domain_list.append(domain.text)
    logger.info("get_domains " + dp_name)
    return domain_list


def get_domain_config(dp_name, domain):
    """
    Gets the domains configuration

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :return: str, base64 string of DataPower domain configuration
    """
    request = "<ns:GetDomainConfigRequest><ns:Domain>%s</ns:Domain></ns:GetDomainConfigRequest>" % (domain)
    xml_response = make_request(dp_name, request=request, interface='amp').read()
    tree = ElementTree.fromstring(xml_response)
    domain_config = tree.find('./env:Body/amp:GetDomainConfigResponse/amp:Config',namespaces,)
    logger.info("get_domain_config " + dp_name + " " + domain)
    return domain_config.text


def export_config(dp_name, domain, objects, location):
    xml_strs = []
    for obj in objects:
        xml_strs.append('<man:object class="' + obj['class'] + '" name="' + obj['name'] + '"/>')

    request = '<man:request domain="%s"><man:do-export format="ZIP">%s</man:do-export></man:request>' % (domain, ''.join(xml_strs))
    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    file = tree.find('./env:Body/dp:response/dp:file', namespaces,)
    in_bytes = file.text.encode('ascii')
    file_str = base64.b64decode(in_bytes)

    with open(location + os.sep + 'export.zip', 'wb') as f:
        f.write(file_str)

    return location + os.sep + 'export.zip'
    return file_str

def get_services(dp_name, domain):
    """
    Gets the services within a DataPower domain

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :return: list, list containing type Service(class_display_name, class_name, name, admin_state, op_state, config_state, quiesce_state).

    EXAMPLE of using returned list
    >>> services = dp_lib3.get_services('tocdo30150', 'Security')
    >>> for service in services:
    ...     print(service)
    ...
    AAARouter MultiProtocolGateway enabled up saved
    APICRouter MultiProtocolGateway enabled up saved

    OR
    >>> for service in services:
    ...     print(service.name)
    ...
    AAARouter
    APICRouter
    CDE-IntEnterpriseGateway-MutualSSL
    CDE-IntEnterpriseGateway-MutualSSL-JWT
    """
    request = "<ns:GetServiceListFromDomainRequest><ns:Domain>%s</ns:Domain></ns:GetServiceListFromDomainRequest>" % (domain)
    xml_response = make_request(dp_name, request=request, interface='amp').read()
    tree = ElementTree.fromstring(xml_response)
    domain_services = tree.findall(
        './env:Body/amp:GetServiceListFromDomainResponse/amp:Services/amp:Object',
        namespaces,
    )
    services = []
    for service in domain_services:
        service_dict = {}
        service_dict['name'] = service.get('name')
        service_dict['class-name'] = service.get('class-name')
        service_dict['class-display-name'] = service.get('class-display-name')
        for elem in service:
            service_dict[elem.tag.lstrip('{%s}' % namespaces['amp'])] = elem.text
        services.append(service_dict)
    logger.info("Fetched services from " + dp_name + " in " + domain + " domain")
    return services


def set_log_level(dp_name, domain, log_level="error"):
    """
    Sets log level at DataPower domain level.

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :param log_level: str, error, warning, debug, etc...
    :return: str, return status, 'OK' for success.
    """
    request = "<man:request domain=\"%s\"><man:do-action><SetLogLevel><LogLevel>%s</LogLevel></SetLogLevel></man:do-action></man:request>" % (domain, log_level)

    xml_response = make_request(dp_name, request=request, interface='soma').read()

    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("Set log level to error on " + dp_name + " in " + domain + " " + return_status)
    return return_status


def create_checkpoint(dp_name, domain, checkpoint_name):
    """
    Creates a checkpoint in a DataPower domain

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :param checkpoint_name: str, name of the checkpoint
    :return: str, return status, 'OK' for success.
    """
    request = "<man:request domain=\"%s\"><man:do-action><SaveCheckpoint><ChkName>%s</ChkName></SaveCheckpoint></man:do-action></man:request>" % (domain, checkpoint_name)

    xml_response = make_request(dp_name, request=request, interface='soma').read()

    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("Created checkpoint "+ checkpoint_name + " on "+ dp_name + " in " + domain + " domain, return status " + return_status)
    return return_status


def rollback_checkpoint(dp_name, domain, checkpoint_name):
    """
    Roll back to a checkpoint in a DataPower domain

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :param checkpoint_name: str, name of the checkpoint
    :return: str, return status, 'OK' for success.
    """
    request = "<man:request domain=\"%s\"><man:do-action><RollbackCheckpoint><ChkName>%s</ChkName></RollbackCheckpoint></man:do-action></man:request>" % (domain, checkpoint_name)

    xml_response = make_request(dp_name, request=request, interface='soma').read()

    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("Rolled back checkpoint " + checkpoint_name +  " on " + dp_name + " in " + domain + "domain, return status: " + return_status)
    return return_status


def remove_checkpoint(dp_name, domain, checkpoint_name):
    """
    Delete a checkpoint in a DataPower domain

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :param checkpoint_name: str, name of the checkpoint
    :return: str, return status, 'OK' for success.
    """
    request = " <man:request domain=\"%s\"><man:do-action><RemoveCheckpoint><ChkName>%s</ChkName></RemoveCheckpoint></man:do-action></man:request> " % (domain, checkpoint_name)

    xml_response = make_request(dp_name, request=request, interface='soma').read()

    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("Created checkpoint "+ checkpoint_name + " on "+ dp_name + " in " + domain + " domain, return status " + return_status)
    return return_status


def reset_domain(dp_name, domain):
    """
    Resets a DataPower domain, removing all objects but saving files

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :return: str, return status, 'OK' for success.
    """
    request = " <man:request domain=\"%s\"><man:do-action><ResetThisDomain/></man:do-action></man:request> " % (domain)
    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info( dp_name + " reset domain: " + domain)
    return return_status


def get_domain_status(dp_name, domain="default"):
    """
    Retrives the status of a DataPower domain

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :return: dict  {'AdminState': 'enabled', 'OpState': 'up', 'ConfigState': 'saved', 'DebugState': 'false', 'CurrentCommand': None, 'QuiesceState': None}
    """
    request = "<ns:GetDomainStatusRequest><ns:Domain>%s</ns:Domain></ns:GetDomainStatusRequest>" % domain

    xml_response = make_request(dp_name, request=request, interface='amp').read()
    tree = ElementTree.fromstring(xml_response)

    domain_state = tree.findall(
        './env:Body/amp:GetDomainStatusResponse/amp:Domain[@name="%s"]' % domain,
        namespaces,
    )[0]
    domain_state_dict = {}
    for elem in domain_state:
        domain_state_dict[elem.tag.lstrip('{%s}' % namespaces['amp'])] = elem.text

    logger.info("get_domain_status " + dp_name + " " + domain)

    return domain_state_dict


def get_object_status(dp_name, domain, class_name, service_name=None):
    """
    Retrives the status of a DataPower object

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :param class_name: str, examples: SSLClientProfile, MultiProtocalGateway, etc...
    :return: ObjectStatus obj
    """
    object_name_str = ""
    if service_name is not None:
        object_name_str = " object-name=\"" + service_name + "\""
    request = ('<man:request domain=\"' + domain + '\"><man:get-status class=\"ObjectStatus\" object-class=\"' + class_name +"\"" + object_name_str + '/></man:request>')
    xml_response = make_request(dp_name, request=request, interface='soma').read()

    tree = ElementTree.fromstring(xml_response)
    objects = tree.findall('./env:Body/dp:response/dp:status/ObjectStatus', namespaces,)

    object_status_list = []

    for object_status in objects:
        obj_stat_dict = {}
        for obj_stat in object_status:
            obj_stat_dict[obj_stat.tag] = obj_stat.text
        object_status_list.append(obj_stat_dict)

    logger.info("Fetched object status " + dp_name + " " + domain + " " + class_name)
    return object_status_list

#def get_file_store(dp_name, domain, location="local:", no_subdirectories="false"):
#    request = ('<man:request domain=\"' + domain  + '\"><man:get-filestore location=\"' + location + '\" no-subdirectories= \"' + no_subdirectories + '\"/></man:request>')
#    print(str(request.tostring))


def do_view_certificate_details(dp_name, domain, certificate_object):
    request = '<man:request domain=\"' + domain + '\"><man:do-view-certificate-details><man:certificate-object>' \
              + certificate_object + '</man:certificate-object></man:do-view-certificate-details></man:request>'

    xml_response = make_request(dp_name, request=request, interface='soma').read()

    tree = ElementTree.fromstring(xml_response)
    cert = tree.find('./env:Body/dp:response/dp:view-certificate-details/CryptoCertificate/CertificateDetails', namespaces,)

    cert_details = {'CertificateObject': certificate_object, 'Domain': domain }

    fingerprint_sha1 = cert.attrib.get('fingerprint-sha1')
    version = cert.find("./Version").text
    serial_number = cert.find("./SerialNumber").text
    signature_algorithm = cert.find("./SignatureAlgorithm").text
    #modulus = cert.find("./xmlns:KeyValue/RSAKeyValue/Modulus").text

    issuer = cert.find("./Issuer").text
    cert_details['CertificateDetails'] = {'fingerprint-sha1': fingerprint_sha1, 'Version': version, 'SerialNumber': serial_number,
                                          'SignatureAlgorithm' : signature_algorithm, 'Issuer': issuer}

    # logger.info("Fetched object status " + dp_name + " " + domain + " " + class_name)
    return cert_details


def service_debug_mode(dp_name, domain, class_name, name, debug_mode="off"):
    """
    Turns debug mode on or off for a service

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :param class_name: str, MultiProtocalGateway or WSProxy
    :param name: str, name of the object to turn on debug
    :param debug_mode: str, on or off, defaults to off
    :return: str, return status, 'OK' for success.
    """
    request = """ <man:request domain="%s"><man:modify-config>
        <%s name="%s">
        <DebugMode>%s</DebugMode>
        </%s>

        </man:modify-config>
        </man:request>""" % (domain, class_name, name, debug_mode, class_name)

    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info(dp_name + " " + domain + " " + class_name + " " + name + " set to " + debug_mode + " " + return_status)
    return return_status


def quiesce_dp(dp_name, domain="default", time_out=300):
    """
    Quiesces DataPower at the Default Domain, quiescing all Domains.

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain, default is 'default'
    :param time_out: int, duration to quiesce, 60 is minimum, 300 is default
    :return: str, return status, 'OK' for success.
    """
    request = """<man:request domain="%s">
        <man:do-action>
        <QuiesceDP>
        <timeout>%s</timeout>
        </QuiesceDP>
        </man:do-action>
        </man:request>""" % (domain, time_out)
    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("Quiescing " + dp_name + " return status " + return_status)
    return return_status

def quiesce_domain(dp_name, domain, time_out=300):
    """
    Quiesces DataPower at the Default Domain, quiescing all Domains.

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain, default is 'default'
    :param time_out: int, duration to quiesce, 60 is minimum, 300 is default
    :return: str, return status, 'OK' for success.
    """
    if domain == 'default':
        raise Exception('Not allowed to quiesce default domain.')
    if time_out < 60:
        raise Exception('Timeout must be >= 60')
    request = """<man:request domain="default">
               <man:do-action><DomainQuiesce>
               <name>%s</name>
               <timeout>%s</timeout>
               </DomainQuiesce>
               </man:do-action>
               </man:request>""" % (domain, time_out)
    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("Quiescing " + dp_name + " " + domain + " return status " + return_status)
    return return_status

def unquiesce_domain(dp_name, domain):
    """
    Quiesces DataPower at the Default Domain, quiescing all Domains.

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain, default is 'default'
    :param time_out: int, duration to quiesce, 60 is minimum, 300 is default
    :return: str, return status, 'OK' for success.
    """
    request = """<man:request domain="default">
               <man:do-action>
               <DomainUnquiesce>
               <name>%s</name>
               </DomainUnquiesce>
               </man:do-action>
               </man:request>""" % (domain)
    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("Quiescing " + dp_name + " " + domain + " return status " + return_status)
    return return_status


def unquiesce_dp(dp_name, domain="default"):
    """
    UnQuiesces DataPower at the Default Domain, unquiescing all Domains.

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain, default is 'default'
    :return: str, return status, 'OK' for success.
    """
    request = """
        <man:request domain="%s">
        <man:do-action>
        <UnquiesceDP/>
        </man:do-action>
        </man:request>""" % (domain)
    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("UnQuiescing " + dp_name + " return status " + return_status)
    return return_status


def reboot(dp_name, delay='10'):
    """
    Reboots DataPower

    :param dp_name: str, name of the DataPower
    :param delay: str, default is '10'
    :return: str, return status, 'OK' for success.
    """
    request = """<man:request domain="default">
        <man:do-action>
        <Shutdown>
        <Mode>reboot</Mode>
        <Delay>%s</Delay>
        </Shutdown>
        </man:do-action>
        </man:request>""" % (delay)
    #xml_response = make_request(dp_name, request=request, interface='soma').read()
    #tree = ElementTree.fromstring(xml_response)
    #return_status = soma_check_return(tree)
    #logger.info("Rebooting " + dp_name)
    #return return_status


def save_configuration(dp_name, domain):
    """
    Saves DataPower domain config

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the Domain
    :return: str, return status, 'OK' for success.
    """
    request = """<man:request domain="%s">
        <man:do-action>
        <SaveConfig/>
        </man:do-action>
        </man:request>""" % (domain)
    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("Saving Configuration on " + dp_name + " in " + domain +  " domain " + return_status)
    return return_status


def get_tcp_table(dp_name):
    """
    Returns the TCP Table

    :param dp_name: str, name of the DataPower
    :return: str, return status, 'OK' for success.
    """
    request = """<man:request domain="default"><man:get-status class="TCPTable"/></man:request>"""
    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    result = tree.findall('./env:Body/dp:response/dp:status/TCPTable', namespaces,)
    tcp_tables = []
    for tcp_table in result:
        table = {}
        for elem in tcp_table:
            table[elem.tag] = elem.text
        tcp_tables.append(table)
    return tcp_tables


def ping_remote_host(dp_name, remote_host):
    """
    Pings a remote host

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the Domain
    :return: str, return status, 'OK' for success.
    """
    request = """<man:request domain="default">
        <man:do-action>
        <Ping>
        <RemoteHost>%s</RemoteHost>
        </Ping>
        </man:do-action>
        </man:request>""" % (remote_host)

    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    return_status = soma_check_return(tree)
    logger.info("Pinged from " + dp_name + " to " + remote_host + " " + return_status)
    return return_status


def tcp_conn_test(dp_name, remote_host, remote_port):
    uri = '/mgmt/actionqueue/default'
    req_dict = {
        "TCPConnectionTest": {
            "RemoteHost": remote_host,
            "RemotePort": remote_port
        }
    }
    body = dict_to_json(req_dict)
    response = make_request(dp_name, uri=uri, interface='rest', method='POST', request=body).read()
    dict_ = resp_to_dict(response)
    return format_object_config(dict_)


def soma_check_return(tree):
    """
    Checks the return status of a SOMA call

    :param tree: xml tree, response from DataPower
    :return: str|list, if multiple requests are sent at once, datapower returns mulitple OKs
             Need to check return status type if its a string or list
             'OK' for success.
    """
    error_response = tree.find('./env:Body/dp:response/dp:result/error-log/',namespaces,)
    #Order matters, check for error first
    if error_response is not None:
        return error_response.text
    else:
        responses = []
        for ok_response in tree.findall('./env:Body/dp:response/dp:result',namespaces,):
            if ok_response is not None:
                responses.append(str.strip(ok_response.text))
        if len(responses) == 1:
            return responses[0]
        else:
            return responses


def get_object_config(dp_name, domain=None, obj=None, name=None, recursive=False, depth='7', uri=None):
    """
    Gets a DataPower objects configuration

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain, default is None
    :param obj: str, class name of the obj, ie MultiProtocalGateway, WSProxy, etc...
    :param name: str, name of the object.  This is optional and when not specified DataPower returns all objects of that type in the domain
    :param recursive: bool, True or False, if True DataPower returns all referenced ObjectStatus.
    :param depth: str, 1-7, sets a limit of recursive depth, default is 7
    :param uri: str, optionally you can pass the uri instead of Domain, obj, name params.
    :return: dict, this is formatted and added to an array by default.
    """
    if uri is None:
        if name is None:
            uri = '/mgmt/config/' + domain + '/' + obj
        else:
            uri = '/mgmt/config/' + domain + '/' + obj  + '/' + name

    if recursive is True :
        uri += '?view=recursive&depth=' + depth
    response = make_request(dp_name, uri=uri, interface='rest', method='GET').read()
    dict_ = resp_to_dict(response)
    return format_object_config(dict_)


def modify_object_config(dp_name, domain, obj_dict):
    """
    Modifies a DataPower objects configuration, creates if object does not exist

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain, default is None
    :param obj_dict: dict, object typically returned by get_object_config
    :return: dict, status of object modification
    """
    uri = '/mgmt/config/' + domain + '/' + list(obj_dict)[0] + '/' + obj_dict[list(obj_dict)[0]]['name']
    body = dict_to_json(obj_dict)
    response = make_request(dp_name, uri=uri, request=body, interface='rest', method='PUT').read()
    return json.loads(response.decode('utf-8'))


def set_object_config(dp_name, domain, obj_dict):
    """
    NEED To debug why this doesnt work....
    Sets a DataPower objects configuration, this only works if the target object does
    not already exist in the domain.

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain, default is None
    :param obj_dict: dict, object typically returned by get_object_config
    :return: dict, status of object modification
    """
    uri = '/mgmt/config/' + domain + '/' + list(obj_dict)[0]
    body = dict_to_json(obj_dict)
    response = make_request(dp_name, uri=uri, request=body, interface='rest', method='POST').read()
    return json.loads(response.decode('utf-8'))


def delete_object_config(dp_name, domain, obj, name):
    """
    Deletes a DataPower object

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain, default is None
    :param obj: str, class name of the obj
    :param name: str, name of the object
    :return: dict, status of object deletion
    """
    uri = '/mgmt/config/' + domain + '/' + obj  + '/' + name
    response = make_request(dp_name, uri=uri, interface='rest', method='DELETE').read()
    dict_ = resp_to_dict(response)
    return dict_


def format_object_config(dict_):
    dp_objects = []
    for key, value in dict_.items():
        if key != '_links' and key != '_embedded':
            app_dict = { key : value }
            dp_objects.append(app_dict)
    if '_embedded' in dict_.keys():
        for dp_object in dict_['_embedded']['descendants']:
            dp_objects.append(dp_object)
    scrub(dp_objects, 'href')
    scrub(dp_objects, '_links')
    return dp_objects


def scrub(obj, bad_key):
    """
    Removes specified key from the dictioary in place.
    :param obj: dict, dictionary from DataPowers get object config rest call
    :param bad_key: str, key to remove from the dictionary
    """
    if isinstance(obj, dict):
        for key in list(obj.keys()):
            if key == bad_key:
                del obj[key]
            else:
                scrub(obj[key], bad_key)
    elif isinstance(obj, list):
        for i in reversed(range(len(obj))):
            if obj[i] == bad_key:
                del obj[i]
            else:
                scrub(obj[i], bad_key)
    else:
        # neither a dict nor a list, do nothing
        pass


def search_dict(dict_, search_key):
    results = []
    search_(dict_, search_key, results)
    return results


def search_(dict_, search_key, results):
    for key, value in dict_.items():
        if type(value) is dict:
            if key == search_key:
                results.append(dict_)
            search_(dict_[key], search_key, results)
        elif type(value) is list:
            for d in value:
                if type(d) is dict:
                    search_(d, search_key, results)
                else:
                    if key == search_key:
                        results.append(dict_)
        else:
            if key == search_key:
                results.append(dict_[key])


def get_host_alias(host):
    host_alias_list = []
    objects = get_object_config(host, "default", "HostAlias")
    for alias in objects:
        alias_name = alias.get("name")
        host_alias_list.append(alias_name)
    return host_alias_list


def file_to_base64(file):
    """
    Converts a file to base 64

    :param file: str, full path to file
    :param base64_file: str, path to output base64 file too.
    """
    with open(file, 'rb') as fin:
        file_content = fin.read()
    return base64.b64encode(file_content).decode('ascii')


def create_directory(dp_name, domain, directory):
    """

    :param dp_name:
    :param directory:
    :param domain:
    :return:
    """
    uri = '/mgmt/filestore/' + domain + '/local'
    body = {
        "directory": {
            "name": directory
        }
    }
    print(uri, dict_to_json(body))
    response = make_request(dp_name, uri=uri, request=dict_to_json(body), interface='rest', method='POST').read()
    dict_ = resp_to_dict(response)
    return response


def is_directory(dp_name, domain, directory):
    """

    :param dp_name:
    :param directory:
    :param domain:
    :return:
    """
    uri = '/mgmt/filestore/' + domain + '/local/' + directory.rstrip('/')
    try:
        response = make_request(dp_name, uri=uri, interface='rest', method='GET')
        return response.code == 200
    except AttributeError:
        return False


def put_file(dp_name, domain, root='local', file=""):
    """
    Upload file to DataPower local:///

    :param dp_name:
    :param file:
    :param domain:
    :return: str
    """
    if root == 'cert':
        file_name = file.split('\\')[-1]
        uri = '/mgmt/filestore/' + domain + '/' + root + '/' + file_name
    else:
        uri = '/mgmt/filestore/' + domain + '/' + root + '/' + file.replace('\\', '/').lstrip('./')
    file_contents_base64 = file_to_base64(file)
    body = {
        'file': {
            'name': file.split('\\')[-1],
            'content': file_contents_base64
        }
    }
   
    response = make_request(dp_name, uri=uri, request=dict_to_json(body), interface='rest', method='PUT').read()

    dict_ = resp_to_dict(response)
    return dict_


def get_file(dp_name, file="", domain="default"):
    """
    Retrieves a file from DataPower.

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :param file: str, full path to the file, ex local:///path/to/file.xml
    :return: bytes string, leave this as bytes and write it to a file as bytes or face the consequences...
    """
    request = "<man:request domain=\"%s\"><man:get-file name=\"%s\"/></man:request>" % (domain, file)

    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)
    _file = tree.findall('./env:Body/dp:response/dp:file', namespaces,)[0].text

    s = base64.standard_b64decode(_file)
    logger.info("Fetched file " + file + " from " + dp_name + " domain " + domain)
    return s


#Returns a JSON formatted directory structure
def get_filestore(dp_name, domain="default", location='local:', no_subdirectories='false'):
    """
    Retrieves the filestore from a DataPower domain

    :param dp_name: str, name of the DataPower
    :param domain: str, name of the domain
    :param location: str, defaults to local:
    :param no_subdirectories: str, 'true' or 'false'
    :return: dict
    """
    request = "<man:request domain=\"%s\"><man:get-filestore location=\"%s\" no-subdirectories=\"%s\"/></man:request>" % (domain, location, no_subdirectories)
    xml_response = make_request(dp_name, request=request, interface='soma').read()
    tree = ElementTree.fromstring(xml_response)

    file_store = tree.findall('./env:Body/dp:response/dp:filestore/location/', namespaces,)
    # Need to recursively traverse file_store to retrieve useful results.
    root = {}
    filestore_xml_to_dict(file_store, root)
    if location == 'sharedcert:':
        files = []
        for file in root['files']:
            files.append(location + ':///' + file)
        return files
    return list_files(root, location, False)


def list_files(filestore, base_dir, xml=False):
    files = []
    files_out = []
    build_file_paths(filestore, files)
    for _file in files:
        if re.findall(base_dir, _file):
            if xml:
                files_out.append(create_file_xml(_file))
            else:
                files_out.append(_file.replace(':/', ':///'))
    return files_out


def create_file_xml(_file):
    return '<file name=\"' + _file.replace(':/', ':///') + '\" src=\"' + _file.replace(':/', '/') + '\" location=\"local\"/>'


def build_file_paths(filestore, files):
    for key, value in filestore.items():
        if isinstance(value, dict):
            if "files" in value:
                for _file in value['files']:
                    file_url = key + "/" + _file
                    files.append(file_url)
            if not isinstance(value, list):
                build_file_paths(value, files)


def isBase64(sb):
    """
    Checks if a string is base64 or not

    :param sb: str
    :returns: bool
    """
    try:
        if type(sb) == str:
        # If there's any unicode here, an exception will be thrown and the function will return false
            sb_bytes = bytes(sb, 'ascii')
        elif type(sb) == bytes:
            sb_bytes = sb
        else:
            raise ValueError("Argument must be string or bytes")
        return base64.b64encode(base64.b64decode(sb_bytes)) == sb_bytes
    except Exception:
        return False


def filestore_xml_to_dict(tree_elem, parent):
    """
    Converts an xml type filestore to dictionary type file store using recursion.

    :param tree_elem: xml ElementTree
    :param parent: dictionary that we are building while parsing the xml ElementTree
    """
    for child in tree_elem:
        if child: #Child contains sub elements
            if child.tag == "directory":
                parent[child.get("name")] = {}
                filestore_xml_to_dict(child, parent[child.get("name")])
            else:
                if "files" not in parent:
                    parent["files"] = []
                parent["files"].append(child.get("name"))