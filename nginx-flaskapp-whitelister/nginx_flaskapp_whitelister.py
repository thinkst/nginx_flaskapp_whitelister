import sys, getopt
import nginx
import re
import importlib
import subprocess
import tempfile
import os

def main():

    nginx_parameter_length_limit = 4000

    pythonhome_directory = ""
    flask_app_file_location = ""
    application_name = ""
    nginx_conf_location = ""
    nginx_include_location = ""

    module_usage_string = """
Usage: nginx_flaskapp_whitelister -r (optional) -p <pythonenvdirectory> -f <flaskappmodule> -a <flaskapplicationname> -c <nginxconfiglocation> -n <nginxincludelocation>
Flags:
        -h                              Help function to display functionality and guidance to use the nginx_flaskapp_whitelister module.
        -r                              Optional: Restart Nginx to reload added configuration and for white-listing to take immediate effect.
        -p <pythonenvdirectory>         The directory of the python environment that the Flask app is running in. The $PYTHONHOME variable.
        -f <flaskappmodule>             The python module from where the Flask app is served.
        -a <flaskapplicationname>       The physical name of the Flask application.
        -c <nginxconfiglocation>        The location of the current Nginx configuration that is used to serve the Flask application.
        -n <nginxincludelocation>       Optional: File path to where the 'include.whitelist' file will be included from within the Nginx configuration
                                        that is used to serve the Flask application. If no file path is provided, the default will be used as
                                        '/etc/nginx/'.
"""

    # Initial parameter/flag verification and extraction

    if not len(sys.argv) > 1:
        print('No arguments supplied. For more information run: nginx_flaskapp_whitelister -h')
        print(module_usage_string)
        sys.exit(2)

    try:
       opts, args = getopt.getopt(sys.argv[1:],"hrp:f:a:c:n:",["pythonenvdir=","flaskappmodule=","applicationname=","nginxconfiglocation=","nginxincludelocation="])
    except getopt.GetoptError:
       print(module_usage_string)
       sys.exit(2)
    for opt, arg in opts:
        if opt == '-h':
            print(module_usage_string)
            sys.exit()
        elif opt in ("-p", "--pythonenvdir"):
            pythonhome_directory = arg
        elif opt in ("-f", "--flaskappmodule"):
            if "/" in arg:
                flask_app_file_location = arg.replace("/", ".")
                if flask_app_file_location.startswith("."):
                    flask_app_file_location = flask_app_file_location[1:]
            else:
                flask_app_file_location = arg
        elif opt in ("-a", "--applicationname"):
            application_name = arg
        elif opt in ("-c", "--nginxconfiglocation"):
            nginx_conf_location = arg
        elif opt in ("-n", "--nginxincludelocation"):
            nginx_include_location = arg

    required_arguments = [{'pythonenvdir' : pythonhome_directory}, {'flaskappmodule' : flask_app_file_location}, {'applicationname' : application_name}, {'nginxconfiglocation' : nginx_conf_location}]

    missing_arg = ""
    for argument in required_arguments:
        if argument.values()[0] == "":
            if missing_arg == "":
                missing_arg = argument.keys()[0]
            else:
                missing_arg = missing_arg + ", " + argument.keys()[0]
    if missing_arg != "":
        print('Required arguments (' + missing_arg + ') are missing. For more information run: nginx_flaskapp_whitelister -h')
        print(module_usage_string)
        sys.exit(2)

    # Setup the PYTHONPATH variable to point to the python home and import the requested Flask app from the specified module
    sys.path.append(pythonhome_directory)
    project = importlib.import_module(flask_app_file_location)
    app = getattr(project, application_name)

    # Extract all exposed flask endpoints from the specified app
    links = []
    for rule in app.url_map._rules:
        links.append(rule.rule)

    # Consolidate the retrieved rules from the flask app url map to only contain a list of allowed endpoints and strip
    # parameter sections (< >) from endpoints
    allowed_locations = []
    for endpoint in links:
        if endpoint != "/":
            allowed_locations.append(re.sub('<[^>]+>', '', endpoint))

    # Load the current NginX config used to serve the application into a config object
    config = nginx.loadf(nginx_conf_location)

    # Extract the keys and configuration from the config object that refers to the location directive that allows the access
    # to "location / {}" (presumed to be the most likely allowed full access route configured)
    original_location_object = []
    original_server_list = list(config.filter('Http')[0].filter('Server'))
    for server in original_server_list:
        if server.locations != []:
            original_location_object.extend(server.locations)

    current_locations = []
    for location in original_location_object:
        current_locations.append(location.as_dict)

    # Create a new NginX config object for the added included location directives for the whitelisted locations
    allowed_location_keys = []

    whitelist_location_conf = nginx.Conf()
    for location in current_locations:
        if location.keys()[0] == 'location /':
            for key in location['location /']:
                nested_key = []
                if "if (" in key.keys()[0]:
                    for x in key[key.keys()[0]]:
                        nested_key.append(nginx.Key(x.keys()[0], x[x.keys()[0]]).as_strings)
                    allowed_location_keys.append(nginx.Key(key.keys()[0], '{ ' + "".join(nested_key) + ' }'))
                else:
                    allowed_location_keys.append(nginx.Key(key.keys()[0], key[key.keys()[0]]))

    # As Nginx has a parameter limit that caps the amount of characters allowed in a directive parameter,
    # the allowed location endpoints are chunked accordingly into as big as possible chunks within the limit
    dynamic_locations_write_variable = []
    for location in allowed_locations:
        if len("|".join(dynamic_locations_write_variable)) < nginx_parameter_length_limit:
            dynamic_locations_write_variable.append(location)
        else:
            whitelist_location_conf.add(nginx.Location('~ (' + '|'.join(dynamic_locations_write_variable) + ')', nginx.Key('include', 'shared.conf')))
            dynamic_locations_write_variable = []
    if dynamic_locations_write_variable != []:
        whitelist_location_conf.add(nginx.Location('~ (' + '|'.join(dynamic_locations_write_variable) + ')', nginx.Key('include', 'shared.conf')))
        dynamic_locations_write_variable = []
    whitelist_location_conf.add(nginx.Location('= /', nginx.Key('include', 'shared.conf')))
    whitelist_location_conf.add(nginx.Location('~ /', nginx.Key('return', '404')))

    # Create a shared Nginx config object containing the keys and configurations shared and re-used
    # across various location directives. This shared.conf is then included per directive, instead
    # of repeating code
    shared_conf = nginx.Conf()
    shared_conf.add(*allowed_location_keys)
    shared_conf_tmp_file = tempfile.NamedTemporaryFile(dir='/tmp/').name
    nginx.dumpf(shared_conf, shared_conf_tmp_file)
    with open(shared_conf_tmp_file, 'r') as file:
        shared_conf_data = file.readlines()
        if any("if (" in string for string in shared_conf_data):
            for line in shared_conf_data:
                if "if (" in line:
                    shared_conf_data[shared_conf_data.index(line)] = line.replace(') "{', ') {')
                if '}";' in line:
                    shared_conf_data[shared_conf_data.index(line)] = line.replace('}";', '}')
            with open(shared_conf_tmp_file, 'w') as file:
                file.writelines(shared_conf_data)

    whitelist_location_conf_tmp_file = tempfile.NamedTemporaryFile(dir='/tmp/').name
    nginx.dumpf(whitelist_location_conf, whitelist_location_conf_tmp_file)

    # If a specific Nginx include location is specified, the generated configuration are moved to this location,
    # otherwise it is moved to a default location of (/etc/nginx/). This filepath should match the path of the
    # include directive inserted into the main nginx.conf for enabling the nginx whitelisting.
    if nginx_include_location != "":
        os.rename(whitelist_location_conf_tmp_file, nginx_include_location + "/include.whitelist")
        os.rename(shared_conf_tmp_file, nginx_include_location + "/shared.conf")
    else:
        os.rename(whitelist_location_conf_tmp_file, "/etc/nginx/include.whitelist")
        os.rename(shared_conf_tmp_file, "/etc/nginx/shared.conf")

    # For the newly generated whitelisting config to take effect, the Nginx config should be reloaded and the
    # process restarted. If the restart flag was set by the user, Nginx will be attempted to restart as part
    # of the tool implementation
    for opt, arg in opts:
        if opt == '-r':
            nginx_restart = subprocess.check_output(["service","nginx","restart"])
            print(nginx_restart)
