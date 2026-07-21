#! /bin/python3

import argparse
import sys
import logging
import os
import http.client
import json
import keyword
import re
import textwrap
import secrets
import string
import subprocess
import shlex
import random
from urllib.parse import urlparse

API_HOST = os.environ.get("API_URL").strip("https://").strip("http://")
API_BASE_URI = "/api/v1"
CMD_ENV = {
    "PATH": "/usr/sqlite330/bin:/usr/local/bin:/usr/bin:/bin",
    "UMASK": "0002",
    "LD_LIBRARY_PATH": "/usr/sqlite330/lib",
}

DEFAULT_PYTHON_VERSION = "3.12"
DEFAULT_DJANGO_VERSION = "6.0.7"
DEFAULT_PROJECT_NAME = "myproject"
PROJECT_NAME_RE = re.compile(r"^[a-zA-Z_][a-zA-Z0-9_]*$")

# OSVar names that the orchestrator sets when the postgres branch is enabled; fetched via the Opalstack API at install time because Opalstack does not source user OSVars into the installer's process environment.
DB_ENV_VARS = ("DB_NAME", "DB_USER", "DB_PASS", "DB_HOST", "DB_PORT")
DB_ENGINE_DEFAULT = "django.db.backends.postgresql"

# OSVar names that the orchestrator sets when the static-app branch is enabled; fetched via the Opalstack API at install time for the same reason.
STATIC_ENV_VARS = ("STATIC_ROOT", "STATIC_URL")

# OSVar names that the orchestrator sets when the media-app branch is enabled; fetched via the Opalstack API at install time for the same reason.
MEDIA_ENV_VARS = ("MEDIA_ROOT", "MEDIA_URL")

# OSVar name that the orchestrator sets to the site's public domain; used to pin ALLOWED_HOSTS.
SITE_DOMAIN_ENV_VAR = "SITE_DOMAIN"

UWSGI_CONF_TEMPLATE = textwrap.dedent("""\
    [uwsgi]
    master = True
    http-socket = 127.0.0.1:{port}
    env = LD_LIBRARY_PATH=/usr/sqlite330/lib
    virtualenv = {appdir}/env/
    daemonize = /home/{osuser_name}/logs/apps/{app_name}/uwsgi.log
    pidfile = {appdir}/tmp/uwsgi.pid
    workers = 2
    threads = 2

    # adjust the following to point to your project
    python-path = {appdir}/{project_name}
    wsgi-file = {appdir}/{project_name}/{project_name}/wsgi.py
    touch-reload = {appdir}/{project_name}/{project_name}/wsgi.py
    """)

START_SCRIPT_TEMPLATE = textwrap.dedent("""\
    #!/bin/bash
    export TMPDIR={appdir}/tmp
    export LD_LIBRARY_PATH=/usr/sqlite330/lib
    mkdir -p {appdir}/tmp
    PIDFILE="{appdir}/tmp/uwsgi.pid"

    if [ -e "$PIDFILE" ] && (pgrep -u {osuser_name} | grep -x -f $PIDFILE &> /dev/null); then
      echo "uWSGI for {app_name} already running."
      exit 99
    fi

    {appdir}/env/bin/uwsgi --ini {appdir}/uwsgi.ini

    echo "Started uWSGI for {app_name}."
    """)

STOP_SCRIPT_TEMPLATE = textwrap.dedent("""\
    #!/bin/bash
    PIDFILE="{appdir}/tmp/uwsgi.pid"

    if [ ! -e "$PIDFILE" ]; then
        echo "$PIDFILE missing, maybe uWSGI is already stopped?"
        exit 99
    fi

    PID=$(cat $PIDFILE)

    if [ -e "$PIDFILE" ] && (pgrep -u {osuser_name} | grep -x -f $PIDFILE &> /dev/null); then
      {appdir}/env/bin/uwsgi --stop $PIDFILE
      sleep 3
    fi

    if [ -e "$PIDFILE" ] && (pgrep -u {osuser_name} | grep -x -f $PIDFILE &> /dev/null); then
      echo "uWSGI did not stop, killing it."
      sleep 3
      kill -9 $PID
    fi
    rm -f $PIDFILE
    echo "Stopped."
    """)

AXES_SETTINGS_BLOCK = textwrap.dedent("""\

    #
    #    DJANGO AXES
    #

    AUTHENTICATION_BACKENDS = [
        'axes.backends.AxesStandaloneBackend',
        'django.contrib.auth.backends.ModelBackend',
    ]

    # axes: brute-force protection
    AXES_ENABLED = True
    AXES_FAILURE_LIMIT = 5
    # datetime.timedelta or hours as int; attempts forgotten after this
    AXES_COOLOFF_TIME = 1
    # locks on the username alone: behind the front proxy every client shares
    # the same upstream address, so ip_address tracking would let one attacker
    # lock out the whole site
    AXES_LOCKOUT_PARAMETERS = ['username']
    # successful login clears that user's failure counter
    AXES_RESET_ON_SUCCESS = True

    # custom message shown on lockout (default is a plain 429 response)
    AXES_LOCKOUT_TEMPLATE = None          # or 'lockout.html' if you make one
    AXES_VERBOSE = True
    """)

README_TEMPLATE = textwrap.dedent("""\
    # Opalstack Django README

    ## Post-install steps

    Please take the following steps before you begin to use your Django
    installation:

    1. Connect your Django application to a site route in the control panel.

    2. Verify ALLOWED_HOSTS in {appdir}/{project_name}/{project_name}/settings.py
       matches your site's domains (the installer pins it to the SITE_DOMAIN
       OSVar when present). Example:

           ALLOWED_HOSTS = ['domain.com', 'www.domain.com']

    3. Run the following commands to restart your Django instance:

       {appdir}/stop
       {appdir}/start

    ## Using your own project

    If you want to serve your own Django project from this instance:

    1. Upload your project directory to {appdir}

    2. Activate the app's environment:

           source {appdir}/env/bin/activate

    3. Install your project's Python dependencies with pip.

    4. Edit {appdir}/uwsgi.ini to point `wsgi-file` and `touch-reload` at your project's WSGI handler

    5. Run the following commands to restart your Django instance:

       {appdir}/stop
       {appdir}/start

    ## More info

    See https://docs.opalstack.com/topic-guides/django/ for more information.
    """)


class OpalstackAPITool:
    """simple wrapper for http.client get and post"""

    def __init__(self, host, base_uri, authtoken, user, password):
        self.host = host
        self.base_uri = base_uri

        # if there is no auth token, then try to log in with provided credentials
        if not authtoken:
            endpoint = self.base_uri + "/login/"
            payload = json.dumps({"username": user, "password": password})
            conn = http.client.HTTPSConnection(self.host)
            conn.request(
                "POST", endpoint, payload, headers={"Content-type": "application/json"}
            )
            result = json.loads(conn.getresponse().read())
            if not result.get("token"):
                logging.warning(
                    "Invalid username or password and no auth token provided, exiting."
                )
                sys.exit()
            else:
                authtoken = result["token"]

        self.headers = {
            "Content-type": "application/json",
            "Authorization": f"Token {authtoken}",
        }

    def get(self, endpoint):
        """GETs an API endpoint"""
        endpoint = self.base_uri + endpoint
        conn = http.client.HTTPSConnection(self.host)
        conn.request("GET", endpoint, headers=self.headers)
        return json.loads(conn.getresponse().read())

    def post(self, endpoint, payload):
        """POSTs data to an API endpoint"""
        endpoint = self.base_uri + endpoint
        conn = http.client.HTTPSConnection(self.host)
        conn.request("POST", endpoint, payload, headers=self.headers)
        return json.loads(conn.getresponse().read())


def create_file(path, contents, writemode="w", perms=0o600):
    """make a file, perms are passed as octal"""
    with open(path, writemode) as f:
        f.write(contents)
    os.chmod(path, perms)
    logging.info(f"Created file {path} with permissions {oct(perms)}")


def download(url, localfile, writemode="wb", perms=0o600):
    """save a remote file, perms are passed as octal"""
    logging.info(f"Downloading {url} as {localfile} with permissions {oct(perms)}")
    u = urlparse(url)
    if u.scheme == "http":
        conn = http.client.HTTPConnection(u.netloc)
    else:
        conn = http.client.HTTPSConnection(u.netloc)
    conn.request("GET", u.path)
    r = conn.getresponse()
    with open(localfile, writemode) as f:
        while True:
            data = r.read(4096)
            if data:
                f.write(data)
            else:
                break
    os.chmod(localfile, perms)
    logging.info(f"Downloaded {url} as {localfile} with permissions {oct(perms)}")


def gen_password(length=20):
    """makes a random password"""
    chars = string.ascii_letters + string.digits
    return "".join(secrets.choice(chars) for i in range(length))


def run_command(cmd, env=CMD_ENV):
    """runs a command, returns output"""
    logging.info(f"Running: {cmd}")
    try:
        result = subprocess.check_output(shlex.split(cmd), env=env)
    except subprocess.CalledProcessError as e:
        logging.debug(e.output)
    return result


def add_cronjob(cronjob):
    """appends a cron job to the user's crontab"""
    homedir = os.path.expanduser("~")
    tmpname = f"{homedir}/.tmp{gen_password()}"
    tmp = open(tmpname, "w")
    subprocess.run("crontab -l".split(), stdout=tmp)
    tmp.write(f"{cronjob}\n")
    tmp.close()
    cmd = f"crontab {tmpname}"
    doit = run_command(cmd)
    cmd = run_command(f"rm -f {tmpname}")
    logging.info(f"Added cron job: {cronjob}")


def build_databases_block(engine, name, user, password, host, port):
    """builds a Django DATABASES literal using repr to escape values safely"""
    return (
        "DATABASES = {\n"
        "    'default': {\n"
        f"        'ENGINE': {engine!r},\n"
        f"        'NAME': {name!r},\n"
        f"        'USER': {user!r},\n"
        f"        'PASSWORD': {password!r},\n"
        f"        'HOST': {host!r},\n"
        f"        'PORT': {port!r},\n"
        "    },\n"
        "}"
    )


def rewrite_databases_in_settings(settings_path, new_block):
    """replaces the existing DATABASES = {...} literal in settings.py by walking braces"""
    with open(settings_path, "r", encoding="utf-8") as f:
        text = f.read()
    marker = "DATABASES = {"
    start = text.find(marker)
    if start < 0:
        raise RuntimeError(f"DATABASES marker not found in {settings_path}")
    depth = 0
    end = None
    for i in range(start + len(marker) - 1, len(text)):
        ch = text[i]
        if ch == "{":
            depth += 1
        elif ch == "}":
            depth -= 1
            if depth == 0:
                end = i + 1
                break
    if end is None:
        raise RuntimeError(f"Unbalanced braces in DATABASES block in {settings_path}")
    with open(settings_path, "w", encoding="utf-8") as f:
        f.write(text[:start] + new_block + text[end:])


def fetch_osvars_for_osuser(api, osuser_id):
    """returns a {name: content} dict of OSVars attached to the given osuser id"""
    all_osvars = api.get("/osvar/list/")
    result = {}
    for v in all_osvars:
        if osuser_id in (v.get("osusers") or []):
            result[v.get("name")] = v.get("content")
    return result


def rewrite_static_in_settings(settings_path, static_url, static_root):
    """replaces the existing STATIC_URL line and ensures STATIC_ROOT is set to the Opalstack STA app dir"""
    with open(settings_path, "r", encoding="utf-8") as f:
        text = f.read()
    new_static_url_line = f"STATIC_URL = {static_url!r}"
    new_static_root_line = f"STATIC_ROOT = {static_root!r}"
    static_url_re = re.compile(r"^STATIC_URL\s*=.*$", re.MULTILINE)
    static_root_re = re.compile(r"^STATIC_ROOT\s*=.*$", re.MULTILINE)
    if static_url_re.search(text):
        text = static_url_re.sub(new_static_url_line, text, count=1)
    else:
        text = text.rstrip() + "\n\n" + new_static_url_line + "\n"
    if static_root_re.search(text):
        text = static_root_re.sub(new_static_root_line, text, count=1)
    else:
        text = text.rstrip() + "\n" + new_static_root_line + "\n"
    with open(settings_path, "w", encoding="utf-8") as f:
        f.write(text)


def rewrite_allowed_hosts_in_settings(settings_path, hosts):
    """replaces the ALLOWED_HOSTS line with the given host list"""
    with open(settings_path, "r", encoding="utf-8") as f:
        text = f.read()
    new_line = f"ALLOWED_HOSTS = {hosts!r}"
    allowed_hosts_re = re.compile(r"^ALLOWED_HOSTS\s*=.*$", re.MULTILINE)
    if not allowed_hosts_re.search(text):
        raise RuntimeError(f"ALLOWED_HOSTS line not found in {settings_path}")
    text = allowed_hosts_re.sub(new_line, text, count=1)
    with open(settings_path, "w", encoding="utf-8") as f:
        f.write(text)


def rewrite_debug_in_settings(settings_path, debug_value):
    """replaces the DEBUG line with the given boolean value"""
    with open(settings_path, "r", encoding="utf-8") as f:
        text = f.read()
    new_line = f"DEBUG = {bool(debug_value)!r}"
    debug_re = re.compile(r"^DEBUG\s*=.*$", re.MULTILINE)
    if not debug_re.search(text):
        raise RuntimeError(f"DEBUG line not found in {settings_path}")
    text = debug_re.sub(new_line, text, count=1)
    with open(settings_path, "w", encoding="utf-8") as f:
        f.write(text)


def rewrite_media_in_settings(settings_path, media_url, media_root):
    """replaces the existing MEDIA_URL line and ensures MEDIA_ROOT is set to the Opalstack STA app dir"""
    with open(settings_path, "r", encoding="utf-8") as f:
        text = f.read()
    new_media_url_line = f"MEDIA_URL = {media_url!r}"
    new_media_root_line = f"MEDIA_ROOT = {media_root!r}"
    media_url_re = re.compile(r"^MEDIA_URL\s*=.*$", re.MULTILINE)
    media_root_re = re.compile(r"^MEDIA_ROOT\s*=.*$", re.MULTILINE)
    if media_url_re.search(text):
        text = media_url_re.sub(new_media_url_line, text, count=1)
    else:
        text = text.rstrip() + "\n\n" + new_media_url_line + "\n"
    if media_root_re.search(text):
        text = media_root_re.sub(new_media_root_line, text, count=1)
    else:
        text = text.rstrip() + "\n" + new_media_root_line + "\n"
    with open(settings_path, "w", encoding="utf-8") as f:
        f.write(text)


def append_to_settings_list(text, marker, new_entry, settings_path):
    """inserts an entry before the closing bracket of a flat settings list"""
    start = text.find(marker)
    if start < 0:
        raise RuntimeError(f"{marker!r} marker not found in {settings_path}")
    end = text.find("]", start)
    if end < 0:
        raise RuntimeError(f"Unterminated {marker!r} list in {settings_path}")
    return text[:end] + f"    {new_entry!r},\n" + text[end:]


def wire_axes_in_settings(settings_path):
    """registers django-axes: app, middleware, and the settings block at the end"""
    with open(settings_path, "r", encoding="utf-8") as f:
        text = f.read()
    if "axes" in text:
        raise RuntimeError(f"axes already referenced in {settings_path}")
    text = append_to_settings_list(text, "INSTALLED_APPS = [", "axes", settings_path)
    # AxesMiddleware must be last so every earlier middleware has already run
    text = append_to_settings_list(
        text, "MIDDLEWARE = [", "axes.middleware.AxesMiddleware", settings_path
    )
    text = text.rstrip() + "\n" + AXES_SETTINGS_BLOCK
    with open(settings_path, "w", encoding="utf-8") as f:
        f.write(text)


def main():
    """run it"""
    # grab args from cmd or env

    parser = argparse.ArgumentParser(description="Installs Django on Opalstack account")

    parser.add_argument(
        "-i",
        dest="app_uuid",
        help="UUID of the base app",
        default=os.environ.get("UUID"),
    )
    parser.add_argument(
        "-n",
        dest="app_name",
        help="name of the base app",
        default=os.environ.get("APPNAME"),
    )
    parser.add_argument(
        "-t",
        dest="opal_token",
        help="API auth token",
        default=os.environ.get("OPAL_TOKEN"),
    )
    parser.add_argument(
        "-u",
        dest="opal_user",
        help="Opalstack account name",
        default=os.environ.get("OPAL_USER"),
    )
    parser.add_argument(
        "-p",
        dest="opal_password",
        help="Opalstack account password",
        default=os.environ.get("OPAL_PASS"),
    )
    parser.add_argument(
        "--python-version",
        dest="python_version",
        help="Python version to use for the virtualenv (e.g. 3.12)",
        default=os.environ.get("PYTHON_VERSION", DEFAULT_PYTHON_VERSION),
    )
    parser.add_argument(
        "--django-version",
        dest="django_version",
        help="Django version to install (e.g. 6.0.5)",
        default=os.environ.get("DJANGO_VERSION", DEFAULT_DJANGO_VERSION),
    )
    parser.add_argument(
        "--project-name",
        dest="project_name",
        help="Django project (Python package) name (e.g. myproject)",
        default=os.environ.get("PROJECT_NAME", DEFAULT_PROJECT_NAME),
    )
    args = parser.parse_args()

    # validate Django project name (must be a valid Python identifier and not a keyword)
    if not PROJECT_NAME_RE.match(args.project_name) or keyword.iskeyword(
        args.project_name
    ):
        sys.exit(f"Invalid Django project name: {args.project_name!r}")

    # init logging
    logging.basicConfig(
        level=logging.INFO, format="[%(asctime)s] %(levelname)s: %(message)s"
    )
    # go!
    logging.info(f"Started installation of Django app {args.app_name}")
    api = OpalstackAPITool(
        API_HOST, API_BASE_URI, args.opal_token, args.opal_user, args.opal_password
    )
    appinfo = api.get(f"/app/read/{args.app_uuid}")
    appdir = f'/home/{appinfo["osuser_name"]}/apps/{appinfo["name"]}'

    # Fetch user-scoped OSVars via the API; Opalstack does not source them into the installer's process environment.
    osuser_ref = appinfo.get("osuser")
    osuser_id = osuser_ref.get("id") if isinstance(osuser_ref, dict) else osuser_ref
    osvars = fetch_osvars_for_osuser(api, osuser_id) if osuser_id else {}
    logging.info(
        f'Fetched {len(osvars)} OSVars for osuser {appinfo["osuser_name"]}: {sorted(osvars.keys())}'
    )

    # Override the Django project name from the PROJECT_NAME OSVar when present; the orchestrator sets it for the same reason DB_*/STATIC_* are conveyed via OSVar.
    osvar_project_name = osvars.get("PROJECT_NAME")
    if osvar_project_name:
        if not PROJECT_NAME_RE.match(osvar_project_name) or keyword.iskeyword(
            osvar_project_name
        ):
            sys.exit(
                f"Invalid PROJECT_NAME OSVar value: {osvar_project_name!r}"
            )
        if osvar_project_name != args.project_name:
            logging.info(
                f"Overriding project_name from PROJECT_NAME OSVar: {args.project_name!r} -> {osvar_project_name!r}"
            )
        args.project_name = osvar_project_name

    # create tmp dir
    os.mkdir(f"{appdir}/tmp", 0o700)
    logging.info(f"Created directory {appdir}/tmp")
    CMD_ENV["TMPDIR"] = f"{appdir}/tmp"

    # create virtualenv
    python_executable_path = (
        run_command(f"which python{args.python_version}").decode("utf-8").strip()
    )
    run_command(f"{python_executable_path} -m venv {appdir}/env")
    logging.info(
        f"Created virtualenv at {appdir}/env using python{args.python_version}"
    )

    # install uwsgi
    run_command(f"scl enable devtoolset-11 -- {appdir}/env/bin/pip install uwsgi")
    run_command(f"chmod 700 {appdir}/env/bin/uwsgi")
    logging.info("Installed latest uWSGI into virtualenv")

    # install django
    run_command(
        f"scl enable devtoolset-11 -- {appdir}/env/bin/pip install django=={args.django_version}"
    )
    logging.info(f"Installed Django {args.django_version} into virtualenv")

    # create project dir
    os.mkdir(f"{appdir}/{args.project_name}", 0o700)
    logging.info(f"Created Django project directory {appdir}/{args.project_name}")

    # run startproject with dir option
    run_command(
        f"{appdir}/env/bin/django-admin startproject {args.project_name} {appdir}/{args.project_name}"
    )
    logging.info(f"Populated Django project directory {appdir}/{args.project_name}")

    # django config
    settings_path = f"{appdir}/{args.project_name}/{args.project_name}/settings.py"

    # pin ALLOWED_HOSTS to the site's public domain when the SITE_DOMAIN OSVar is
    # present; falls back to the permissive wildcard only for unorchestrated installs
    site_domain = osvars.get(SITE_DOMAIN_ENV_VAR)
    if site_domain:
        allowed_hosts = [site_domain]
    else:
        allowed_hosts = ["*"]
        logging.warning(
            f"OSVar {SITE_DOMAIN_ENV_VAR} not set; ALLOWED_HOSTS falls back to ['*']"
        )
    rewrite_allowed_hosts_in_settings(settings_path, allowed_hosts)
    logging.info(f"Wrote ALLOWED_HOSTS = {allowed_hosts!r} into {settings_path}")

    # production default: never ship with DEBUG on
    rewrite_debug_in_settings(settings_path, False)
    logging.info(f"Wrote DEBUG = False into {settings_path}")

    # optional postgres wiring: when DB_* OSVars are present, install psycopg and rewrite DATABASES
    if all(osvars.get(k) for k in DB_ENV_VARS):
        run_command(
            f"scl enable devtoolset-11 -- {appdir}/env/bin/pip install psycopg[binary]"
        )
        logging.info("Installed psycopg[binary] into virtualenv")
        new_databases = build_databases_block(
            engine=osvars.get("DB_ENGINE", DB_ENGINE_DEFAULT),
            name=osvars["DB_NAME"],
            user=osvars["DB_USER"],
            password=osvars["DB_PASS"],
            host=osvars["DB_HOST"],
            port=osvars["DB_PORT"],
        )
        rewrite_databases_in_settings(settings_path, new_databases)
        logging.info(f"Rewrote DATABASES block in {settings_path} to use PostgreSQL")
    else:
        missing_db = [k for k in DB_ENV_VARS if not osvars.get(k)]
        logging.info(f"Skipping postgres wiring; missing OSVars: {missing_db}")

    # optional static-files wiring: when STATIC_* OSVars are present, point Django at the STA app dir and run collectstatic
    if all(osvars.get(k) for k in STATIC_ENV_VARS):
        static_root = osvars["STATIC_ROOT"]
        static_url = osvars["STATIC_URL"]
        rewrite_static_in_settings(settings_path, static_url, static_root)
        logging.info(
            f"Wrote STATIC_URL={static_url!r} and STATIC_ROOT={static_root!r} into {settings_path}"
        )
        os.makedirs(static_root, exist_ok=True)
        manage_py = f"{appdir}/{args.project_name}/manage.py"
        run_command(f"{appdir}/env/bin/python {manage_py} collectstatic --noinput")
        logging.info(f"Ran collectstatic into {static_root}")
    else:
        missing_static = [k for k in STATIC_ENV_VARS if not osvars.get(k)]
        logging.info(f"Skipping static-files wiring; missing OSVars: {missing_static}")

    # optional media-files wiring: when MEDIA_* OSVars are present, point Django at the media STA app dir
    if all(osvars.get(k) for k in MEDIA_ENV_VARS):
        media_root = osvars["MEDIA_ROOT"]
        media_url = osvars["MEDIA_URL"]
        rewrite_media_in_settings(settings_path, media_url, media_root)
        logging.info(
            f"Wrote MEDIA_URL={media_url!r} and MEDIA_ROOT={media_root!r} into {settings_path}"
        )
        os.makedirs(media_root, exist_ok=True)
    else:
        missing_media = [k for k in MEDIA_ENV_VARS if not osvars.get(k)]
        logging.info(f"Skipping media-files wiring; missing OSVars: {missing_media}")

    # brute-force protection: install django-axes and wire it into settings.py
    run_command(
        f"scl enable devtoolset-11 -- {appdir}/env/bin/pip install django-axes"
    )
    logging.info("Installed django-axes into virtualenv")
    wire_axes_in_settings(settings_path)
    logging.info(f"Wired django-axes into {settings_path}")

    # apply initial Django migrations against whichever backend settings.py now points at;
    # runs after the axes wiring so its access-attempt tables are created here too
    manage_py = f"{appdir}/{args.project_name}/manage.py"
    run_command(f"{appdir}/env/bin/python {manage_py} migrate --noinput")
    logging.info("Ran initial Django migrations")

    # uwsgi config
    uwsgi_conf = UWSGI_CONF_TEMPLATE.format(
        port=appinfo["port"],
        appdir=appdir,
        osuser_name=appinfo["osuser_name"],
        app_name=appinfo["name"],
        project_name=args.project_name,
    )
    create_file(f"{appdir}/uwsgi.ini", uwsgi_conf, perms=0o600)

    # start script
    start_script = START_SCRIPT_TEMPLATE.format(
        appdir=appdir,
        osuser_name=appinfo["osuser_name"],
        app_name=appinfo["name"],
    )
    create_file(f"{appdir}/start", start_script, perms=0o700)

    # stop script
    stop_script = STOP_SCRIPT_TEMPLATE.format(
        appdir=appdir,
        osuser_name=appinfo["osuser_name"],
    )
    create_file(f"{appdir}/stop", stop_script, perms=0o700)

    # cron
    m = random.randint(0, 9)
    croncmd = f"0{m},1{m},2{m},3{m},4{m},5{m} * * * * {appdir}/start > /dev/null 2>&1"
    add_cronjob(croncmd)

    # make README
    readme = README_TEMPLATE.format(appdir=appdir, project_name=args.project_name)
    create_file(f"{appdir}/README", readme)

    # start it
    run_command(f"{appdir}/start")

    # finished, push a notice with credentials
    payload = json.dumps([{"id": args.app_uuid}])
    api.post("/app/installed/", payload)

    logging.info(f"Completed installation of Django app {args.app_name}")


if __name__ == "__main__":
    main()
