# Installing

## Dependencies
* The dependencies can be installed with help of the requirements.txt (eg. `pip2 install -r requirements.txt`)
* Since Chilkat can not be installed via pip it has to be manually installed.
* [`chilkat`](https://www.chilkatsoft.com/python.asp) (Python 2.7 64bit)
* Furthermore some additional system packages have to be installed via the Linux-Package-Manager. For Debian based systems this can be done by the following command:
* `apt-get install adb python neo4j python-pip virtualbox postgresql python-dev libffi-dev libssl-dev libxml2-dev libxslt1-dev libjpeg-dev tcpdump libcap2-bin automake autoconf libtool python-psycopg2 libpq-dev apache2 apache2-utils libexpat1 ssl-cert libapache2-mod-wsgi`
* There is also an install script in the root folder which you may use.
* After successful installation of all requirements you can start with initializing the database and migrate the Django-Project
* Next Steps:
* initialize database
* migrate project (python2 manage.py migrate)

## Backend
* [`django-multiupload`](https://github.com/Chive/django-multiupload) Run `pip install -e git+https://github.com/Chive/django-multiupload.git#egg=multiupload`
* Set up PATH_MODULE_CONFIG in Backend view.py 
* Edit the config files DynamicAnalyzer/settings.py StaticAnalyzer/settings.py and config/misc_config.py


# Running
## Neo4J
Tested with version [neo4j-community-2.3.3](https://neo4j.com/download/?ref=home)
* `ulimit -n 40000` - Ensure better performance by allowing more open file descriptors
* `neo4j-community-X.X.X/bin/neo4j start` - Start the Neo4J Framework

## Postgres
* Start the Database-Server `systemctl start postgres`

## Cuckoo
* Since Cuckoo needs to be connected to the Internet you need some Firewall-Rules. An example is provided in the iptables.sh file. You can adapt this to your existing Firewall
* For the usage of the Cuckoo image file you may have to create a new snapshot after importing to VirtualBox


# Usage
## Neo4J
* Start Neo4J using the commandline (see `Running > Neo4J`)
* Open the [Neo4J browser](http://localhost:7474/browser)
* Execute [Cypher requests](https://neo4j.com/docs/cypher-refcard/current/)

## Cuckoo
* Note: From time to time you should clean cuckoo temp files. You can do this by navigating in DynamicAnalyzer/cuckoo and issue the following command: `python2 cuckoo.py --clean`


